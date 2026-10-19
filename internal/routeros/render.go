// Package routeros renders the RouterOS v7 script an operator pastes into a
// MikroTik terminal to make it a WireGuard client of the tenant's hubs.
package routeros

import (
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

// Server is one hub the router may use; Input.Servers is in priority order.
type Server struct {
	Host      string
	Port      int
	PublicKey string
}

// Input is what the script needs to know about one router.
type Input struct {
	Label      string
	Address    netip.Addr
	PrivateKey string
	Servers    []Server
}

const (
	tag        = "netmanager-vpn"
	ifaceName  = "netmanager-vpn"
	loName     = "netmanager-lo"
	tableName  = "netmanager-vpn"
	switchName = "netmanager-vpn-switch"
	coreAddr   = "10.99.0.1"
	allowed    = "10.99.0.0/24,10.99.128.0/24"
	mtu        = 1420
	keepalive  = "25s"
	interval   = "20s"
	failHold   = "00:05:00"
	pingCount  = 5
	pingOK     = 4
	// The switch script needs test for ping and write for the peer; the
	// scheduler must hold at least the script's policy to run it.
	policy = "read,write,test"
	// The server list packs host, port and key into one string per entry;
	// switchBody splits on the same character.
	sep = "|"
)

var subnets = []string{"10.99.0.0/24", "10.99.128.0/24"}

// Validate reports input that would render a broken script. Callers run it
// before any Render function.
func (in Input) Validate() error {
	if !in.Address.Is4() {
		return errors.New("routeros: address must be IPv4")
	}
	if in.PrivateKey == "" {
		return errors.New("routeros: private key is empty")
	}
	if len(in.Servers) == 0 {
		return errors.New("routeros: no servers")
	}
	for i, s := range in.Servers {
		switch {
		case s.Host == "" || strings.Contains(s.Host, sep):
			return fmt.Errorf("routeros: server %d: bad host %q", i, s.Host)
		case s.Port < 1 || s.Port > 65535:
			return fmt.Errorf("routeros: server %d: bad port %d", i, s.Port)
		case s.PublicKey == "" || strings.Contains(s.PublicKey, sep):
			return fmt.Errorf("routeros: server %d: bad public key", i)
		}
	}
	return nil
}

// RenderFull returns the whole script: loopback, tunnel on Servers[0],
// routing, then the switch script and scheduler. Pasting it again converges
// on the same state without taking the tunnel down.
func RenderFull(in Input) string {
	var b strings.Builder
	addr := in.Address.String()
	first := in.Servers[0]
	ensure(&b, "/interface bridge", "name="+loName,
		"name="+loName, "comment="+str(tag))
	ensure(&b, "/ip address", "interface="+loName+" comment="+str(tag),
		"interface="+loName, "address="+addr+"/32 comment="+str(tag))
	ensure(&b, "/interface wireguard", "name="+ifaceName,
		"name="+ifaceName,
		fmt.Sprintf("mtu=%d private-key=%s comment=%s", mtu, str(in.PrivateKey), str(tag+": "+in.Label)))
	// The endpoint is set only when the peer is created: on a re-paste the
	// switch script may have moved it to another hub, and moving it back
	// here would cut the session the paste is arriving through.
	ensure(&b, "/interface wireguard peers", "interface="+ifaceName,
		fmt.Sprintf("interface=%s public-key=%s endpoint-address=%s endpoint-port=%d",
			ifaceName, str(first.PublicKey), str(first.Host), first.Port),
		fmt.Sprintf("allowed-address=%s persistent-keepalive=%s comment=%s", allowed, keepalive, str(tag)))
	ensure(&b, "/routing table", "name="+tableName,
		"name="+tableName+" fib", "comment="+str(tag))
	for _, s := range subnets {
		ensure(&b, "/routing rule", "comment="+str(tag)+" dst-address="+s,
			"dst-address="+s,
			"action=lookup-only-in-table table="+tableName+" comment="+str(tag))
	}
	for _, s := range subnets {
		ensure(&b, "/ip route", "comment="+str(tag)+" dst-address="+s,
			"dst-address="+s,
			"gateway="+ifaceName+" routing-table="+tableName+" pref-src="+addr+" comment="+str(tag))
	}
	b.WriteString(RenderScheduler(in))
	return b.String()
}

// ensure adds the object only when the selector finds nothing, then sets the
// mutable properties on whatever it finds, so a re-paste updates in place.
func ensure(b *strings.Builder, path, selector, create, update string) {
	fmt.Fprintf(b, ":if ([:len [%s find %s]] = 0) do={ %s add %s %s }\n", path, selector, path, create, update)
	fmt.Fprintf(b, "%s set [find %s] %s\n", path, selector, update)
}

// RenderScheduler returns the switch script and the scheduler that runs it.
// They hold no tunnel state, so replacing them outright is safe.
func RenderScheduler(in Input) string {
	var b strings.Builder
	fmt.Fprintf(&b, "/system scheduler remove [find name=%s]\n", switchName)
	fmt.Fprintf(&b, "/system script remove [find name=%s]\n", switchName)
	fmt.Fprintf(&b, "/system script add name=%s policy=%s comment=%s source=%s\n",
		switchName, policy, str(tag), str(SwitchSource(in)))
	fmt.Fprintf(&b, "/system scheduler add name=%s interval=%s policy=%s comment=%s on-event=%s\n",
		switchName, interval, policy, str(tag), str("/system script run "+switchName))
	return b.String()
}

// switchBody is the switch script. :tostr is there because an IP endpoint may
// come back typed as ip, which never equals the host string in the list. The
// fail mark is tested apart from the subtraction because RouterOS does not
// short-circuit, and subtracting a missing mark from a timestamp is an error.
const switchBody = `:global nmVpnFail
:if ([:typeof $nmVpnFail] != "array") do={ :set nmVpnFail [:toarray ""] }
:local servers {@SERVERS@}
:if ([/ping @CORE@ src-address=@ADDR@ count=@COUNT@ interval=1s] < @OK@) do={
  :local cur [:tostr [/interface wireguard peers get [find interface=@IFACE@] endpoint-address]]
  :set ($nmVpnFail->$cur) [:timestamp]
  :local n [:len $servers]
  :local idx -1
  :for i from=0 to=($n - 1) do={
    :local s [:pick $servers $i]
    :if ([:pick $s 0 [:find $s "|"]] = $cur) do={ :set idx $i }
  }
  :local next ""
  :for k from=1 to=$n do={
    :local s [:pick $servers (($idx + $k) % $n)]
    :local h [:pick $s 0 [:find $s "|"]]
    :local t ($nmVpnFail->$h)
    :local fresh false
    :if ([:typeof $t] = "time") do={ :set fresh (([:timestamp] - $t) < @HOLD@) }
    :if (($next = "") && ($fresh = false)) do={ :set next $s }
  }
  :if ($next = "") do={ :set next [:pick $servers 0] }
  :local p [:find $next "|"]
  :local host [:pick $next 0 $p]
  :local rest [:pick $next ($p + 1) [:len $next]]
  :set p [:find $rest "|"]
  :if ($host != $cur) do={
    /interface wireguard peers set [find interface=@IFACE@] endpoint-address=$host endpoint-port=[:tonum [:pick $rest 0 $p]] public-key=[:pick $rest ($p + 1) [:len $rest]]
    :log warning ("@TAG@: pindah ke " . $host)
  }
}
`

// SwitchSource returns the switch script body unescaped, for netmanager to
// replace the server list through the API (/system/script/set source=).
//
// When the core stops answering, the current hub is marked failed for
// failHold and the peer moves to the next unmarked hub in list order, or to
// the first when all are marked. There is deliberately no return to the first
// hub: a flapping first hub would otherwise pull the router back and forth.
func SwitchSource(in Input) string {
	entries := make([]string, len(in.Servers))
	for i, s := range in.Servers {
		entries[i] = str(s.Host + sep + strconv.Itoa(s.Port) + sep + s.PublicKey)
	}
	return strings.NewReplacer(
		"@SERVERS@", strings.Join(entries, ";"),
		"@CORE@", coreAddr,
		"@ADDR@", in.Address.String(),
		"@COUNT@", strconv.Itoa(pingCount),
		"@OK@", strconv.Itoa(pingOK),
		"@IFACE@", ifaceName,
		"@HOLD@", failHold,
		"@TAG@", tag,
	).Replace(switchBody)
}

func str(s string) string { return `"` + quote(s) + `"` }

// quote escapes s for a RouterOS string literal. `?` opens help in the
// terminal and `$` starts a variable; newlines are escaped so a multi-line
// script source stays on one pasted line. Other control and non-ASCII bytes
// become \HH (RouterOS wants capital hex) so the paste is plain ASCII.
func quote(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch c {
		case '\\', '"', '$', '?':
			b.WriteByte('\\')
			b.WriteByte(c)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			if c < 0x20 || c >= 0x7f {
				fmt.Fprintf(&b, `\%02X`, c)
			} else {
				b.WriteByte(c)
			}
		}
	}
	return b.String()
}
