// Package routeros renders the RouterOS v7 script an operator pastes into a
// MikroTik terminal to make it a WireGuard client of the tenant's hubs.
package routeros

import (
	"errors"
	"fmt"
	"net/netip"
	"regexp"
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
	// The server list packs host, port and key into one string per entry;
	// switchBody splits on the same character.
	sep = "|"
)

// hostnameRE and hasLetterRE are the core's rule for a hub's public host
// (internal/core). A hostname needs a letter so that a mistyped address such
// as 999.1.1.1 is not taken for a name.
var hasLetterRE = regexp.MustCompile(`[A-Za-z]`)

var hostnameRE = regexp.MustCompile(`^([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$`)

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
		case !validHost(s.Host):
			return fmt.Errorf("routeros: server %d: bad host %q", i, s.Host)
		case s.Port < 1 || s.Port > 65535:
			return fmt.Errorf("routeros: server %d: bad port %d", i, s.Port)
		case s.PublicKey == "" || strings.Contains(s.PublicKey, sep):
			return fmt.Errorf("routeros: server %d: bad public key", i)
		}
	}
	return nil
}

func validHost(h string) bool {
	if ip, err := netip.ParseAddr(h); err == nil {
		return ip.Is4()
	}
	return len(h) <= 253 && hostnameRE.MatchString(h) && hasLetterRE.MatchString(h)
}

// RenderFull returns the whole script: loopback, tunnel on Servers[0],
// routing, then the switch script and scheduler. Pasting it again converges
// on the same state without taking the tunnel down.
func RenderFull(in Input) string {
	var b strings.Builder
	addr := in.Address.String()
	ensure(&b, "/interface bridge", "name="+loName,
		"name="+loName, "comment="+str(tag))
	ensure(&b, "/ip address", "interface="+loName+" comment="+str(tag),
		"interface="+loName, "address="+addr+"/32 network="+addr+" comment="+str(tag))
	ensure(&b, "/interface wireguard", "name="+ifaceName,
		"name="+ifaceName+" private-key="+str(in.PrivateKey),
		fmt.Sprintf("mtu=%d comment=%s", mtu, str(tag+": "+in.Label)))
	fmt.Fprintf(&b, ":if ([/interface wireguard get [find name=%s] private-key] != %s) do={ /interface wireguard set [find name=%s] private-key=%s }\n",
		ifaceName, str(in.PrivateKey), ifaceName, str(in.PrivateKey))
	writePeer(&b, in)
	ensure(&b, "/routing table", "name="+tableName,
		"name="+tableName+" fib", "comment="+str(tag))
	writeRules(&b)
	for _, s := range subnets {
		ensure(&b, "/ip route", "comment="+str(tag)+" dst-address="+s,
			"dst-address="+s,
			"gateway="+ifaceName+" routing-table="+tableName+" pref-src="+addr+" comment="+str(tag))
	}
	b.WriteString(RenderScheduler(in))
	return b.String()
}

// writePeer creates the peer on Servers[0]. An existing peer is moved there
// only when it sits on no listed hub: on a re-paste the switch script may
// have moved it to another listed hub, and moving it back would cut the
// session the paste is arriving through.
func writePeer(b *strings.Builder, in Input) {
	first := in.Servers[0]
	sel := "interface=" + ifaceName
	update := fmt.Sprintf("allowed-address=%s persistent-keepalive=%s comment=%s", allowed, keepalive, str(tag))
	endpoint := fmt.Sprintf("endpoint-address=%s endpoint-port=%d public-key=%s", str(first.Host), first.Port, str(first.PublicKey))
	fmt.Fprintf(b, ":if ([:len [/interface wireguard peers find %s]] = 0) do={ /interface wireguard peers add %s %s %s; %s }\n",
		sel, sel, endpoint, update, stampSwitch)
	fmt.Fprintf(b, "/interface wireguard peers set [find %s] %s\n", sel, update)
	get := func(prop string) string { return "[/interface wireguard peers get $id " + prop + "]" }
	fmt.Fprintf(b, "{ :local id ([/interface wireguard peers find %s]->0); "+
		":local cur ([:tostr %s] . \"|\" . %s . \"|\" . %s); :local list {%s}; "+
		":if ([:typeof [:find $list $cur]] != \"num\") do={ /interface wireguard peers set $id %s; %s } }\n",
		sel, get("endpoint-address"), get("endpoint-port"), get("public-key"), serverList(in),
		endpoint, stampSwitch)
}

// stampSwitch starts the switch script's post-switch grace, so a peer that
// the paste just created or moved is not failed over before the core has
// followed it to its hub.
const stampSwitch = ":global nmVpnSwitchAt; :set nmVpnSwitchAt [/system resource get uptime]"

// writeRules puts our rules ahead of the operator's: rules are matched in
// order, so an earlier operator rule (policy routing to a WAN table) would
// otherwise take the backhaul traffic. place-before needs an existing rule to
// point at, hence the empty-table branch.
//
// On a re-paste each of our rules moves directly above the first foreign rule
// when that rule sits higher. The destination is never one of ours, so the
// move cannot target itself, and after both lines no foreign rule is above
// either of ours; an order that is already right is left alone. Comments are
// read with :tostr rather than matched with `find where comment!=`, because a
// where-comparison on an unset comment may be false and operators' policy
// rules are often comment-less.
func writeRules(b *strings.Builder) {
	update := "action=lookup-only-in-table table=" + tableName + " comment=" + str(tag)
	for _, s := range subnets {
		sel := "comment=" + str(tag) + " dst-address=" + s
		fmt.Fprintf(b, ":if ([:len [/routing rule find %s]] = 0) do={ :if ([:len [/routing rule find]] = 0) do={ /routing rule add dst-address=%s %s } else={ /routing rule add dst-address=%s %s place-before=([/routing rule find]->0) } }\n",
			sel, s, update, s, update)
		fmt.Fprintf(b, "/routing rule set [find %s] %s\n", sel, update)
	}
	for _, s := range subnets {
		fmt.Fprintf(b, "{ :local all [/routing rule find]; :local f; :local found false; "+
			":foreach i in=$all do={ :if (($found = false) && ([:tostr [/routing rule get $i comment]] != %s)) do={ :set f $i; :set found true } }; "+
			":if ($found) do={ :local r ([/routing rule find comment=%s dst-address=%s]->0); "+
			":if ([:find $all $f] < [:find $all $r]) do={ /routing rule move $r destination=$f } } }\n",
			str(tag), str(tag), s)
	}
}

// ensure adds the object only when the selector finds nothing, then sets the
// mutable properties on whatever it finds, so a re-paste updates in place.
func ensure(b *strings.Builder, path, selector, create, update string) {
	fmt.Fprintf(b, ":if ([:len [%s find %s]] = 0) do={ %s add %s %s }\n", path, selector, path, create, update)
	fmt.Fprintf(b, "%s set [find %s] %s\n", path, selector, update)
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
