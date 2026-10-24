package routeros

import (
	"fmt"
	"strconv"
	"strings"
)

const (
	interval  = "20s"
	failHold  = "00:05:00"
	grace     = "00:01:00"
	pingCount = 5
	pingOK    = 4
	// Two failed checks in a row before switching: a single lossy run on an
	// LTE or rural uplink, or a short core restart, would otherwise cycle
	// every router through its hubs (Ruling R13).
	failsToSwitch = 2
	// The switch script needs test for ping and write for the peer; the
	// scheduler must hold at least the script's policy to run it. Without
	// policy, RouterOS (seen on 7.24.5) gives each scheduler run its own
	// empty globals, so the fail count and fail times never carry over.
	policy = "read,write,policy,test"
)

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

// switchBody is the switch script.
//
// Times come from uptime, not [:timestamp]: uptime never jumps with the clock,
// exists on every v7, and resets on reboot exactly when the globals do (R12).
// The grace after a switch keeps the new hub from being marked failed before
// the core has moved the router's /32 to it; without it, "all marked, take
// the first" could pin the router to the hub that just died.
//
// Marks and the grace are tested apart from the subtraction because RouterOS
// does not short-circuit, and subtracting a missing value is an error. The
// current hub is the full host|port|key entry, so a hub that changed its key
// or port is not mistaken for the listed one. Marks are keyed by host|port:
// two hubs on one VPS share a host, and a host-only mark on the dead one would
// mark both and send the router back to the dead hub.
const switchBody = `:global nmVpnFail
:global nmVpnFailCount
:global nmVpnSwitchAt
:if ([:typeof $nmVpnFail] != "array") do={ :set nmVpnFail [:toarray ""] }
:if ([:typeof $nmVpnFailCount] != "num") do={ :set nmVpnFailCount 0 }
:local servers {@SERVERS@}
:local now [/system resource get uptime]
:local settled true
:if ([:typeof $nmVpnSwitchAt] = "time") do={ :if (($now - $nmVpnSwitchAt) < @GRACE@) do={ :set settled false } }
:if ($settled) do={
@CHECK@
  :if ($nmVpnFailCount >= @FAILS@) do={
    :set nmVpnFailCount 0
    :local id ([@FIND@]->0)
    :local cur (@CUR@)
    :local curEp [:pick $cur 0 [:find $cur "|" [:find $cur "|"]]]
    :set ($nmVpnFail->$curEp) $now
    :local n [:len $servers]
    :local idx [:find $servers $cur]
    :if ([:typeof $idx] != "num") do={ :set idx -1 }
    :local next ""
    :for k from=1 to=$n do={
      :local s [:pick $servers (($idx + $k) % $n)]
      :local ep [:pick $s 0 [:find $s "|" [:find $s "|"]]]
      :local t ($nmVpnFail->$ep)
      :local fresh false
      :if ([:typeof $t] = "time") do={ :set fresh (($now - $t) < @HOLD@) }
      :if (($next = "") && ($fresh = false)) do={ :set next $s }
    }
    :if ($next = "") do={ :set next [:pick $servers 0] }
    :if ($next != $cur) do={
      :local p [:find $next "|"]
      :local host [:pick $next 0 $p]
      :local rest [:pick $next ($p + 1) [:len $next]]
      :set p [:find $rest "|"]
      @SET@
      :set nmVpnSwitchAt $now
      :log warning ("@TAG@: pindah ke " . $host)
    }
  }
}
`

// switchProto is what the switch script does differently per protocol: the
// ping check, how it finds the tunnel object ($id), reads the current hub as
// a server-list entry ($cur), and moves to $host with $rest holding the
// entry's last two fields.
type switchProto struct{ check, find, cur, set string }

const wgPing = "[/ping @CORE@ src-address=@ADDR@ count=@COUNT@ interval=1s]"

var wgSwitch = switchProto{
	check: "  :if (" + wgPing + " >= @OK@) do={ :set nmVpnFailCount 0 } else={ :set nmVpnFailCount ($nmVpnFailCount + 1) }",
	find:  "/interface wireguard peers find interface=" + ifaceName,
	cur:   `[:tostr [/interface wireguard peers get $id endpoint-address]] . "|" . [/interface wireguard peers get $id endpoint-port] . "|" . [/interface wireguard peers get $id public-key]`,
	set:   "/interface wireguard peers set $id endpoint-address=$host endpoint-port=[:tonum [:pick $rest 0 $p]] public-key=[:pick $rest ($p + 1) [:len $rest]]",
}

// l2tpSwitch: PPP puts the /32 on the l2tp interface, so while the tunnel is
// down the ping has no source address. The on-error turns a ping that refuses
// to run into a failed check instead of aborting the run before it counts.
// Setting connect-to re-dials at once (seen on 7.24.5), which is the switch.
var l2tpSwitch = switchProto{
	check: "  :local got 0\n  :do { :set got " + wgPing + " } on-error={}\n" +
		"  :if ($got >= @OK@) do={ :set nmVpnFailCount 0 } else={ :set nmVpnFailCount ($nmVpnFailCount + 1) }",
	find: "/interface l2tp-client find name=" + ifaceName,
	cur:  `[:tostr [/interface l2tp-client get $id connect-to]] . "|` + strconv.Itoa(l2tpPort) + `|" . [/interface l2tp-client get $id ipsec-secret]`,
	set:  "/interface l2tp-client set $id connect-to=$host ipsec-secret=[:pick $rest ($p + 1) [:len $rest]]",
}

// SwitchSource returns the switch script body unescaped, for netmanager to
// replace the server list through the API (/system/script/set source=).
//
// After two failed checks the current hub is marked failed for failHold and
// the tunnel moves to the next unmarked hub in list order, or to the first
// when all are marked. There is deliberately no return to the first hub: a
// flapping first hub would otherwise pull the router back and forth.
func SwitchSource(in Input) string {
	p := wgSwitch
	if in.Protocol == ProtocolL2TP {
		p = l2tpSwitch
	}
	body := strings.NewReplacer(
		"@CHECK@", p.check, "@FIND@", p.find, "@CUR@", p.cur, "@SET@", p.set,
	).Replace(switchBody)
	return strings.NewReplacer(
		"@SERVERS@", serverList(in),
		"@CORE@", coreAddr,
		"@ADDR@", in.Address.String(),
		"@COUNT@", strconv.Itoa(pingCount),
		"@OK@", strconv.Itoa(pingOK),
		"@FAILS@", strconv.Itoa(failsToSwitch),
		"@GRACE@", grace,
		"@HOLD@", failHold,
		"@TAG@", tag,
	).Replace(body)
}

// serverList is the body of a RouterOS array of "host|port|key" entries, the
// key being the IPsec secret for L2TP; the switch script and the re-paste
// check both compare the tunnel against it.
func serverList(in Input) string {
	entries := make([]string, len(in.Servers))
	for i, s := range in.Servers {
		port, key := strconv.Itoa(s.Port), s.PublicKey
		if in.Protocol == ProtocolL2TP {
			port, key = strconv.Itoa(l2tpPort), s.IPsecSecret
		}
		entries[i] = str(s.Host + sep + port + sep + key)
	}
	return strings.Join(entries, ";")
}
