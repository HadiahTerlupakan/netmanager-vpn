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
  :if ([/ping @CORE@ src-address=@ADDR@ count=@COUNT@ interval=1s] >= @OK@) do={ :set nmVpnFailCount 0 } else={ :set nmVpnFailCount ($nmVpnFailCount + 1) }
  :if ($nmVpnFailCount >= @FAILS@) do={
    :set nmVpnFailCount 0
    :local id ([/interface wireguard peers find interface=@IFACE@]->0)
    :local cur ([:tostr [/interface wireguard peers get $id endpoint-address]] . "|" . [/interface wireguard peers get $id endpoint-port] . "|" . [/interface wireguard peers get $id public-key])
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
      /interface wireguard peers set $id endpoint-address=$host endpoint-port=[:tonum [:pick $rest 0 $p]] public-key=[:pick $rest ($p + 1) [:len $rest]]
      :set nmVpnSwitchAt $now
      :log warning ("@TAG@: pindah ke " . $host)
    }
  }
}
`

// SwitchSource returns the switch script body unescaped, for netmanager to
// replace the server list through the API (/system/script/set source=).
//
// After two failed checks the current hub is marked failed for failHold and
// the peer moves to the next unmarked hub in list order, or to the first when
// all are marked. There is deliberately no return to the first hub: a
// flapping first hub would otherwise pull the router back and forth.
func SwitchSource(in Input) string {
	return strings.NewReplacer(
		"@SERVERS@", serverList(in),
		"@CORE@", coreAddr,
		"@ADDR@", in.Address.String(),
		"@COUNT@", strconv.Itoa(pingCount),
		"@OK@", strconv.Itoa(pingOK),
		"@FAILS@", strconv.Itoa(failsToSwitch),
		"@GRACE@", grace,
		"@HOLD@", failHold,
		"@IFACE@", ifaceName,
		"@TAG@", tag,
	).Replace(switchBody)
}

// serverList is the body of a RouterOS array of "host|port|key" entries; the
// switch script and the re-paste check both compare the peer against it.
func serverList(in Input) string {
	entries := make([]string, len(in.Servers))
	for i, s := range in.Servers {
		entries[i] = str(s.Host + sep + strconv.Itoa(s.Port) + sep + s.PublicKey)
	}
	return strings.Join(entries, ";")
}
