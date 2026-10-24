package routeros

import (
	"fmt"
	"strings"
)

const (
	// l2tpPort is IKE's port. The client cannot choose it, so it appears only
	// in the host|port|key entries the switch script compares.
	l2tpPort = 500
	// pppMTU fits inside the hub's 1380-byte wg-up path (spike, R7).
	pppMTU = 1380
	// minVersion is the release the L2TP client was proven on (spike, R7).
	minVersion = "7.24.5"
)

// renderL2TP returns the L2TP/IPsec script: version check, l2tp-client on
// Servers[0], routing, switch script and scheduler, then the removal of the
// WireGuard setup it replaces.
//
// The script is one { } block. Pasted lines otherwise run one by one and an
// :error stops only its own line, so the version check could not keep the
// rest from running. As a block nothing runs until the closing brace has
// arrived, so removing the WireGuard tunnel at the end cannot cut the paste
// short when it came in through that tunnel (R1).
//
// A WireGuard router has an interface named ifaceName, and RouterOS will not
// create the l2tp-client under a taken name. The WireGuard interface is
// renamed to oldName first: its peer, keys and session stay, so the router is
// still reachable while the new client is built, and it is removed last. On a
// router that is already L2TP neither the rename nor the removals find
// anything.
func renderL2TP(in Input) string {
	var b strings.Builder
	b.WriteString("{\n")
	writeVersionCheck(&b)
	writeRename(&b, "/interface wireguard")
	writeL2TPClient(&b, in)
	writeRouting(&b, in.Address.String())
	b.WriteString(RenderScheduler(in))
	writeWireGuardRemoval(&b)
	b.WriteString("}\n")
	return b.String()
}

// writeWireGuardRemoval drops the renamed WireGuard interface with its peer,
// and the loopback whose /32 PPP now puts on the l2tp interface. A find on
// interface= names an interface, and one that no longer exists may be an
// error that would abort the block, so each removal first checks that its
// interface is still there.
func writeWireGuardRemoval(b *strings.Builder) {
	fmt.Fprintf(b, ":if ([:len [/interface wireguard find name=%s]] > 0) do={ /interface wireguard peers remove [find interface=%s]; /interface wireguard remove [find name=%s] }\n",
		oldName, oldName, oldName)
	fmt.Fprintf(b, ":if ([:len [/interface bridge find name=%s]] > 0) do={ /ip address remove [find interface=%s comment=%s]; /interface bridge remove [find name=%s] }\n",
		loName, loName, str(tag), loName)
}

// writeVersionCheck stops the script on anything but v7 at or above
// minVersion. The version reads like "7.24.5 (stable)", "7.24" or
// "7.25beta2", so it is cut at the first character that is not a digit or a
// dot, then split into major, minor and patch; a missing patch counts as 0.
func writeVersionCheck(b *strings.Builder) {
	min := strings.Split(minVersion, ".")
	b.WriteString(`:local ver [/system resource get version]
:local cut false
:local num ""
:for k from=0 to=([:len $ver] - 1) do={ :local c [:pick $ver $k]; :if ([:typeof [:find "0123456789." $c]] != "num") do={ :set cut true }; :if ($cut = false) do={ :set num ($num . $c) } }
:local p [:find $num "."]
:local major [:tonum [:pick $num 0 $p]]
:set num [:pick $num ($p + 1) [:len $num]]
:set p [:find $num "."]
:local minor
:local patch 0
:if ([:typeof $p] = "num") do={ :set minor [:tonum [:pick $num 0 $p]]; :set patch [:tonum [:pick $num ($p + 1) [:len $num]]] } else={ :set minor [:tonum $num] }
`)
	fmt.Fprintf(b, ":if ($major != %s || $minor < %s || ($minor = %s && $patch < %s)) do={ :error %s }\n",
		min[0], min[1], min[1], min[2], str("netmanager-vpn: butuh RouterOS minimal "+minVersion))
}

// writeL2TPClient creates the client on Servers[0]. As with writePeer, an
// existing client is moved there only when it sits on no listed hub, because
// the switch script may have moved it to another listed hub and setting
// connect-to re-dials at once. The secret travels with the host: each hub has
// its own.
func writeL2TPClient(b *strings.Builder, in Input) {
	first := in.Servers[0]
	sel := "name=" + ifaceName
	update := fmt.Sprintf("user=%s password=%s use-ipsec=yes allow=mschap2 max-mtu=%d max-mru=%d add-default-route=no disabled=no comment=%s",
		str(in.PPPUser), str(in.PPPPassword), pppMTU, pppMTU, str(tag+": "+in.Label))
	server := fmt.Sprintf("connect-to=%s ipsec-secret=%s", str(first.Host), str(first.IPsecSecret))
	fmt.Fprintf(b, ":if ([:len [/interface l2tp-client find %s]] = 0) do={ /interface l2tp-client add %s %s %s; %s }\n",
		sel, sel, server, update, stampSwitch)
	fmt.Fprintf(b, "/interface l2tp-client set [find %s] %s\n", sel, update)
	fmt.Fprintf(b, "{ :local id ([/interface l2tp-client find %s]->0); "+
		":local cur ([:tostr [/interface l2tp-client get $id connect-to]] . \"|%d|\" . [/interface l2tp-client get $id ipsec-secret]); :local list {%s}; "+
		":if ([:typeof [:find $list $cur]] != \"num\") do={ /interface l2tp-client set $id %s; %s } }\n",
		sel, l2tpPort, serverList(in), server, stampSwitch)
}
