package routeros

import (
	"strings"
	"testing"
)

func l2tpInput() Input {
	in := testInput()
	in.Protocol, in.PrivateKey = ProtocolL2TP, ""
	in.PPPUser, in.PPPPassword = "nmvpn-0a1b2c3d", "Zm9vYmFyYmF6cXV4cXV1eHF1dXhxdXV4"
	in.Servers[0].PublicKey, in.Servers[1].PublicKey = "", ""
	in.Servers[0].Port, in.Servers[1].Port = 500, 500
	in.Servers[0].IPsecSecret = "c2VjcmV0LW9uZS1zZWNyZXQtb25lLXNlY3JldC1vbmU"
	in.Servers[1].IPsecSecret = "c2VjcmV0LXR3by1zZWNyZXQtdHdvLXNlY3JldC10d28"
	return in
}

func TestRenderFullL2TPMatchesGolden(t *testing.T) {
	if got, want := RenderFull(l2tpInput()), golden(t, "full_l2tp.rsc"); got != want {
		t.Fatalf("full L2TP script differs\n got:\n%s\nwant:\n%s", got, want)
	}
}

func TestRenderSchedulerL2TPMatchesGolden(t *testing.T) {
	if got, want := RenderScheduler(l2tpInput()), golden(t, "scheduler_l2tp.rsc"); got != want {
		t.Fatalf("L2TP scheduler script differs\n got:\n%s\nwant:\n%s", got, want)
	}
}

func indexOfPrefix(ls []string, prefix string) int {
	for i, l := range ls {
		if strings.HasPrefix(l, prefix) {
			return i
		}
	}
	return -1
}

func indexContaining(ls []string, sub string) int {
	for i, l := range ls {
		if strings.Contains(l, sub) {
			return i
		}
	}
	return -1
}

// l2tpRemovals are the commands that tear down the WireGuard setup.
var l2tpRemovals = []string{
	"/interface wireguard peers remove [find interface=netmanager-vpn-old]",
	"/interface wireguard remove [find name=netmanager-vpn-old]",
	`/ip address remove [find interface=netmanager-lo comment="netmanager-vpn"]`,
	"/interface bridge remove [find name=netmanager-lo]",
}

// The paste may arrive through the WireGuard tunnel it replaces (R1), so the
// old tunnel goes only after everything the new one needs is in place.
func TestRenderL2TPRemovesWireGuardLast(t *testing.T) {
	ls := lines(RenderFull(l2tpInput()))
	client := indexOfPrefix(ls, ":if ([:len [/interface l2tp-client find name=netmanager-vpn]] = 0) do={ /interface l2tp-client add ")
	sched := indexOfPrefix(ls, "/system scheduler add name=netmanager-vpn-switch ")
	if client < 0 || sched < 0 {
		t.Fatalf("client=%d scheduler=%d", client, sched)
	}
	for _, rm := range l2tpRemovals {
		at := indexContaining(ls, rm)
		if at < 0 || at < client || at < sched {
			t.Errorf("%s at %d, client at %d, scheduler at %d", rm, at, client, sched)
		}
	}
}

// Two RouterOS interfaces cannot share a name, so the live WireGuard
// interface steps aside before the l2tp-client takes the name.
func TestRenderL2TPRenamesWireGuardFirst(t *testing.T) {
	ls := lines(RenderFull(l2tpInput()))
	rename := indexOfPrefix(ls, ":if ([:len [/interface wireguard find name=netmanager-vpn]] > 0) do={ /interface wireguard set [find name=netmanager-vpn] name=netmanager-vpn-old }")
	client := indexOfPrefix(ls, ":if ([:len [/interface l2tp-client find name=netmanager-vpn]] = 0)")
	if rename < 0 || rename > client {
		t.Fatalf("rename at %d, client at %d", rename, client)
	}
}

func TestRenderWireGuardRenamesL2TPClientFirst(t *testing.T) {
	ls := lines(strings.TrimSuffix(RenderFull(testInput()), "\n"))
	rename := indexOfPrefix(ls, ":if ([:len [/interface l2tp-client find name=netmanager-vpn]] > 0) do={ /interface l2tp-client set [find name=netmanager-vpn] name=netmanager-vpn-old }")
	wg := indexOfPrefix(ls, ":if ([:len [/interface wireguard find name=netmanager-vpn]] = 0)")
	if rename < 0 || rename > wg {
		t.Errorf("rename at %d, wireguard add at %d", rename, wg)
	}
	if last := ls[len(ls)-1]; last != "/interface l2tp-client remove [find name=netmanager-vpn-old]" {
		t.Errorf("last line is %q", last)
	}
}

// A re-paste on a router that is already L2TP must leave the tunnel alone:
// every add is guarded, and the only removes target the switch script, the
// renamed WireGuard interface and the loopback, none of which an L2TP router
// still has. Those removes run only when their interface exists, because a
// find on a missing interface= may raise an error and abort the block.
func TestRenderL2TPIsIdempotentShape(t *testing.T) {
	guarded := map[string]string{
		":if ([:len [/interface wireguard find name=netmanager-vpn-old]] > 0) do={ ": "/interface wireguard peers remove [find interface=netmanager-vpn-old]; /interface wireguard remove [find name=netmanager-vpn-old] }",
		":if ([:len [/interface bridge find name=netmanager-lo]] > 0) do={ ":         `/ip address remove [find interface=netmanager-lo comment="netmanager-vpn"]; /interface bridge remove [find name=netmanager-lo] }`,
	}
	for _, line := range lines(RenderFull(l2tpInput())) {
		if strings.Contains(line, " remove ") && !strings.HasPrefix(line, "/system script remove [find name=netmanager-vpn-switch]") &&
			!strings.HasPrefix(line, "/system scheduler remove [find name=netmanager-vpn-switch]") &&
			!isGuardedRemoval(guarded, line) {
			t.Errorf("unexpected remove: %s", line)
		}
		if strings.Contains(line, " add ") && !strings.HasPrefix(line, "/system ") &&
			!strings.HasPrefix(line, ":if ([:len [") {
			t.Errorf("add not guarded by find: %s", line)
		}
		if strings.Contains(line, "name=netmanager-vpn-old") && strings.Contains(line, " set ") &&
			!strings.HasPrefix(line, ":if ([:len [/interface wireguard find name=netmanager-vpn]] > 0) do={") {
			t.Errorf("rename not guarded by find: %s", line)
		}
	}
}

func isGuardedRemoval(guarded map[string]string, line string) bool {
	for guard, body := range guarded {
		if line == guard+body {
			return true
		}
	}
	return false
}

func TestRenderL2TPHasNoFetchOrImport(t *testing.T) {
	out := RenderFull(l2tpInput())
	for _, banned := range []string{"/tool fetch", "/import"} {
		if strings.Contains(out, banned) {
			t.Errorf("script contains %q", banned)
		}
	}
}

// Pasted lines run one by one and an :error stops only its own line, so the
// script is one block: the check aborts it before anything is changed.
func TestRenderL2TPStopsBelowMinVersion(t *testing.T) {
	out := RenderFull(l2tpInput())
	ls := lines(strings.TrimSuffix(out, "\n"))
	if ls[0] != "{" || ls[len(ls)-1] != "}" {
		t.Fatalf("script is not one block: first %q, last %q", ls[0], ls[len(ls)-1])
	}
	check := strings.Index(out, ":local ver [/system resource get version]")
	stop := strings.Index(out, `:if ($major != 7 || $minor < 24 || ($minor = 24 && $patch < 5)) do={ :error "netmanager-vpn: butuh RouterOS minimal 7.24.5" }`)
	first := strings.Index(out, "/interface ")
	if check < 0 || stop < 0 || !(check < stop && stop < first) {
		t.Fatalf("check=%d stop=%d first change=%d", check, stop, first)
	}
}

func TestRenderWireGuardHasNoVersionCheck(t *testing.T) {
	if strings.Contains(RenderFull(testInput()), "/system resource get version") {
		t.Fatal("WireGuard script gained the L2TP version check")
	}
}

func TestRenderL2TPMovesClientOnlyOffUnlistedServer(t *testing.T) {
	in := l2tpInput()
	want := `{ :local id ([/interface l2tp-client find name=netmanager-vpn]->0); ` +
		`:local cur ([:tostr [/interface l2tp-client get $id connect-to]] . "|500|" . [/interface l2tp-client get $id ipsec-secret]); ` +
		`:local list {` + serverList(in) + `}; ` +
		`:if ([:typeof [:find $list $cur]] != "num") do={ /interface l2tp-client set $id connect-to="hub-a.example.net" ipsec-secret="` + in.Servers[0].IPsecSecret + `"; ` +
		stampSwitch + ` } }`
	if indexOfPrefix(lines(RenderFull(in)), want) < 0 {
		t.Fatalf("no guarded move of the client, want:\n%s", want)
	}
}

func TestRenderL2TPClientProperties(t *testing.T) {
	out := RenderFull(l2tpInput())
	for _, want := range []string{
		`/interface l2tp-client add name=netmanager-vpn connect-to="hub-a.example.net" ipsec-secret="c2VjcmV0LW9uZS1zZWNyZXQtb25lLXNlY3JldC1vbmU" `,
		`user="nmvpn-0a1b2c3d" password="Zm9vYmFyYmF6cXV4cXV1eHF1dXhxdXV4" use-ipsec=yes allow=mschap2 max-mtu=1380 max-mru=1380 add-default-route=no disabled=no comment="netmanager-vpn: Kantor \"Pusat\" \$1"`,
		`gateway=netmanager-vpn routing-table=netmanager-vpn pref-src=10.100.0.10 comment="netmanager-vpn"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %s", want)
		}
	}
	if strings.Contains(out, "/interface bridge add") || strings.Contains(out, "/ip address add") {
		t.Error("L2TP script creates the loopback; PPP assigns the /32")
	}
}

func TestValidateL2TPDoesNotNeedPublicKey(t *testing.T) {
	if err := l2tpInput().Validate(); err != nil {
		t.Fatalf("valid L2TP input rejected: %v", err)
	}
}

func TestValidateRejectsSecretWithSeparator(t *testing.T) {
	cases := map[string]func(*Input){
		"pipe in secret":   func(in *Input) { in.Servers[1].IPsecSecret = "a|b" },
		"empty secret":     func(in *Input) { in.Servers[0].IPsecSecret = "" },
		"empty user":       func(in *Input) { in.PPPUser = "" },
		"empty password":   func(in *Input) { in.PPPPassword = "" },
		"unknown protocol": func(in *Input) { in.Protocol = "sstp" },
	}
	for name, mutate := range cases {
		in := l2tpInput()
		mutate(&in)
		if err := in.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestSwitchSourceL2TPSetsConnectToAndSecret(t *testing.T) {
	in := l2tpInput()
	src := SwitchSource(in)
	for _, want := range []string{
		`:local servers {"hub-a.example.net|500|` + in.Servers[0].IPsecSecret + `";"203.0.113.20|500|` + in.Servers[1].IPsecSecret + `"}`,
		`:local id ([/interface l2tp-client find name=netmanager-vpn]->0)`,
		`:local cur ([:tostr [/interface l2tp-client get $id connect-to]] . "|500|" . [/interface l2tp-client get $id ipsec-secret])`,
		`/interface l2tp-client set $id connect-to=$host ipsec-secret=[:pick $rest ($p + 1) [:len $rest]]`,
	} {
		if !strings.Contains(src, want) {
			t.Errorf("missing %s", want)
		}
	}
	if strings.Contains(src, "wireguard") {
		t.Error("L2TP switch script touches WireGuard")
	}
}

// The /32 sits on the l2tp interface, which has no address while the tunnel
// is down; a ping from a missing source must count as a failed check rather
// than abort the run, or the router would never leave a dead hub.
func TestSwitchL2TPCountsPingErrorAsFailure(t *testing.T) {
	src := SwitchSource(l2tpInput())
	for _, want := range []string{
		"  :local got 0\n",
		"  :do { :set got [/ping 10.99.0.1 src-address=10.100.0.10 count=5 interval=1s] } on-error={}\n",
		"  :if ($got >= 4) do={ :set nmVpnFailCount 0 } else={ :set nmVpnFailCount ($nmVpnFailCount + 1) }\n",
	} {
		if !strings.Contains(src, want) {
			t.Errorf("missing %q", want)
		}
	}
}

func TestWireGuardSchedulerUnchanged(t *testing.T) {
	in := testInput()
	in.Protocol = ProtocolWireGuard
	if got, want := RenderScheduler(in), golden(t, "scheduler.rsc"); got != want {
		t.Fatalf("explicit wireguard differs from scheduler.rsc\n got:\n%s", got)
	}
}
