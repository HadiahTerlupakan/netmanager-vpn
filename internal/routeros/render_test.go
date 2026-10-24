package routeros

import (
	"net/netip"
	"os"
	"slices"
	"strings"
	"testing"
)

// The goldens are provisional until the spike (plan Task 7/8) pastes them on a
// real RouterOS v7 router; Ruling R7.

func testInput() Input {
	return Input{
		Label:      `Kantor "Pusat" $1`,
		Address:    netip.MustParseAddr("10.100.0.10"),
		PrivateKey: "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=",
		Servers: []Server{
			{Host: "hub-a.example.net", Port: 51821, PublicKey: "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg="},
			{Host: "203.0.113.20", Port: 51821, PublicKey: "TrMvSoP4jYQlY6RIzBgbssQqY3vxI2Pi+y71lOWWXX0="},
		},
	}
}

func golden(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestRenderFullMatchesGolden(t *testing.T) {
	if got, want := RenderFull(testInput()), golden(t, "full.rsc"); got != want {
		t.Fatalf("full script differs\n got:\n%s\nwant:\n%s", got, want)
	}
}

func TestRenderSchedulerMatchesGolden(t *testing.T) {
	if got, want := RenderScheduler(testInput()), golden(t, "scheduler.rsc"); got != want {
		t.Fatalf("scheduler script differs\n got:\n%s\nwant:\n%s", got, want)
	}
}

func TestRenderHasNoFetchOrImport(t *testing.T) {
	out := RenderFull(testInput())
	for _, banned := range []string{"/tool fetch", "/import"} {
		if strings.Contains(out, banned) {
			t.Errorf("script contains %q", banned)
		}
	}
}

func TestRenderQuotesLabel(t *testing.T) {
	out := RenderFull(testInput())
	if !strings.Contains(out, `comment="netmanager-vpn: Kantor \"Pusat\" \$1"`) {
		t.Fatalf("label not escaped:\n%s", out)
	}
}

func TestRenderServerOrderPreserved(t *testing.T) {
	in := testInput()
	in.Servers = append(in.Servers, Server{Host: "hub-c.example.net", Port: 51900, PublicKey: "k"})
	src := SwitchSource(in)
	a := strings.Index(src, `"hub-a.example.net|51821|`)
	b := strings.Index(src, `"203.0.113.20|51821|`)
	c := strings.Index(src, `"hub-c.example.net|51900|k"`)
	if a < 0 || b < 0 || c < 0 || !(a < b && b < c) {
		t.Fatalf("server order lost (a=%d b=%d c=%d):\n%s", a, b, c, src)
	}
}

// A re-paste runs over the tunnel it configures, so nothing that carries the
// tunnel may be removed; only the switch script and its scheduler are replaced,
// and an L2TP client renamed aside by a protocol change is dropped.
func TestRenderIsIdempotentShape(t *testing.T) {
	for _, line := range strings.Split(RenderFull(testInput()), "\n") {
		if strings.Contains(line, " remove ") &&
			!strings.HasPrefix(line, "/system script remove [find name=netmanager-vpn-switch]") &&
			!strings.HasPrefix(line, "/system scheduler remove [find name=netmanager-vpn-switch]") &&
			line != "/interface l2tp-client remove [find name=netmanager-vpn-old]" {
			t.Errorf("unexpected remove: %s", line)
		}
		if strings.Contains(line, " add ") && !strings.HasPrefix(line, "/system ") &&
			!strings.HasPrefix(line, ":if ([:len [") {
			t.Errorf("add not guarded by find: %s", line)
		}
	}
}

func lines(s string) []string { return strings.Split(s, "\n") }

func TestRenderFullMovesPeerOnlyOffUnlistedHub(t *testing.T) {
	in := testInput()
	guard := `:local list {` + serverList(in) + `}; :if ([:typeof [:find $list $cur]] != "num") do={ /interface wireguard peers set $id endpoint-address=`
	found := false
	for _, line := range lines(RenderFull(in)) {
		// The switch script's source moves the peer by design; only the
		// paste-time lines are under test here.
		if strings.HasPrefix(line, "/system ") || !strings.Contains(line, "peers set") ||
			!strings.Contains(line, "endpoint-address=") {
			continue
		}
		if !strings.Contains(line, guard) {
			t.Errorf("existing peer moved without checking the list: %s", line)
		}
		for _, prop := range []string{"endpoint-address]", "endpoint-port]", "public-key]"} {
			if !strings.Contains(line, "peers get $id "+prop) {
				t.Errorf("current hub not compared on %s: %s", prop, line)
			}
		}
		found = true
	}
	if !found {
		t.Fatal("no check moves a peer off an unlisted hub")
	}
}

func TestRenderSetsPrivateKeyOnlyWhenChanged(t *testing.T) {
	for _, line := range lines(RenderFull(testInput())) {
		if strings.Contains(line, "wireguard set") && strings.Contains(line, "private-key=") &&
			!strings.HasPrefix(line, ":if ([/interface wireguard get [find name=netmanager-vpn] private-key] != ") {
			t.Errorf("private key re-set unconditionally: %s", line)
		}
	}
}

func TestRenderCreatesRulesAtTheTop(t *testing.T) {
	out := RenderFull(testInput())
	route := strings.Index(out, "/ip route")
	for _, s := range []string{"10.99.0.0/24", "10.99.128.0/24"} {
		add := strings.Index(out, `:if ([:len [/routing rule find comment="netmanager-vpn" dst-address=`+s+`]] = 0) do={ :if ([:len [/routing rule find]] = 0) do={ /routing rule add dst-address=`+s)
		if add < 0 || add > route {
			t.Errorf("%s: guarded add at %d, first route at %d", s, add, route)
		}
	}
	if !strings.Contains(out, "place-before=([/routing rule find]->0)") {
		t.Error("new rules are not placed before the existing ones")
	}
}

// Each of our rules is moved directly above the first foreign rule when that
// rule sits higher. The first foreign rule is found by reading each rule's
// comment as a string rather than with `find where comment!=`, because a
// where-comparison on an unset comment may be false and operators' policy
// rules are often comment-less. The target is never one of ours, so it cannot be a
// self-move, and once both have run no foreign rule is above either of ours.
func TestRenderReordersAboveFirstForeignRule(t *testing.T) {
	out := RenderFull(testInput())
	route := strings.Index(out, "/ip route")
	for _, s := range []string{"10.99.0.0/24", "10.99.128.0/24"} {
		want := `{ :local all [/routing rule find]; :local f; :local found false; ` +
			`:foreach i in=$all do={ :if (($found = false) && ([:tostr [/routing rule get $i comment]] != "netmanager-vpn")) do={ :set f $i; :set found true } }; ` +
			`:if ($found) do={ :local r ([/routing rule find comment="netmanager-vpn" dst-address=` + s + `]->0); ` +
			`:if ([:find $all $f] < [:find $all $r]) do={ /routing rule move $r destination=$f } } }`
		at := strings.Index(out, want)
		if at < 0 || at > route {
			t.Errorf("%s: reorder line missing or after routes (at=%d route=%d)", s, at, route)
		}
	}
}

// moveAboveFirstForeign models the rendered reorder line on a rule list.
func moveAboveFirstForeign(list []string, ours string) []string {
	idx := func(v string) int { return slices.Index(list, v) }
	f := slices.IndexFunc(list, func(v string) bool { return !strings.HasPrefix(v, "R") })
	if f < 0 || f > idx(ours) {
		return list
	}
	out := slices.Delete(slices.Clone(list), idx(ours), idx(ours)+1)
	return slices.Insert(out, f, ours)
}

func TestRuleReorderModel(t *testing.T) {
	for _, tc := range []struct{ in, want []string }{
		{[]string{"Z", "R128", "R0", "X"}, []string{"R0", "R128", "Z", "X"}},
		{[]string{"X", "R128", "R0"}, []string{"R0", "R128", "X"}},
		{[]string{"X", "R0", "R128"}, []string{"R0", "R128", "X"}},
		{[]string{"R128", "R0", "X"}, []string{"R128", "R0", "X"}},
		{[]string{"R0", "R128"}, []string{"R0", "R128"}},
	} {
		got := tc.in
		for _, ours := range []string{"R0", "R128"} {
			got = moveAboveFirstForeign(got, ours)
		}
		if !slices.Equal(got, tc.want) {
			t.Errorf("%v: got %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestRenderGivesNewPeerTheGrace(t *testing.T) {
	stamp := ":global nmVpnSwitchAt; :set nmVpnSwitchAt [/system resource get uptime]"
	var add, move bool
	for _, line := range lines(RenderFull(testInput())) {
		if strings.Contains(line, "/interface wireguard peers add") {
			add = strings.Contains(line, stamp)
		}
		if strings.HasPrefix(line, "{ :local id") {
			move = strings.Contains(line, stamp)
		}
	}
	if !add || !move {
		t.Fatalf("grace not started on paste (add=%v move=%v)", add, move)
	}
}

func TestSwitchGraceGuardsPing(t *testing.T) {
	src := SwitchSource(testInput())
	guard := strings.Index(src, `:if ([:typeof $nmVpnSwitchAt] = "time") do={ :if (($now - $nmVpnSwitchAt) < 00:01:00) do={ :set settled false } }`)
	settled := strings.Index(src, ":if ($settled) do={")
	ping := strings.Index(src, "/ping ")
	set := strings.Index(src, "peers set $id")
	stamp := strings.Index(src, ":set nmVpnSwitchAt $now")
	if guard < 0 || !(guard < settled && settled < ping) {
		t.Errorf("grace must gate the ping (guard=%d settled=%d ping=%d)", guard, settled, ping)
	}
	if set < 0 || stamp < set {
		t.Errorf("switch must start the grace (set=%d stamp=%d)", set, stamp)
	}
}

func TestSwitchNeedsTwoFailedChecks(t *testing.T) {
	src := SwitchSource(testInput())
	count := strings.Index(src, ">= 4) do={ :set nmVpnFailCount 0 } else={ :set nmVpnFailCount ($nmVpnFailCount + 1) }")
	gate := strings.Index(src, ":if ($nmVpnFailCount >= 2) do={\n    :set nmVpnFailCount 0")
	mark := strings.Index(src, ":set ($nmVpnFail->$curEp) $now")
	set := strings.Index(src, "peers set $id")
	if count < 0 || gate < 0 || !(count < gate && gate < mark && mark < set) {
		t.Errorf("count=%d gate=%d mark=%d set=%d", count, gate, mark, set)
	}
}

// On RouterOS 7.24.5 a scheduler run without the policy policy gets a fresh,
// private set of globals each time: nmVpnFailCount never reached 2 and the
// router never switched, and nmVpnSwitchAt set at paste time was invisible.
func TestSwitchScriptAndSchedulerKeepGlobalsAcrossRuns(t *testing.T) {
	out := RenderScheduler(testInput())
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		if !strings.Contains(line, " add name=netmanager-vpn-switch ") {
			continue
		}
		start := strings.Index(line, " policy=") + len(" policy=")
		policies := strings.Split(line[start:start+strings.Index(line[start:], " ")], ",")
		if !slices.Contains(policies, "policy") {
			t.Errorf("policy %v lacks \"policy\": %s", policies, line[:start+30])
		}
	}
}

// Two hubs on one VPS share a host. Keyed by host, marking the dead one marked
// both, "all marked, take the first" picked the dead hub again, and the lab
// router on 7.24.5 never left it.
func TestSwitchMarksHubsByHostAndPort(t *testing.T) {
	in := testInput()
	in.Servers[1].Host = in.Servers[0].Host
	in.Servers[1].Port = 51823
	src := SwitchSource(in)
	for _, want := range []string{
		`:local curEp [:pick $cur 0 [:find $cur "|" [:find $cur "|"]]]`,
		`:set ($nmVpnFail->$curEp) $now`,
		`:local ep [:pick $s 0 [:find $s "|" [:find $s "|"]]]`,
		`:local t ($nmVpnFail->$ep)`,
	} {
		if !strings.Contains(src, want) {
			t.Errorf("switch does not key marks by host|port, missing %s", want)
		}
	}
}

func TestSwitchUsesUptime(t *testing.T) {
	src := SwitchSource(testInput())
	if strings.Contains(src, ":timestamp") || !strings.Contains(src, ":local now [/system resource get uptime]") {
		t.Fatalf("switch must time marks by uptime:\n%s", src)
	}
}

func TestSwitchComparesFullEntry(t *testing.T) {
	src := SwitchSource(testInput())
	cur := `:local cur ([:tostr [/interface wireguard peers get $id endpoint-address]] . "|" . [/interface wireguard peers get $id endpoint-port] . "|" . [/interface wireguard peers get $id public-key])`
	if !strings.Contains(src, cur) || !strings.Contains(src, ":local idx [:find $servers $cur]") ||
		!strings.Contains(src, ":if ($next != $cur) do={") {
		t.Fatalf("current hub not matched on host, port and key:\n%s", src)
	}
}

func TestSwitchSourceHasNoEscapes(t *testing.T) {
	src := SwitchSource(testInput())
	if strings.Contains(src, `\$`) || strings.Contains(src, `\"`) {
		t.Fatalf("raw body must not be escaped:\n%s", src)
	}
	if !strings.Contains(RenderScheduler(testInput()), `source="`+quote(src)+`"`) {
		t.Fatal("scheduler does not embed the escaped SwitchSource")
	}
}

func TestQuoteEscapesQuestionMarkAndNewline(t *testing.T) {
	cases := map[string]string{
		`a"b$c`:    `a\"b\$c`,
		`back\sl`:  `back\\sl`,
		"why?":     `why\?`,
		"l1\nl2\r": `l1\nl2\r`,
		"tab\tx":   `tab\tx`,
		"bell\x07": `bell\07`,
		"café":     `caf\C3\A9`,
	}
	for in, want := range cases {
		if got := quote(in); got != want {
			t.Errorf("quote(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestValidateRejectsBadInput(t *testing.T) {
	if err := testInput().Validate(); err != nil {
		t.Fatalf("valid input rejected: %v", err)
	}
	cases := map[string]func(*Input){
		"no address":    func(in *Input) { in.Address = netip.Addr{} },
		"ipv6 address":  func(in *Input) { in.Address = netip.MustParseAddr("fd00::1") },
		"no key":        func(in *Input) { in.PrivateKey = "" },
		"no servers":    func(in *Input) { in.Servers = nil },
		"empty host":    func(in *Input) { in.Servers[1].Host = "" },
		"port zero":     func(in *Input) { in.Servers[0].Port = 0 },
		"port too high": func(in *Input) { in.Servers[0].Port = 65536 },
		"empty pubkey":  func(in *Input) { in.Servers[0].PublicKey = "" },
		"pipe in host":  func(in *Input) { in.Servers[0].Host = "a|b" },
		"space in host": func(in *Input) { in.Servers[0].Host = "hub a.example.net" },
		"url as host":   func(in *Input) { in.Servers[0].Host = "https://hub-a.example.net" },
		"host and port": func(in *Input) { in.Servers[0].Host = "hub-a.example.net:51821" },
		"ipv6 host":     func(in *Input) { in.Servers[0].Host = "2001:db8::1" },
		"bad label":     func(in *Input) { in.Servers[0].Host = "-hub.example.net" },
		"not an ip":     func(in *Input) { in.Servers[0].Host = "999.1.1.1" },
		"short dotted":  func(in *Input) { in.Servers[0].Host = "1.2.3" },
		"pipe in key":   func(in *Input) { in.Servers[1].PublicKey = "a|b" },
	}
	for name, mutate := range cases {
		in := testInput()
		mutate(&in)
		if err := in.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
