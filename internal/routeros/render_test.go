package routeros

import (
	"net/netip"
	"os"
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
// tunnel may be removed; only the switch script and its scheduler are replaced.
func TestRenderIsIdempotentShape(t *testing.T) {
	for _, line := range strings.Split(RenderFull(testInput()), "\n") {
		if strings.Contains(line, " remove ") &&
			!strings.HasPrefix(line, "/system script remove [find name=netmanager-vpn-switch]") &&
			!strings.HasPrefix(line, "/system scheduler remove [find name=netmanager-vpn-switch]") {
			t.Errorf("unexpected remove: %s", line)
		}
		if strings.Contains(line, " add ") && !strings.HasPrefix(line, "/system ") &&
			!strings.HasPrefix(line, ":if ([:len [") {
			t.Errorf("add not guarded by find: %s", line)
		}
	}
}

func TestRenderFullDoesNotMoveExistingPeer(t *testing.T) {
	for _, line := range strings.Split(RenderFull(testInput()), "\n") {
		if strings.HasPrefix(line, "/interface wireguard peers set") &&
			(strings.Contains(line, "endpoint-address=") || strings.Contains(line, "public-key=")) {
			t.Fatalf("re-paste would move the peer off its current hub: %s", line)
		}
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
