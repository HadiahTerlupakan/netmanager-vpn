package firewall

import (
	"os"
	"strings"
	"testing"
)

// The goldens are provisional until the spike's vpn-hub.nft confirms them.

func golden(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestRenderHubMatchesSpike(t *testing.T) {
	if got, want := RenderHub(), golden(t, "hub.nft"); got != want {
		t.Fatalf("hub ruleset differs\n got:\n%s\nwant:\n%s", got, want)
	}
}

func TestRenderCoreMatchesGolden(t *testing.T) {
	if got, want := RenderCore(), golden(t, "core.nft"); got != want {
		t.Fatalf("core ruleset differs\n got:\n%s\nwant:\n%s", got, want)
	}
}

// The hub may carry only one direction of a flow (the router can answer
// through another hub), so conntrack there would drop half the replies. The
// core sees both directions whichever hub carries the router.
func TestHubRulesetIsStateless(t *testing.T) {
	if strings.Contains(RenderHub(), "ct ") {
		t.Error("hub ruleset must not use conntrack")
	}
}

// A compromised hub VPS must not reach kubelet, the k3s API, NodePorts or the
// pod network through wg-core: only RADIUS and ping to the core, and admin
// traffic to routers, enter there.
func TestCoreFiltersWgCoreIngressBeforeNodePortDNAT(t *testing.T) {
	rs := RenderCore()
	for _, want := range []string{
		"type filter hook prerouting priority -150; policy accept;",
		`iifname "wg-core" ct state established,related accept`,
		`iifname "wg-core" ip saddr 10.100.0.0/14 ip daddr 10.99.0.1 udp dport { 30812, 30813 } accept`,
		`iifname "wg-core" ip saddr 10.99.128.0/24 ip daddr 10.100.0.0/14 accept`,
	} {
		if !strings.Contains(rs, want) {
			t.Errorf("core ruleset lacks %q", want)
		}
	}
	drop := strings.Index(rs, `iifname "wg-core" drop`)
	if drop < 0 || drop < strings.LastIndex(rs, `iifname "wg-core" ip saddr`) {
		t.Fatalf("wg-core must end in a drop after its accepts:\n%s", rs)
	}
}

func TestHubDropsRouterInitiatedTCP(t *testing.T) {
	rs := RenderHub()
	drop := strings.Index(rs, `iifname "wg-nm" tcp flags & (syn | ack) == syn drop`)
	accept := strings.Index(rs, "tcp sport { 8728, 8291, 22 } accept")
	if drop < 0 || accept < 0 || drop > accept {
		t.Fatalf("bare-SYN drop must precede the sport accept (drop=%d accept=%d)", drop, accept)
	}
}
