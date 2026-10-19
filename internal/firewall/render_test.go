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

func TestRulesetsAreStateless(t *testing.T) {
	for name, rs := range map[string]string{"hub": RenderHub(), "core": RenderCore()} {
		if strings.Contains(rs, "ct ") {
			t.Errorf("%s ruleset must not use conntrack", name)
		}
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
