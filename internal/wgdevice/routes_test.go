package wgdevice

import (
	"net"
	"slices"
	"testing"
)

func cidrs(t *testing.T, entries ...string) []*net.IPNet {
	t.Helper()
	out := make([]*net.IPNet, 0, len(entries))
	for _, e := range entries {
		_, n, err := net.ParseCIDR(e)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, n)
	}
	return out
}

func strs(nets []*net.IPNet) []string {
	out := make([]string, 0, len(nets))
	for _, n := range nets {
		out = append(out, n.String())
	}
	slices.Sort(out)
	return out
}

// wg-up carries 10.99.0.N/24 and its core peer lists 10.99.0.0/24: the kernel
// already holds that connected route, so adding it again fails with EEXIST.
func TestPlanRoutesSkipsConnectedPrefixOnAdd(t *testing.T) {
	cfg := Config{Address: "10.99.0.2/24", Peers: []PeerConfig{{AllowedIPs: []string{"10.99.0.0/24", "10.99.128.0/24"}}}}
	add, stale, err := planRoutes(cfg, cidrs(t, "10.99.0.0/24"))
	if err != nil {
		t.Fatal(err)
	}
	if got := strs(add); !slices.Equal(got, []string{"10.99.128.0/24"}) {
		t.Fatalf("add = %v", got)
	}
	if len(stale) != 0 {
		t.Fatalf("connected route marked stale: %v", stale)
	}
}

func TestPlanRoutesAddsMissingAndRemovesStale(t *testing.T) {
	cfg := Config{Address: "10.99.0.1/24", Peers: []PeerConfig{
		{AllowedIPs: []string{"10.99.0.2/32", "10.100.0.5/32"}},
		{AllowedIPs: []string{"10.99.128.2/32"}},
	}}
	add, stale, err := planRoutes(cfg, cidrs(t, "10.99.0.0/24", "10.99.0.2/32", "10.100.0.9/32"))
	if err != nil {
		t.Fatal(err)
	}
	if got := strs(add); !slices.Equal(got, []string{"10.100.0.5/32", "10.99.128.2/32"}) {
		t.Fatalf("add = %v", got)
	}
	if len(stale) != 1 || !stale["10.100.0.9/32"] {
		t.Fatalf("stale = %v", stale)
	}
}

func TestPlanRoutesRejectsBadInput(t *testing.T) {
	if _, _, err := planRoutes(Config{Address: "bogus"}, nil); err == nil {
		t.Fatal("bad interface address accepted")
	}
	cfg := Config{Address: "10.99.0.1/24", Peers: []PeerConfig{{AllowedIPs: []string{"10.1.2"}}}}
	if _, _, err := planRoutes(cfg, nil); err == nil {
		t.Fatal("bad allowed ip accepted")
	}
}
