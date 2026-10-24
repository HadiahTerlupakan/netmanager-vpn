package wgdevice

import (
	"errors"
	"fmt"
	"net"
	"slices"
	"strings"
	"syscall"
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

// fakeTable refuses a route some link already holds, as the kernel does.
type fakeTable struct {
	holders map[string]string // destination -> link name
	added   []string
}

func (f *fakeTable) add(dst *net.IPNet) error {
	if _, held := f.holders[dst.String()]; held {
		return fmt.Errorf("file exists: %w", syscall.EEXIST)
	}
	f.added = append(f.added, dst.String())
	return nil
}

func (f *fakeTable) holder(dst *net.IPNet) string { return f.holders[dst.String()] }

func TestAddRoutesYieldsToPPPLinkAndAddsTheRest(t *testing.T) {
	tbl := &fakeTable{holders: map[string]string{"10.100.0.11/32": "nmppp0"}}
	err := addRoutes(cidrs(t, "10.100.0.10/32", "10.100.0.11/32", "10.100.0.12/32"), "nmppp", tbl.add, tbl.holder)
	if !errors.Is(err, ErrRouteBusy) || !strings.Contains(err.Error(), "10.100.0.11/32") {
		t.Fatalf("err = %v", err)
	}
	if !slices.Equal(tbl.added, []string{"10.100.0.10/32", "10.100.0.12/32"}) {
		t.Fatalf("added = %v", tbl.added)
	}
	delete(tbl.holders, "10.100.0.11/32")
	if err := addRoutes(cidrs(t, "10.100.0.11/32"), "nmppp", tbl.add, tbl.holder); err != nil {
		t.Fatalf("route not added once the link was gone: %v", err)
	}
}

func TestAddRoutesFailsOnForeignCollision(t *testing.T) {
	for name, yieldTo := range map[string]string{"other link": "nmppp", "no yield": ""} {
		tbl := &fakeTable{holders: map[string]string{"10.100.0.11/32": "ppp0"}}
		if name == "no yield" {
			tbl.holders["10.100.0.11/32"] = "nmppp0"
		}
		err := addRoutes(cidrs(t, "10.100.0.11/32", "10.100.0.12/32"), yieldTo, tbl.add, tbl.holder)
		if err == nil || errors.Is(err, ErrRouteBusy) || !errors.Is(err, syscall.EEXIST) {
			t.Fatalf("%s: err = %v", name, err)
		}
		if !slices.Equal(tbl.added, []string{"10.100.0.12/32"}) {
			t.Fatalf("%s: added = %v", name, tbl.added)
		}
	}
}
