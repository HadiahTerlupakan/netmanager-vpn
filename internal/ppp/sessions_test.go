package ppp

import (
	"net/netip"
	"testing"
)

func TestLivePeersOnlyCountsTheHubsOwnSessions(t *testing.T) {
	gw := netip.MustParseAddr("10.99.0.2")
	a := netip.MustParseAddr
	links := []pppLink{
		{encap: "ppp", up: true, local: gw, peer: a("10.100.0.10")},
		{encap: "ppp", up: true, local: a("192.168.1.1"), peer: a("192.168.1.2")}, // the host's own PPPoE
		{encap: "ppp", up: false, local: gw, peer: a("10.100.0.11")},
		{encap: "none", up: true, local: gw, peer: a("10.100.0.12")},
		{encap: "ppp", up: true, local: gw},
	}
	got := livePeers(links, gw)
	if len(got) != 1 || !got[a("10.100.0.10")] {
		t.Fatalf("live = %v", got)
	}
}
