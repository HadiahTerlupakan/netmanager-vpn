package ppp

import (
	"net/netip"
	"testing"
)

func TestLivePeersOnlyCountsTheHubsOwnSessions(t *testing.T) {
	gw := netip.MustParseAddr("10.99.0.2")
	a := netip.MustParseAddr
	links := []pppLink{
		{name: "nmppp0", encap: "ppp", up: true, local: gw, peer: a("10.100.0.10")},
		{name: "ppp0", encap: "ppp", up: true, local: a("192.168.1.1"), peer: a("192.168.1.2")}, // the host's own PPPoE
		// A host uplink whose local end happens to equal the gateway.
		{name: "ppp1", encap: "ppp", up: true, local: gw, peer: a("10.100.0.14")},
		{name: "nmppp1", encap: "ppp", up: false, local: gw, peer: a("10.100.0.11")},
		{name: "nmppp2", encap: "none", up: true, local: gw, peer: a("10.100.0.12")},
		{name: "nmppp3", encap: "ppp", up: true, local: gw},
	}
	got := livePeers(links, gw)
	if len(got) != 1 || !got[a("10.100.0.10")] {
		t.Fatalf("live = %v", got)
	}
}
