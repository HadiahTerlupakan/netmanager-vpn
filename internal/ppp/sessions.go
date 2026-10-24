package ppp

import "net/netip"

// Sessions sees the PPP sessions the daemon holds and ends one.
type Sessions interface {
	// Live returns the router address of every session that is up.
	Live() (map[netip.Addr]bool, error)
	// Terminate ends the session at addr. The router dials again within
	// seconds, so its login must already be gone from chap-secrets.
	Terminate(addr netip.Addr) error
}

// pppLink is what Live needs to know of one kernel link.
type pppLink struct {
	encap       string
	up          bool
	local, peer netip.Addr
}

// livePeers keeps only links that are accel-ppp's: up, of type ppp, and with
// the hub's gateway address as their local end. Any other PPP link on the
// host, such as its own PPPoE uplink, is never stamped or terminated.
func livePeers(links []pppLink, gw netip.Addr) map[netip.Addr]bool {
	live := map[netip.Addr]bool{}
	for _, l := range links {
		if l.encap == "ppp" && l.up && l.local == gw && l.peer.IsValid() {
			live[l.peer] = true
		}
	}
	return live
}
