// Package ipam hands out tunnel addresses from fixed pools.
package ipam

import (
	"errors"
	"net/netip"
	"time"
)

// Pools and the inclusive bounds callers allocate within. The bounds exclude
// network and broadcast addresses and, for the backhaul, the core's own .1
// and the range above .126.
var (
	RouterPool   = netip.MustParsePrefix("10.100.0.0/14")
	BackhaulPool = netip.MustParsePrefix("10.99.0.0/24")
	AdminPool    = netip.MustParsePrefix("10.99.128.0/24")

	RouterFirst   = netip.MustParseAddr("10.100.0.1")
	RouterLast    = netip.MustParseAddr("10.103.255.254")
	BackhaulFirst = netip.MustParseAddr("10.99.0.2")
	BackhaulLast  = netip.MustParseAddr("10.99.0.126")
	AdminFirst    = netip.MustParseAddr("10.99.128.1")
	AdminLast     = netip.MustParseAddr("10.99.128.254")
)

// releaseHold keeps a released address out of circulation: netmanager may
// still have the old address in nas.nasname for a while.
const releaseHold = 7 * 24 * time.Hour

// ErrExhausted means no address in the range is free.
var ErrExhausted = errors.New("ipam: no free address")

// Allocate returns the lowest address in [first, last] inside pool that is not
// in use. taken maps an address to the time it was released; a zero time means
// it is still in use.
func Allocate(pool netip.Prefix, first, last netip.Addr, taken map[netip.Addr]time.Time, now time.Time) (netip.Addr, error) {
	for ip := first; ip.IsValid() && ip.Compare(last) <= 0 && pool.Contains(ip); ip = ip.Next() {
		released, ok := taken[ip]
		if !ok || (!released.IsZero() && now.Sub(released) >= releaseHold) {
			return ip, nil
		}
	}
	return netip.Addr{}, ErrExhausted
}
