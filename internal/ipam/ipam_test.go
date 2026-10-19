package ipam

import (
	"errors"
	"net/netip"
	"testing"
	"time"
)

var now = time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)

func a(s string) netip.Addr { return netip.MustParseAddr(s) }

func TestAllocateSkipsTaken(t *testing.T) {
	taken := map[netip.Addr]time.Time{a("10.99.0.2"): {}, a("10.99.0.3"): {}}
	got, err := Allocate(BackhaulPool, BackhaulFirst, BackhaulLast, taken, now)
	if err != nil {
		t.Fatal(err)
	}
	if got != a("10.99.0.4") {
		t.Fatalf("got %s, want 10.99.0.4", got)
	}
}

func TestAllocateBackhaulRange(t *testing.T) {
	taken := map[netip.Addr]time.Time{}
	for ip := BackhaulFirst; ip.Compare(BackhaulLast) <= 0; ip = ip.Next() {
		taken[ip] = time.Time{}
	}
	if _, err := Allocate(BackhaulPool, BackhaulFirst, BackhaulLast, taken, now); !errors.Is(err, ErrExhausted) {
		t.Fatalf("err = %v, want ErrExhausted", err)
	}
}

func TestAllocateHoldsReleasedForSevenDays(t *testing.T) {
	taken := map[netip.Addr]time.Time{
		a("10.99.0.2"): now.Add(-6 * 24 * time.Hour),
		a("10.99.0.3"): now.Add(-8 * 24 * time.Hour),
	}
	got, err := Allocate(BackhaulPool, BackhaulFirst, BackhaulLast, taken, now)
	if err != nil {
		t.Fatal(err)
	}
	if got != a("10.99.0.3") {
		t.Fatalf("got %s, want 10.99.0.3", got)
	}
}

func TestAllocateRouterPoolFirstIsNotNetworkAddress(t *testing.T) {
	got, err := Allocate(RouterPool, RouterFirst, RouterLast, nil, now)
	if err != nil {
		t.Fatal(err)
	}
	if got != a("10.100.0.1") {
		t.Fatalf("got %s, want 10.100.0.1", got)
	}
}

func TestAllocateStaysInsidePool(t *testing.T) {
	if _, err := Allocate(AdminPool, a("10.99.128.254"), a("10.99.129.5"), map[netip.Addr]time.Time{a("10.99.128.254"): {}, a("10.99.128.255"): {}}, now); !errors.Is(err, ErrExhausted) {
		t.Fatalf("err = %v, want ErrExhausted", err)
	}
}
