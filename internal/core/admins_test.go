package core

import (
	"encoding/json"
	"errors"
	"net/netip"
	"strings"
	"testing"

	"github.com/hadiahterlupakan/netmanager-vpn/internal/store"
	"github.com/hadiahterlupakan/netmanager-vpn/internal/wgdevice"
)

func TestAdminPeerAllocatesFromAdminPool(t *testing.T) {
	f := newFixture(t)
	p, err := f.core.CreateAdminPeer("laptop")
	if err != nil {
		t.Fatal(err)
	}
	if p.Address.String() != "10.99.128.1" {
		t.Fatalf("address %s", p.Address)
	}
	got, ok := peerByKey(f.dev.Last(), p.PublicKey)
	if !ok || len(got.AllowedIPs) != 1 || got.AllowedIPs[0] != "10.99.128.1/32" {
		t.Fatalf("wg-core peer %+v", got)
	}
	next, err := f.core.CreateAdminPeer("phone")
	if err != nil || next.Address.String() != "10.99.128.2" {
		t.Fatalf("second peer %+v %v", next, err)
	}
}

func TestCreateAdminPeerValidation(t *testing.T) {
	f := newFixture(t)
	for _, label := range []string{"", "   ", strings.Repeat("a", 65), strings.Repeat("é", 65)} {
		if _, err := f.core.CreateAdminPeer(label); !errors.Is(err, ErrValidation) {
			t.Fatalf("label len %d: %v", len(label), err)
		}
	}
}

func TestAdminConfigContainsRouterPool(t *testing.T) {
	f := newFixture(t)
	p, _ := f.core.CreateAdminPeer("laptop")
	text, err := f.core.AdminConfig(p.ID)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Address = 10.99.128.1/32", "AllowedIPs = 10.99.0.0/24, 10.100.0.0/14",
		"Endpoint = vpn.radpro.id:51822", "PersistentKeepalive = 25"} {
		if !strings.Contains(text, want) {
			t.Fatalf("config lacks %q:\n%s", want, text)
		}
	}
	if _, err := f.core.AdminConfig("nope"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("unknown id: %v", err)
	}
}

func TestAdminConfigExactText(t *testing.T) {
	f := newFixture(t)
	const priv = "cGl2YXRla2V5cHJpdmF0ZWtleXByaXZhdGVrZXk0NDQ="
	sealed, err := f.box.Seal(priv)
	if err != nil {
		t.Fatal(err)
	}
	row, err := f.st.CreateAdminPeer(store.AdminPeer{Label: "x", Address: netip.MustParseAddr("10.99.128.9"),
		PublicKey: "adminpub", PrivateKey: sealed})
	if err != nil {
		t.Fatal(err)
	}
	corePriv, err := f.core.corePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	want := "[Interface]\nPrivateKey = " + priv + "\nAddress = 10.99.128.9/32\n\n" +
		"[Peer]\nPublicKey = " + corePriv.PublicKey().String() + "\nEndpoint = vpn.radpro.id:51822\n" +
		"AllowedIPs = 10.99.0.0/24, 10.100.0.0/14\nPersistentKeepalive = 25\n"
	got, err := f.core.AdminConfig(row.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("got:\n%s\nwant:\n%s", got, want)
	}
}

func TestDeleteAdminPeerRemovesFromCore(t *testing.T) {
	f := newFixture(t)
	p, _ := f.core.CreateAdminPeer("laptop")
	if err := f.core.DeleteAdminPeer(p.ID); err != nil {
		t.Fatal(err)
	}
	if _, ok := peerByKey(f.dev.Last(), p.PublicKey); ok {
		t.Fatal("deleted admin kept its wg-core peer")
	}
	if err := f.core.DeleteAdminPeer(p.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("second delete: %v", err)
	}
	if list, _ := f.core.ListAdminPeers(); len(list) != 0 {
		t.Fatalf("list %+v", list)
	}
}

func TestCreateAdminPeerRollsBackWhenApplyFails(t *testing.T) {
	f := newFixture(t)
	dev := &failingDevice{Memory: wgdevice.NewMemory(), fail: true}
	f.core.dev = dev
	if _, err := f.core.CreateAdminPeer("laptop"); err == nil {
		t.Fatal("want error")
	}
	if list, _ := f.core.ListAdminPeers(); len(list) != 0 {
		t.Fatalf("half-created peer left: %+v", list)
	}
	if len(dev.Last().Peers) != 0 {
		t.Fatalf("device kept the rolled-back peer: %+v", dev.Last().Peers)
	}
	dev.fail = false
	p, err := f.core.CreateAdminPeer("laptop")
	if err != nil || p.Address.String() != "10.99.128.1" {
		t.Fatalf("address not free again: %+v %v", p, err)
	}
}

// The view is what the API serialises; the private key must not be reachable
// from it by any route.
func TestAdminPeerViewHasNoPrivateKey(t *testing.T) {
	f := newFixture(t)
	p, _ := f.core.CreateAdminPeer("laptop")
	row, _ := f.st.ListAdminPeers()
	raw, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.ToLower(string(raw)), "private") || strings.Contains(string(raw), row[0].PrivateKey) {
		t.Fatalf("view leaks key material: %s", raw)
	}
}

func TestCreateAdminPeerCountsLabelInCharacters(t *testing.T) {
	f := newFixture(t)
	if _, err := f.core.CreateAdminPeer(strings.Repeat("é", 64)); err != nil {
		t.Fatalf("64 characters rejected: %v", err)
	}
}

func TestDeleteAdminPeerRetryRevokesAfterFailedApply(t *testing.T) {
	f := newFixture(t)
	p, _ := f.core.CreateAdminPeer("laptop")
	dev := &failingDevice{Memory: f.dev, fail: true}
	f.core.dev = dev
	if err := f.core.DeleteAdminPeer(p.ID); err == nil {
		t.Fatal("want apply error")
	}
	if _, ok := peerByKey(f.dev.Last(), p.PublicKey); !ok {
		t.Fatal("peer should still be on the device after the failed apply")
	}
	dev.fail = false
	if err := f.core.DeleteAdminPeer(p.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("retry: %v", err)
	}
	if _, ok := peerByKey(f.dev.Last(), p.PublicKey); ok {
		t.Fatal("retry left the revoked peer on the device")
	}
}

func TestCreateAdminPeerRetriesOnAddressConflict(t *testing.T) {
	f := newFixture(t)
	raced := false
	f.core.afterAdminTaken = func() {
		if raced {
			return
		}
		raced = true
		_, _ = f.st.CreateAdminPeer(store.AdminPeer{Label: "rival", Address: netip.MustParseAddr("10.99.128.1"),
			PublicKey: "rivalpk", PrivateKey: "x"})
	}
	p, err := f.core.CreateAdminPeer("laptop")
	if err != nil || p.Address.String() != "10.99.128.2" {
		t.Fatalf("got %+v %v", p, err)
	}
}

func TestCreateAdminPeerGivesUpAfterSecondConflict(t *testing.T) {
	f := newFixture(t)
	next := 1
	f.core.afterAdminTaken = func() {
		addr := netip.AddrFrom4([4]byte{10, 99, 128, byte(next)})
		next++
		_, _ = f.st.CreateAdminPeer(store.AdminPeer{Label: "rival", Address: addr, PublicKey: "r", PrivateKey: "x"})
	}
	if _, err := f.core.CreateAdminPeer("laptop"); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("want ErrConflict, got %v", err)
	}
}
