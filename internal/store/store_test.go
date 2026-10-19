package store

import (
	"errors"
	"net/netip"
	"path/filepath"
	"testing"
	"time"
)

func openTemp(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func newHub(t *testing.T, s *Store, name, addr string) Hub {
	t.Helper()
	h, err := s.CreateHub(Hub{
		Name: name, PublicHost: name + ".example.net", ListenPort: 51821,
		BackhaulAddr: netip.MustParseAddr(addr), PublicKey: "pub-" + name,
		PrivateKey: "sealed-" + name, APIToken: "tok-" + name,
		Status: "pending_install", JoinExpiresAt: time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("CreateHub: %v", err)
	}
	return h
}

func newRouter(t *testing.T, s *Store, label, addr string) Router {
	t.Helper()
	r, err := s.CreateRouter(Router{
		Label: label, Ref: "ref-" + label, Address: netip.MustParseAddr(addr),
		PublicKey: "rpub-" + label, PrivateKey: "rsealed-" + label, Status: "pending",
	})
	if err != nil {
		t.Fatalf("CreateRouter: %v", err)
	}
	return r
}

func TestMigrateIsIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = Open(path)
	if err != nil {
		t.Fatalf("second Open: %v", err)
	}
	s.Close()
}

func TestDeleteHubRefusedWhileReferenced(t *testing.T) {
	s := openTemp(t)
	h := newHub(t, s, "a", "10.99.0.2")
	r := newRouter(t, s, "r1", "10.100.0.1")
	if err := s.SetRouterHubs(r.ID, []string{h.ID}); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteHub(h.ID); !errors.Is(err, ErrInUse) {
		t.Fatalf("DeleteHub = %v, want ErrInUse", err)
	}
	if err := s.DeleteRouter(r.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteHub(h.ID); err != nil {
		t.Fatalf("DeleteHub after release: %v", err)
	}
	if _, err := s.GetHub(h.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetHub = %v, want ErrNotFound", err)
	}
}

func TestDeleteRouterKeepsReleasedAt(t *testing.T) {
	s := openTemp(t)
	live := newRouter(t, s, "live", "10.100.0.1")
	gone := newRouter(t, s, "gone", "10.100.0.2")
	if err := s.DeleteRouter(gone.ID); err != nil {
		t.Fatal(err)
	}
	taken, err := s.TakenAddresses("router")
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := taken[live.Address]; !ok || !got.IsZero() {
		t.Fatalf("live address = %v, %v; want zero time", got, ok)
	}
	if got, ok := taken[gone.Address]; !ok || got.IsZero() {
		t.Fatalf("released address = %v, %v; want released_at", got, ok)
	}
	if _, err := s.GetRouter(gone.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetRouter released = %v, want ErrNotFound", err)
	}
	list, err := s.ListRouters()
	if err != nil || len(list) != 1 || list[0].ID != live.ID {
		t.Fatalf("ListRouters = %v, %v", list, err)
	}
}

func TestSetRouterHubsReplacesOrder(t *testing.T) {
	s := openTemp(t)
	a := newHub(t, s, "a", "10.99.0.2")
	b := newHub(t, s, "b", "10.99.0.3")
	r := newRouter(t, s, "r1", "10.100.0.1")
	if err := s.SetRouterHubs(r.ID, []string{a.ID, b.ID}); err != nil {
		t.Fatal(err)
	}
	if err := s.UpdateRouterHubSyncState(r.ID, a.ID, "synced"); err != nil {
		t.Fatal(err)
	}
	if err := s.SetRouterHubs(r.ID, []string{b.ID, a.ID}); err != nil {
		t.Fatal(err)
	}
	got, err := s.ListRouterHubs(r.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].HubID != b.ID || got[0].Priority != 0 ||
		got[1].HubID != a.ID || got[1].Priority != 1 {
		t.Fatalf("order = %+v", got)
	}
	if got[0].SyncState != "pending" || got[1].SyncState != "synced" {
		t.Fatalf("sync states = %q, %q; want pending, synced", got[0].SyncState, got[1].SyncState)
	}
}

func TestSetRouterHubsRemovesDropped(t *testing.T) {
	s := openTemp(t)
	a := newHub(t, s, "a", "10.99.0.2")
	b := newHub(t, s, "b", "10.99.0.3")
	r := newRouter(t, s, "r1", "10.100.0.1")
	_ = s.SetRouterHubs(r.ID, []string{a.ID, b.ID})
	if err := s.SetRouterHubs(r.ID, []string{b.ID}); err != nil {
		t.Fatal(err)
	}
	got, _ := s.ListRouterHubs(r.ID)
	if len(got) != 1 || got[0].HubID != b.ID || got[0].Priority != 0 {
		t.Fatalf("got %+v", got)
	}
	if err := s.DeleteHub(a.ID); err != nil {
		t.Fatalf("dropped hub should be deletable: %v", err)
	}
}

func TestHubLifecycle(t *testing.T) {
	s := openTemp(t)
	h := newHub(t, s, "a", "10.99.0.2")
	if h.ID == "" || h.CreatedAt.IsZero() {
		t.Fatalf("CreateHub did not fill ID/CreatedAt: %+v", h)
	}
	seen := time.Now().UTC().Truncate(time.Second)
	if err := s.UpdateHubStatus(h.ID, "online", &seen); err != nil {
		t.Fatal(err)
	}
	exp := time.Now().Add(2 * time.Hour)
	if err := s.UpdateHubKeys(h.ID, "newpub", "newsealed", "newtok", exp); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetHub(h.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != "online" || got.LastSeenAt == nil || !got.LastSeenAt.Equal(seen) ||
		got.PublicKey != "newpub" || got.PrivateKey != "newsealed" || got.APIToken != "newtok" ||
		!got.JoinExpiresAt.Equal(exp) || got.BackhaulAddr != h.BackhaulAddr {
		t.Fatalf("hub = %+v", got)
	}
	if err := s.UpdateHubStatus("nope", "x", nil); !errors.Is(err, ErrNotFound) {
		t.Fatalf("UpdateHubStatus missing = %v", err)
	}
	list, _ := s.ListHubs()
	if len(list) != 1 {
		t.Fatalf("ListHubs = %d", len(list))
	}
}

func TestClaimRouterAndEvents(t *testing.T) {
	s := openTemp(t)
	a := newHub(t, s, "a", "10.99.0.2")
	b := newHub(t, s, "b", "10.99.0.3")
	r := newRouter(t, s, "r1", "10.100.0.1")
	if err := s.ClaimRouter(r.ID); err != nil {
		t.Fatal(err)
	}
	got, _ := s.GetRouter(r.ID)
	if got.Status != "active" {
		t.Fatalf("status = %q", got.Status)
	}
	if err := s.AddRouterEvent(r.ID, a.ID, b.ID, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := s.AddRouterEvent(r.ID, "", a.ID, time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	ev, err := s.ListRouterEvents(r.ID, 10)
	if err != nil || len(ev) != 2 {
		t.Fatalf("events = %v, %v", ev, err)
	}
	if ev[0].FromHubID != "" || ev[0].ToHubID != a.ID || ev[1].FromHubID != a.ID {
		t.Fatalf("events not newest first: %+v", ev)
	}
}

func TestTakenAddressesKinds(t *testing.T) {
	s := openTemp(t)
	h := newHub(t, s, "a", "10.99.0.2")
	p, err := s.CreateAdminPeer(AdminPeer{
		Label: "laptop", Address: netip.MustParseAddr("10.99.128.2"),
		PublicKey: "apub", PrivateKey: "asealed",
	})
	if err != nil {
		t.Fatal(err)
	}
	back, _ := s.TakenAddresses("backhaul")
	adm, _ := s.TakenAddresses("admin")
	if _, ok := back[h.BackhaulAddr]; !ok || len(back) != 1 {
		t.Fatalf("backhaul = %v", back)
	}
	if _, ok := adm[p.Address]; !ok || len(adm) != 1 {
		t.Fatalf("admin = %v", adm)
	}
	if _, err := s.TakenAddresses("bogus"); err == nil {
		t.Fatal("unknown kind should error")
	}
	if err := s.DeleteAdminPeer(p.ID); err != nil {
		t.Fatal(err)
	}
	if l, _ := s.ListAdminPeers(); len(l) != 0 {
		t.Fatalf("admin peers = %v", l)
	}
	if err := s.DeleteAdminPeer(p.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second delete = %v", err)
	}
}

func TestServerKey(t *testing.T) {
	s := openTemp(t)
	if _, err := s.ServerKey("wg-core"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing = %v", err)
	}
	_ = s.SetServerKey("wg-core", "one")
	_ = s.SetServerKey("wg-core", "two")
	if got, _ := s.ServerKey("wg-core"); got != "two" {
		t.Fatalf("got %q", got)
	}
}

func TestHubConfigAndPeers(t *testing.T) {
	s := openTemp(t)
	if _, err := s.LoadHubConfig(); !errors.Is(err, ErrNotFound) {
		t.Fatalf("empty = %v", err)
	}
	cfg := HubConfig{
		CorePublicKey: "cpub", CoreEndpoint: "core.example.net:51822",
		BackhaulAddr: netip.MustParseAddr("10.99.0.2"), APIToken: "tok",
		PrivateKeyUp: "up", PrivateKeyNM: "nm",
	}
	if err := s.SaveHubConfig(cfg); err != nil {
		t.Fatal(err)
	}
	cfg.APIToken = "tok2"
	if err := s.SaveHubConfig(cfg); err != nil {
		t.Fatal(err)
	}
	got, err := s.LoadHubConfig()
	if err != nil || got != cfg {
		t.Fatalf("got %+v, %v", got, err)
	}

	addr := netip.MustParseAddr("10.100.0.1")
	if err := s.UpsertPeer(Peer{PublicKey: "p1", Address: addr}); err != nil {
		t.Fatal(err)
	}
	addr2 := netip.MustParseAddr("10.100.0.9")
	if err := s.UpsertPeer(Peer{PublicKey: "p1", Address: addr2}); err != nil {
		t.Fatal(err)
	}
	peers, _ := s.ListPeers()
	if len(peers) != 1 || peers[0].Address != addr2 || peers[0].CreatedAt.IsZero() {
		t.Fatalf("peers = %+v", peers)
	}
	if err := s.DeletePeer("p1"); err != nil {
		t.Fatal(err)
	}
	if err := s.DeletePeer("p1"); err != nil {
		t.Fatalf("deleting absent peer should be idempotent: %v", err)
	}
}
