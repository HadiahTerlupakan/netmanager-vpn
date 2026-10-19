package store

import (
	"errors"
	"fmt"
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
		Status: HubStatusPendingInstall, JoinExpiresAt: time.Now().Add(time.Hour),
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
		PublicKey: "rpub-" + label, PrivateKey: "rsealed-" + label, Status: RouterStatusPending,
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
	if err := s.UpdateRouterHubSyncState(r.ID, a.ID, SyncStateSynced); err != nil {
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
	if got[0].SyncState != SyncStatePending || got[1].SyncState != SyncStateSynced {
		t.Fatalf("sync states = %q, %q; want pending, synced", got[0].SyncState, got[1].SyncState)
	}
}

func TestSetRouterHubsRemovesDropped(t *testing.T) {
	s := openTemp(t)
	a := newHub(t, s, "a", "10.99.0.2")
	b := newHub(t, s, "b", "10.99.0.3")
	r := newRouter(t, s, "r1", "10.100.0.1")
	if err := s.SetRouterHubs(r.ID, []string{a.ID, b.ID}); err != nil {
		t.Fatal(err)
	}
	if err := s.SetRouterHubs(r.ID, []string{b.ID}); err != nil {
		t.Fatal(err)
	}
	got := must(s.ListRouterHubs(r.ID))
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
	if err := s.UpdateHubStatus(h.ID, HubStatusOnline, &seen); err != nil {
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
	if got.Status != HubStatusOnline || got.LastSeenAt == nil || !got.LastSeenAt.Equal(seen) ||
		got.PublicKey != "newpub" || got.PrivateKey != "newsealed" || got.APIToken != "newtok" ||
		!got.JoinExpiresAt.Equal(exp) || got.BackhaulAddr != h.BackhaulAddr {
		t.Fatalf("hub = %+v", got)
	}
	if err := s.UpdateHubStatus("nope", "x", nil); !errors.Is(err, ErrNotFound) {
		t.Fatalf("UpdateHubStatus missing = %v", err)
	}
	list := must(s.ListHubs())
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
	got := must(s.GetRouter(r.ID))
	if got.Status != RouterStatusActive {
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
	back := must(s.TakenAddresses("backhaul"))
	adm := must(s.TakenAddresses("admin"))
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
	if l := must(s.ListAdminPeers()); len(l) != 0 {
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
	for _, v := range []string{"one", "two"} {
		if err := s.SetServerKey("wg-core", v); err != nil {
			t.Fatal(err)
		}
	}
	if got := must(s.ServerKey("wg-core")); got != "two" {
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
	peers := must(s.ListPeers())
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

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

func TestRouterAddressUniqueWhileLive(t *testing.T) {
	s := openTemp(t)
	first := newRouter(t, s, "r1", "10.100.0.1")
	_, err := s.CreateRouter(Router{Label: "dup", Address: first.Address, Status: RouterStatusPending})
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate live address = %v, want ErrConflict", err)
	}
	if err := s.DeleteRouter(first.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateRouter(Router{Label: "reuse", Address: first.Address, Status: RouterStatusPending}); err != nil {
		t.Fatalf("released address reuse: %v", err)
	}
}

func TestHubAndAdminAddressConflict(t *testing.T) {
	s := openTemp(t)
	h := newHub(t, s, "a", "10.99.0.2")
	if _, err := s.CreateHub(Hub{Name: "b", BackhaulAddr: h.BackhaulAddr}); !errors.Is(err, ErrConflict) {
		t.Fatalf("hub dup = %v", err)
	}
	p := AdminPeer{Label: "x", Address: netip.MustParseAddr("10.99.128.2")}
	if _, err := s.CreateAdminPeer(p); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateAdminPeer(p); !errors.Is(err, ErrConflict) {
		t.Fatalf("admin dup = %v", err)
	}
}

func TestTakenAddressesLiveBeatsReleased(t *testing.T) {
	s := openTemp(t)
	addr := netip.MustParseAddr("10.100.0.1")
	live := newRouter(t, s, "live", addr.String())
	// A released row inserted after the live one, with a later created_at,
	// must not mask it whatever order the scan returns them in.
	if _, err := s.db.Exec(`INSERT INTO routers (id, label, ref, address, public_key, private_key, status, created_at, released_at)
		VALUES ('old','old','','10.100.0.1','','','pending',?,?)`, fmtTime(time.Now().Add(time.Hour)), fmtTime(time.Now())); err != nil {
		t.Fatal(err)
	}
	got := must(s.TakenAddresses("router"))
	if at, ok := got[addr]; !ok || !at.IsZero() {
		t.Fatalf("live address masked: %v, %v", at, ok)
	}
	if err := s.DeleteRouter(live.ID); err != nil {
		t.Fatal(err)
	}
	got = must(s.TakenAddresses("router"))
	if at := got[addr]; at.IsZero() || !at.After(time.Now().Add(-time.Minute)) {
		t.Fatalf("want latest released_at, got %v", at)
	}
}

func TestTakenAddressesLatestReleaseWins(t *testing.T) {
	s := openTemp(t)
	addr := "10.100.0.5"
	older := time.Now().Add(-48 * time.Hour)
	newer := time.Now().Add(-time.Hour)
	for i, at := range []time.Time{newer, older} {
		if _, err := s.db.Exec(`INSERT INTO routers (id, label, ref, address, public_key, private_key, status, created_at, released_at)
			VALUES (?,?,'',?,'','','pending',?,?)`, fmt.Sprint("r", i), "x", addr, fmtTime(older), fmtTime(at)); err != nil {
			t.Fatal(err)
		}
	}
	got := must(s.TakenAddresses("router"))[netip.MustParseAddr(addr)]
	if !got.Equal(newer.UTC().Truncate(time.Nanosecond)) {
		t.Fatalf("got %v, want %v", got, newer)
	}
}

func TestSetRouterHubsRejectsOrphans(t *testing.T) {
	s := openTemp(t)
	h := newHub(t, s, "a", "10.99.0.2")
	r := newRouter(t, s, "r1", "10.100.0.1")
	if err := s.SetRouterHubs(r.ID, []string{h.ID, "missing"}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown hub = %v", err)
	}
	if err := s.SetRouterHubs("missing", []string{h.ID}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown router = %v", err)
	}
	if err := s.DeleteRouter(r.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.SetRouterHubs(r.ID, []string{h.ID}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("released router = %v", err)
	}
	if err := s.DeleteHub(h.ID); err != nil {
		t.Fatalf("no orphan row should pin the hub: %v", err)
	}
}

func TestClaimRouterOnlyWhenPending(t *testing.T) {
	s := openTemp(t)
	r := newRouter(t, s, "r1", "10.100.0.1")
	if err := s.ClaimRouter(r.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.ClaimRouter(r.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second claim = %v", err)
	}
	gone := newRouter(t, s, "r2", "10.100.0.2")
	if err := s.DeleteRouter(gone.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.ClaimRouter(gone.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("claim released = %v", err)
	}
}

func TestOpenRejectsNewerSchema(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`INSERT INTO schema_migrations (version) VALUES (?)`, len(migrations)+1); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path); err == nil {
		t.Fatal("Open accepted a database from a newer build")
	}
}

func TestHubRouterCountsSkipsReleased(t *testing.T) {
	s := openTemp(t)
	a := newHub(t, s, "a", "10.99.0.2")
	b := newHub(t, s, "b", "10.99.0.3")
	r1 := newRouter(t, s, "r1", "10.100.0.1")
	r2 := newRouter(t, s, "r2", "10.100.0.2")
	for _, r := range []Router{r1, r2} {
		if err := s.SetRouterHubs(r.ID, []string{a.ID}); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.SetRouterHubs(r2.ID, []string{a.ID, b.ID}); err != nil {
		t.Fatal(err)
	}
	got, err := s.HubRouterCounts()
	if err != nil || got[a.ID] != 2 || got[b.ID] != 1 {
		t.Fatalf("counts %v err %v", got, err)
	}
	if err := s.DeleteRouter(r1.ID); err != nil {
		t.Fatal(err)
	}
	got, _ = s.HubRouterCounts()
	if got[a.ID] != 1 {
		t.Fatalf("released router still counted: %v", got)
	}
}
