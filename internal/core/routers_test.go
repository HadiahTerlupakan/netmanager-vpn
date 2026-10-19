package core

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/hadiahterlupakan/netmanager-vpn/internal/store"
)

type peerCall struct {
	hubID, pub string
	addr       netip.Addr
}

type recHubs struct {
	mu          sync.Mutex
	upserts     []peerCall
	deletes     []peerCall
	failUpserts int
	failDeletes bool
	listed      map[string][]HubPeerStatus
}

func (r *recHubs) UpsertPeer(_ context.Context, h store.Hub, pub string, addr netip.Addr) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.failUpserts > 0 {
		r.failUpserts--
		return errors.New("hub unreachable")
	}
	r.upserts = append(r.upserts, peerCall{h.ID, pub, addr})
	return nil
}

func (r *recHubs) DeletePeer(_ context.Context, h store.Hub, pub string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.failDeletes {
		return errors.New("hub unreachable")
	}
	r.deletes = append(r.deletes, peerCall{hubID: h.ID, pub: pub})
	return nil
}

func (r *recHubs) Peers(_ context.Context, h store.Hub) ([]HubPeerStatus, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.listed[h.ID], nil
}

func routerFixture(t *testing.T, hubCount int) (fixture, *recHubs, []store.Hub) {
	t.Helper()
	f := newFixture(t)
	rec := &recHubs{listed: map[string][]HubPeerStatus{}}
	f.core.hubs = rec
	var hubs []store.Hub
	for _, name := range []string{"A", "B", "C"}[:hubCount] {
		h, _, err := f.core.CreateHub(name, name+".example.com", 0)
		if err != nil {
			t.Fatal(err)
		}
		if err := f.st.UpdateHubStatus(h.ID, store.HubStatusOnline, nil); err != nil {
			t.Fatal(err)
		}
		hubs = append(hubs, h)
	}
	return f, rec, hubs
}

func TestCreateRouterRegistersOnEveryHub(t *testing.T) {
	f, rec, hubs := routerFixture(t, 2)
	v, err := f.core.CreateRouter(context.Background(), "cust-1", []string{hubs[0].ID, hubs[1].ID})
	if err != nil {
		t.Fatal(err)
	}
	if len(rec.upserts) != 2 || rec.upserts[0].hubID != hubs[0].ID || rec.upserts[1].hubID != hubs[1].ID {
		t.Fatalf("upserts = %+v", rec.upserts)
	}
	if rec.upserts[0].pub != rec.upserts[1].pub || rec.upserts[0].addr != rec.upserts[1].addr {
		t.Fatalf("hubs got different peers: %+v", rec.upserts)
	}
	if rec.upserts[0].addr.String() != v.Address || v.Status != store.RouterStatusPending || v.Ref != "" {
		t.Fatalf("view = %+v", v)
	}
	for i, h := range v.Hubs {
		if h.SyncState != store.SyncStateSynced || h.Priority != i || h.Name == "" {
			t.Fatalf("hub %d = %+v", i, h)
		}
	}
	rt, _ := f.st.GetRouter(v.ID)
	if rt.PrivateKey == "" || rt.PublicKey != rec.upserts[0].pub {
		t.Fatalf("router row = %+v", rt)
	}
}

func TestCreateRouterRejectsOfflineHub(t *testing.T) {
	f, rec, hubs := routerFixture(t, 2)
	if err := f.st.UpdateHubStatus(hubs[1].ID, store.HubStatusPendingInstall, nil); err != nil {
		t.Fatal(err)
	}
	_, err := f.core.CreateRouter(context.Background(), "x", []string{hubs[0].ID, hubs[1].ID})
	if !errors.Is(err, ErrValidation) || len(rec.upserts) != 0 {
		t.Fatalf("err = %v, upserts = %d", err, len(rec.upserts))
	}
	if rs, _ := f.st.ListRouters(); len(rs) != 0 {
		t.Fatal("router stored despite validation error")
	}
}

func TestCreateRouterRejectsDuplicateHub(t *testing.T) {
	f, _, hubs := routerFixture(t, 1)
	_, err := f.core.CreateRouter(context.Background(), "x", []string{hubs[0].ID, hubs[0].ID})
	if !errors.Is(err, ErrValidation) {
		t.Fatalf("err = %v", err)
	}
}

func TestCreateRouterRejectsUnknownHub(t *testing.T) {
	f, _, _ := routerFixture(t, 1)
	_, err := f.core.CreateRouter(context.Background(), "x", []string{"nope"})
	if !errors.Is(err, ErrValidation) {
		t.Fatalf("err = %v", err)
	}
}

func TestUnreachableHubMarkedPendingThenSynced(t *testing.T) {
	f, rec, hubs := routerFixture(t, 2)
	rec.failUpserts = 1
	v, err := f.core.CreateRouter(context.Background(), "x", []string{hubs[0].ID, hubs[1].ID})
	if err != nil {
		t.Fatal(err)
	}
	if v.Hubs[0].SyncState != store.SyncStatePending || v.Hubs[1].SyncState != store.SyncStateSynced {
		t.Fatalf("hubs = %+v", v.Hubs)
	}
	if err := f.core.SyncPending(context.Background()); err != nil {
		t.Fatal(err)
	}
	v, _ = f.core.GetRouter(v.ID)
	if v.Hubs[0].SyncState != store.SyncStateSynced {
		t.Fatalf("after sync: %+v", v.Hubs)
	}
}

func TestSetRouterHubsRemovesDroppedHub(t *testing.T) {
	f, rec, hubs := routerFixture(t, 2)
	ctx := context.Background()
	v, _ := f.core.CreateRouter(ctx, "x", []string{hubs[0].ID, hubs[1].ID})
	if err := f.core.SetRouterHubs(ctx, v.ID, []string{hubs[1].ID}); err != nil {
		t.Fatal(err)
	}
	if len(rec.deletes) != 1 || rec.deletes[0].hubID != hubs[0].ID || rec.deletes[0].pub != rec.upserts[0].pub {
		t.Fatalf("deletes = %+v", rec.deletes)
	}
	if len(rec.upserts) != 2 {
		t.Fatalf("kept hub was re-registered: %+v", rec.upserts)
	}
}

func TestExpirePendingAfter24h(t *testing.T) {
	f, rec, hubs := routerFixture(t, 1)
	ctx := context.Background()
	v, _ := f.core.CreateRouter(ctx, "x", []string{hubs[0].ID})
	now := time.Now()
	if n, err := f.core.ExpirePending(ctx, now.Add(23*time.Hour)); err != nil || n != 0 {
		t.Fatalf("23h: n=%d err=%v", n, err)
	}
	if _, err := f.st.GetRouter(v.ID); err != nil {
		t.Fatal(err)
	}
	if n, err := f.core.ExpirePending(ctx, now.Add(25*time.Hour)); err != nil || n != 1 {
		t.Fatalf("25h: n=%d err=%v", n, err)
	}
	if _, err := f.st.GetRouter(v.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("router still stored: %v", err)
	}
	if len(rec.deletes) != 1 || rec.deletes[0].hubID != hubs[0].ID {
		t.Fatalf("deletes = %+v", rec.deletes)
	}
}

func TestClaimedRouterNotExpired(t *testing.T) {
	f, _, hubs := routerFixture(t, 1)
	ctx := context.Background()
	v, _ := f.core.CreateRouter(ctx, "x", []string{hubs[0].ID})
	if err := f.core.ClaimRouter(v.ID, "dev-1"); err != nil {
		t.Fatal(err)
	}
	if n, err := f.core.ExpirePending(ctx, time.Now().Add(72*time.Hour)); err != nil || n != 0 {
		t.Fatalf("n=%d err=%v", n, err)
	}
	got, err := f.core.GetRouter(v.ID)
	if err != nil || got.Status != store.RouterStatusActive || got.Ref != "dev-1" {
		t.Fatalf("got = %+v err = %v", got, err)
	}
	if err := f.core.ClaimRouter("missing", "r"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("err = %v", err)
	}
}

func TestSyncPendingPrunesStrangers(t *testing.T) {
	f, rec, hubs := routerFixture(t, 2)
	ctx := context.Background()
	v, _ := f.core.CreateRouter(ctx, "x", []string{hubs[0].ID})
	own := rec.upserts[0].pub
	rec.listed[hubs[0].ID] = []HubPeerStatus{{PublicKey: own}, {PublicKey: "stranger"}}
	// Hub B does not carry this router, so its copy is stale too.
	rec.listed[hubs[1].ID] = []HubPeerStatus{{PublicKey: own}}
	if err := f.core.SyncPending(ctx); err != nil {
		t.Fatal(err)
	}
	want := []peerCall{{hubID: hubs[0].ID, pub: "stranger"}, {hubID: hubs[1].ID, pub: own}}
	if len(rec.deletes) != 2 || rec.deletes[0] != want[0] || rec.deletes[1] != want[1] {
		t.Fatalf("deletes = %+v, want %+v (router %s)", rec.deletes, want, v.ID)
	}
}

func TestDeleteRouterToleratesHubFailure(t *testing.T) {
	f, rec, hubs := routerFixture(t, 2)
	ctx := context.Background()
	v, _ := f.core.CreateRouter(ctx, "x", []string{hubs[0].ID, hubs[1].ID})
	rec.failDeletes = true
	if err := f.core.DeleteRouter(ctx, v.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.core.GetRouter(v.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("err = %v", err)
	}
}
