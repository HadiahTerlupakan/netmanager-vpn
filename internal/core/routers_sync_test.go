package core

import (
	"context"
	"testing"
)

// A hub restored from an old backup or reinstalled by hand loses peers the
// core still counts as synced; nothing else would ever re-register them.
func TestSyncPendingRepushesPeerHubLost(t *testing.T) {
	f, rec, hubs := routerFixture(t, 2)
	ctx := context.Background()
	v, err := f.core.CreateRouter(ctx, "x", []string{hubs[0].ID, hubs[1].ID}, "")
	if err != nil {
		t.Fatal(err)
	}
	rt, _ := f.st.GetRouter(v.ID)
	delete(rec.present[hubs[0].ID], rt.PublicKey)
	before := len(rec.upserts)
	if err := f.core.SyncPending(ctx); err != nil {
		t.Fatal(err)
	}
	if !rec.present[hubs[0].ID][rt.PublicKey] {
		t.Fatal("lost peer not re-pushed")
	}
	if got := rec.upserts[before:]; len(got) != 1 || got[0].hubID != hubs[0].ID || got[0].addr != rt.Address {
		t.Fatalf("re-push calls = %+v", got)
	}
}

func TestRepushUndoneForRouterRevokedMidPush(t *testing.T) {
	f, rec, hubs := routerFixture(t, 1)
	ctx := context.Background()
	v, _ := f.core.CreateRouter(ctx, "x", []string{hubs[0].ID}, "")
	rt, _ := f.st.GetRouter(v.ID)
	delete(rec.present[hubs[0].ID], rt.PublicKey)
	rec.beforeUpsert = func() {
		if err := f.core.DeleteRouter(ctx, v.ID); err != nil {
			t.Error(err)
		}
	}
	if err := f.core.SyncPending(ctx); err != nil {
		t.Fatal(err)
	}
	if rec.present[hubs[0].ID][rt.PublicKey] {
		t.Fatal("re-push left a revoked router on the hub")
	}
}
