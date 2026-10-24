package core

import (
	"context"
	"errors"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/hadiahterlupakan/netmanager-vpn/internal/store"
	"github.com/hadiahterlupakan/netmanager-vpn/internal/wgdevice"
)

func ptr(s string) *string { return &s }

func TestChooseActive(t *testing.T) {
	now := testNow
	ago := func(s int) time.Time { return now.Add(-time.Duration(s) * time.Second) }
	tests := []struct {
		name string
		hs   map[string]time.Time
		cur  *string
		want *string
	}{
		{"no handshakes", nil, nil, nil},
		{"newest wins", map[string]time.Time{"A": ago(10), "B": ago(100)}, nil, ptr("A")},
		{"current kept within 5s of newest", map[string]time.Time{"A": ago(5), "B": ago(8)}, ptr("B"), ptr("B")},
		{"current kept at exactly 5s", map[string]time.Time{"A": ago(5), "B": ago(10)}, ptr("B"), ptr("B")},
		{"current dropped when stale", map[string]time.Time{"A": ago(5), "B": ago(170)}, ptr("B"), ptr("A")},
		{"current dropped beyond 5s", map[string]time.Time{"A": ago(5), "B": ago(11)}, ptr("B"), ptr("A")},
		{"planned switch wins at the next rekey gap", map[string]time.Time{"A": ago(5), "B": ago(20)}, ptr("B"), ptr("A")},
		{"all stale", map[string]time.Time{"A": ago(200), "B": ago(200)}, nil, nil},
		{"exactly 180s is stale", map[string]time.Time{"A": ago(180)}, nil, nil},
		{"current absent from handshakes", map[string]time.Time{"A": ago(5)}, ptr("B"), ptr("A")},
		{"tie without current picks smallest id", map[string]time.Time{"B": ago(5), "A": ago(5)}, nil, ptr("A")},
		{"tie keeps current", map[string]time.Time{"B": ago(5), "A": ago(5)}, ptr("B"), ptr("B")},
		{"future handshake alone", map[string]time.Time{"A": now.Add(time.Minute)}, nil, nil},
		{"future handshake loses to a real one", map[string]time.Time{"A": now.Add(time.Minute), "B": ago(20)}, nil, ptr("B")},
		{"current with a future stamp not kept", map[string]time.Time{"A": ago(5), "B": now.Add(time.Minute)}, ptr("B"), ptr("A")},
		{"small skew tolerated", map[string]time.Time{"A": now.Add(3 * time.Second)}, nil, ptr("A")},
		{"stale current and nothing fresh", map[string]time.Time{"B": ago(300)}, ptr("B"), nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := ChooseActive(tc.hs, tc.cur, now)
			if (got == nil) != (tc.want == nil) || (got != nil && *got != *tc.want) {
				t.Fatalf("got %v, want %v", deref(got), deref(tc.want))
			}
		})
	}
}

func deref(s *string) string {
	if s == nil {
		return "<nil>"
	}
	return *s
}

// handshakeHubs reports the handshake each hub has seen per router key.
type handshakeHubs struct {
	*recHubs
	mu   sync.Mutex
	seen map[string]map[string]time.Time // hub ID -> router public key -> handshake
	down map[string]bool
}

func (h *handshakeHubs) set(hubID, pub string, at time.Time) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.seen[hubID] == nil {
		h.seen[hubID] = map[string]time.Time{}
	}
	h.seen[hubID][pub] = at
}

func (h *handshakeHubs) Peers(_ context.Context, hub store.Hub) ([]HubPeerStatus, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.down[hub.ID] {
		return nil, errors.New("hub unreachable")
	}
	var out []HubPeerStatus
	for pub, at := range h.seen[hub.ID] {
		at := at
		out = append(out, HubPeerStatus{PublicKey: pub, LastHandshakeAt: &at})
	}
	return out, nil
}

type applyToggleDevice struct {
	wgdevice.Device
	fail    bool
	onApply func()
}

func (d *applyToggleDevice) Apply(cfg wgdevice.Config) error {
	if d.onApply != nil {
		d.onApply()
	}
	if d.fail {
		return errors.New("kernel refused")
	}
	return d.Device.Apply(cfg)
}

type activeEnv struct {
	f      fixture
	hubs   *handshakeHubs
	hub    []store.Hub
	router store.Router
}

// activeFixture builds two online hubs and one router listing listed of them.
func activeFixture(t *testing.T, listed ...int) activeEnv {
	t.Helper()
	f, rec, hubs := routerFixture(t, 2)
	hh := &handshakeHubs{recHubs: rec, seen: map[string]map[string]time.Time{}, down: map[string]bool{}}
	f.core.hubs = hh
	var ids []string
	for _, i := range listed {
		ids = append(ids, hubs[i].ID)
	}
	view, err := f.core.CreateRouter(context.Background(), "r1", ids, "")
	if err != nil {
		t.Fatal(err)
	}
	rt, err := f.st.GetRouter(view.ID)
	if err != nil {
		t.Fatal(err)
	}
	env := activeEnv{f: f, hubs: hh, hub: hubs, router: rt}
	env.hubsAlive()
	return env
}

// hubsAlive keeps RefreshHubStatuses from marking the hubs offline.
func (e activeEnv) hubsAlive() {
	var st []wgdevice.PeerStatus
	at := testNow.Add(-time.Second)
	for _, h := range e.hub {
		st = append(st, wgdevice.PeerStatus{PublicKey: h.PublicKey, LastHandshakeAt: &at})
	}
	e.f.dev.SetStatus(st)
}

func (e activeEnv) allowedOn(hubIdx int) []string {
	p, _ := peerByKey(e.f.dev.Last(), e.hub[hubIdx].PublicKey)
	return p.AllowedIPs
}

func (e activeEnv) tick(t *testing.T) {
	t.Helper()
	if err := e.f.core.tick(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestActiveLoopMovesRouterAndRecordsEvent(t *testing.T) {
	e := activeFixture(t, 0, 1)
	addr := e.router.Address.String() + "/32"
	e.hubs.set(e.hub[0].ID, e.router.PublicKey, testNow.Add(-10*time.Second))
	e.tick(t)
	if !slices.Contains(e.allowedOn(0), addr) || slices.Contains(e.allowedOn(1), addr) {
		t.Fatalf("router not routed via A: A=%v B=%v", e.allowedOn(0), e.allowedOn(1))
	}

	e.hubs.set(e.hub[0].ID, e.router.PublicKey, testNow.Add(-100*time.Second))
	e.hubs.set(e.hub[1].ID, e.router.PublicKey, testNow.Add(-5*time.Second))
	e.tick(t)
	if slices.Contains(e.allowedOn(0), addr) || !slices.Contains(e.allowedOn(1), addr) {
		t.Fatalf("router not moved to B: A=%v B=%v", e.allowedOn(0), e.allowedOn(1))
	}
	e.tick(t)

	evs, err := e.f.st.ListRouterEvents(e.router.ID, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(evs) != 2 {
		t.Fatalf("want 2 events, got %+v", evs)
	}
	if evs[0].FromHubID != e.hub[0].ID || evs[0].ToHubID != e.hub[1].ID || !evs[0].At.Equal(testNow) {
		t.Fatalf("A->B event wrong: %+v", evs[0])
	}
	if evs[1].FromHubID != "" || evs[1].ToHubID != e.hub[0].ID {
		t.Fatalf("first assignment event wrong: %+v", evs[1])
	}
}

func TestTickRecordsLossOfAllHubs(t *testing.T) {
	e := activeFixture(t, 0, 1)
	e.hubs.set(e.hub[0].ID, e.router.PublicKey, testNow.Add(-10*time.Second))
	e.tick(t)
	e.hubs.set(e.hub[0].ID, e.router.PublicKey, testNow.Add(-400*time.Second))
	e.tick(t)
	if slices.Contains(e.allowedOn(0), e.router.Address.String()+"/32") {
		t.Fatal("route kept after the handshake went stale")
	}
	evs, _ := e.f.st.ListRouterEvents(e.router.ID, 10)
	if len(evs) != 2 || evs[0].FromHubID != e.hub[0].ID || evs[0].ToHubID != "" {
		t.Fatalf("want a to-nil event, got %+v", evs)
	}
}

func TestTickIgnoresHubNotInRouterList(t *testing.T) {
	e := activeFixture(t, 0)
	e.hubs.set(e.hub[1].ID, e.router.PublicKey, testNow.Add(-5*time.Second))
	e.tick(t)
	if slices.Contains(e.allowedOn(1), e.router.Address.String()+"/32") {
		t.Fatal("router routed through a hub outside its list")
	}
	if evs, _ := e.f.st.ListRouterEvents(e.router.ID, 10); len(evs) != 0 {
		t.Fatalf("unexpected events %+v", evs)
	}
}

func TestTickToleratesFailingHub(t *testing.T) {
	e := activeFixture(t, 0, 1)
	e.hubs.set(e.hub[0].ID, e.router.PublicKey, testNow.Add(-5*time.Second))
	e.hubs.set(e.hub[1].ID, e.router.PublicKey, testNow.Add(-50*time.Second))
	e.hubs.down[e.hub[0].ID] = true
	e.tick(t)
	if !slices.Contains(e.allowedOn(1), e.router.Address.String()+"/32") {
		t.Fatalf("router should fall to the reachable hub: B=%v", e.allowedOn(1))
	}
}

func TestTickNoEventWhenApplyFails(t *testing.T) {
	e := activeFixture(t, 0, 1)
	dev := &applyToggleDevice{Device: e.f.dev}
	e.f.core.dev = dev
	e.hubs.set(e.hub[0].ID, e.router.PublicKey, testNow.Add(-5*time.Second))
	dev.fail = true
	if err := e.f.core.tick(context.Background()); err == nil {
		t.Fatal("tick should report the apply failure")
	}
	if evs, _ := e.f.st.ListRouterEvents(e.router.ID, 10); len(evs) != 0 {
		t.Fatalf("event recorded for a move the kernel never got: %+v", evs)
	}
	e.f.core.mu.Lock()
	n := len(e.f.core.active)
	e.f.core.mu.Unlock()
	if n != 0 {
		t.Fatal("active state kept after a failed apply")
	}

	dev.fail = false
	e.tick(t)
	if evs, _ := e.f.st.ListRouterEvents(e.router.ID, 10); len(evs) != 1 {
		t.Fatalf("next tick should retry and record once, got %+v", evs)
	}
}

func TestRevertLeavesConcurrentForgetAlone(t *testing.T) {
	e := activeFixture(t, 0, 1)
	e.hubs.set(e.hub[0].ID, e.router.PublicKey, testNow.Add(-5*time.Second))
	e.tick(t)
	dev := &applyToggleDevice{Device: e.f.dev, fail: true}
	e.f.core.dev = dev
	e.hubs.set(e.hub[1].ID, e.router.PublicKey, testNow.Add(time.Second))
	e.hubs.set(e.hub[0].ID, e.router.PublicKey, testNow.Add(-100*time.Second))
	dev.onApply = func() { e.f.core.forgetActive(e.router.ID, e.hub[1].ID) }
	if err := e.f.core.tick(context.Background()); err == nil {
		t.Fatal("tick should report the apply failure")
	}
	e.f.core.mu.Lock()
	_, ok := e.f.core.active[e.router.ID]
	e.f.core.mu.Unlock()
	if ok {
		t.Fatal("revert resurrected a router forgotten during the pass")
	}
}

func TestCommitPrunesGhostRouters(t *testing.T) {
	e := activeFixture(t, 0, 1)
	e.f.core.mu.Lock()
	e.f.core.active["gone"] = e.hub[0].ID
	e.f.core.handshakes["gone"] = testNow
	e.f.core.mu.Unlock()
	e.tick(t)
	e.f.core.mu.Lock()
	defer e.f.core.mu.Unlock()
	if _, ok := e.f.core.active["gone"]; ok {
		t.Fatal("ghost active entry kept")
	}
	if _, ok := e.f.core.handshakes["gone"]; ok {
		t.Fatal("ghost handshake kept")
	}
}

// A restart must not strip every router's /32 until the first tick: the hub
// carrying each router is seeded from the store, and the first tick that sees
// the same handshakes is not a move.
func TestRestartKeepsActiveHubWithoutEvent(t *testing.T) {
	e := activeFixture(t, 0, 1)
	addr := e.router.Address.String() + "/32"
	e.hubs.set(e.hub[0].ID, e.router.PublicKey, testNow.Add(-10*time.Second))
	e.tick(t)

	restarted := New(e.f.dev, e.f.st, e.f.box, e.hubs, e.f.core.cfg)
	if err := restarted.Init(); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(e.allowedOn(0), addr) {
		t.Fatalf("router /32 dropped by the restart: A=%v", e.allowedOn(0))
	}
	if v, err := restarted.GetRouter(e.router.ID); err != nil || v.ActiveHubID == nil || *v.ActiveHubID != e.hub[0].ID {
		t.Fatalf("seeded view = %+v %v", v, err)
	}
	if err := restarted.tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if evs, _ := e.f.st.ListRouterEvents(e.router.ID, 10); len(evs) != 1 {
		t.Fatalf("restart recorded a move: %+v", evs)
	}
}

// One failed Peers call must not unroute every router on a live hub: the
// last stamps it reported are reused and age out through freshWindow.
func TestTickReusesLastHandshakesWhenHubPeersFail(t *testing.T) {
	e := activeFixture(t, 0, 1)
	addr := e.router.Address.String() + "/32"
	e.hubs.set(e.hub[0].ID, e.router.PublicKey, testNow.Add(-10*time.Second))
	e.tick(t)
	e.hubs.mu.Lock()
	e.hubs.down[e.hub[0].ID] = true
	e.hubs.mu.Unlock()
	e.tick(t)
	if !slices.Contains(e.allowedOn(0), addr) {
		t.Fatalf("router unrouted by one failed Peers call: A=%v", e.allowedOn(0))
	}
	if evs, _ := e.f.st.ListRouterEvents(e.router.ID, 10); len(evs) != 1 {
		t.Fatalf("failed Peers call recorded a move: %+v", evs)
	}

	later := testNow.Add(freshWindow)
	e.f.core.cfg.Now = func() time.Time { return later }
	alive := later.Add(-time.Second)
	e.f.dev.SetStatus([]wgdevice.PeerStatus{
		{PublicKey: e.hub[0].PublicKey, LastHandshakeAt: &alive},
		{PublicKey: e.hub[1].PublicKey, LastHandshakeAt: &alive},
	})
	e.tick(t)
	if slices.Contains(e.allowedOn(0), addr) {
		t.Fatal("reused stamp never aged out")
	}
	evs, _ := e.f.st.ListRouterEvents(e.router.ID, 10)
	if len(evs) != 2 || evs[0].FromHubID != e.hub[0].ID || evs[0].ToHubID != "" {
		t.Fatalf("want a move to none once the stamp aged, got %+v", evs)
	}
}

// Traffic for a router no hub carries must not leave radpro by its default
// route; the unreachable route answers it locally instead.
func TestInitBlackholesRouterPool(t *testing.T) {
	f := newFixture(t)
	if got := f.dev.Unreachable(); !slices.Equal(got, []string{"10.100.0.0/14"}) {
		t.Fatalf("unreachable routes = %v", got)
	}
}
