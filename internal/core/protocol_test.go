package core

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/hadiahterlupakan/netmanager-vpn/internal/ppp"
	"github.com/hadiahterlupakan/netmanager-vpn/internal/routeros"
	"github.com/hadiahterlupakan/netmanager-vpn/internal/store"
)

// l2tpFixture is routerFixture with every hub serving L2TP, in the store and
// in what Info reports to a sync pass.
func l2tpFixture(t *testing.T, hubCount int) (fixture, *recHubs, []store.Hub) {
	t.Helper()
	f, rec, hubs := routerFixture(t, hubCount)
	rec.protocols = map[string][]string{}
	for i, h := range hubs {
		rec.protocols[h.ID] = []string{"wireguard", "l2tp"}
		if err := f.st.UpdateHubProtocols(h.ID, []string{"wireguard", "l2tp"}); err != nil {
			t.Fatal(err)
		}
		hubs[i], _ = f.st.GetHub(h.ID)
	}
	return f, rec, hubs
}

func openOrFail(t *testing.T, f fixture, sealed string) string {
	t.Helper()
	plain, err := f.box.Open(sealed)
	if err != nil {
		t.Fatal(err)
	}
	return plain
}

func TestCreateRouterL2TPMakesPPPCredentials(t *testing.T) {
	f, rec, hubs := l2tpFixture(t, 1)
	v, err := f.core.CreateRouter(context.Background(), "x", []string{hubs[0].ID}, "l2tp")
	if err != nil {
		t.Fatal(err)
	}
	rt, _ := f.st.GetRouter(v.ID)
	pass := openOrFail(t, f, rt.PPPPassword)
	raw, err := base64.RawURLEncoding.DecodeString(pass)
	if rt.PPPUser != "nmvpn-"+v.ID || len(pass) != 32 || err != nil || len(raw) != 24 {
		t.Fatalf("user %q password %q (%v)", rt.PPPUser, pass, err)
	}
	if !ppp.UserRE.MatchString(rt.PPPUser) || !ppp.PasswordRE.MatchString(pass) {
		t.Fatalf("hub would refuse login %q / %q", rt.PPPUser, pass)
	}
	want := PeerSpec{PublicKey: rt.PublicKey, Address: rt.Address, Protocol: "l2tp", PPPUser: rt.PPPUser, PPPPassword: pass}
	if len(rec.upserts) != 1 || rec.upserts[0].spec != want {
		t.Fatalf("upserts %+v, want spec %+v", rec.upserts, want)
	}
	if v.Protocol != "l2tp" || v.Hubs[0].SyncState != store.SyncStateSynced {
		t.Fatalf("view %+v", v)
	}
}

func TestCreateRouterDefaultsToWireGuard(t *testing.T) {
	f, rec, hubs := l2tpFixture(t, 1)
	v, err := f.core.CreateRouter(context.Background(), "x", []string{hubs[0].ID}, "")
	if err != nil {
		t.Fatal(err)
	}
	rt, _ := f.st.GetRouter(v.ID)
	want := PeerSpec{PublicKey: rt.PublicKey, Address: rt.Address, Protocol: "wireguard"}
	if v.Protocol != "wireguard" || rt.PPPUser != "" || len(rec.upserts) != 1 || rec.upserts[0].spec != want {
		t.Fatalf("view %+v router %+v upserts %+v", v, rt, rec.upserts)
	}
	if _, err := f.core.CreateRouter(context.Background(), "y", []string{hubs[0].ID}, "pptp"); !errors.Is(err, ErrValidation) {
		t.Fatalf("unknown protocol: %v", err)
	}
}

func TestValidateHubIDsRejectsHubWithoutProtocol(t *testing.T) {
	f, rec, hubs := routerFixture(t, 1)
	if _, err := f.core.CreateRouter(context.Background(), "x", []string{hubs[0].ID}, "l2tp"); !errors.Is(err, ErrValidation) {
		t.Fatalf("WireGuard-only hub took an L2TP router: %v", err)
	}
	// Listing L2TP is not enough: without a PSK the core has no secret to
	// hand the router.
	if err := f.st.UpdateHubProtocols(hubs[0].ID, []string{"wireguard", "l2tp"}); err != nil {
		t.Fatal(err)
	}
	if err := f.st.UpdateHubPSK(hubs[0].ID, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := f.core.CreateRouter(context.Background(), "x", []string{hubs[0].ID}, "l2tp"); !errors.Is(err, ErrValidation) {
		t.Fatalf("hub without PSK took an L2TP router: %v", err)
	}
	if rs, _ := f.st.ListRouters(); len(rs) != 0 || len(rec.upserts) != 0 {
		t.Fatalf("routers %d upserts %d", len(rs), len(rec.upserts))
	}
}

func TestProtocolScriptDoesNotSwitch(t *testing.T) {
	f, rec, hubs := l2tpFixture(t, 1)
	v, _ := f.core.CreateRouter(context.Background(), "x", []string{hubs[0].ID}, "")
	before := len(rec.upserts)
	script, err := f.core.ProtocolScript(v.ID, "l2tp")
	if err != nil {
		t.Fatal(err)
	}
	rt, _ := f.st.GetRouter(v.ID)
	if !strings.Contains(script, rt.PPPUser) || !strings.Contains(script, openOrFail(t, f, rt.PPPPassword)) {
		t.Fatalf("script lacks the stored PPP login %q", rt.PPPUser)
	}
	got, _ := f.core.GetRouter(v.ID)
	if got.Protocol != "wireguard" || len(rec.upserts) != before {
		t.Fatalf("protocol %q, upserts %d -> %d", got.Protocol, before, len(rec.upserts))
	}
}

func TestProtocolScriptRejectsUnsupportedHub(t *testing.T) {
	f, _, hubs := routerFixture(t, 1)
	v, _ := f.core.CreateRouter(context.Background(), "x", []string{hubs[0].ID}, "")
	if _, err := f.core.ProtocolScript(v.ID, "l2tp"); !errors.Is(err, ErrValidation) {
		t.Fatalf("err = %v", err)
	}
	if rt, _ := f.st.GetRouter(v.ID); rt.PPPUser != "" {
		t.Fatalf("refused script still minted a login: %q", rt.PPPUser)
	}
}

func TestSetRouterProtocolPushesToEveryHub(t *testing.T) {
	f, rec, hubs := l2tpFixture(t, 2)
	ctx := context.Background()
	v, _ := f.core.CreateRouter(ctx, "x", []string{hubs[0].ID, hubs[1].ID}, "")
	before := len(rec.upserts)
	got, err := f.core.SetRouterProtocol(ctx, v.ID, "l2tp")
	if err != nil {
		t.Fatal(err)
	}
	pushed := rec.upserts[before:]
	if len(pushed) != 2 || pushed[0].hubID != hubs[0].ID || pushed[1].hubID != hubs[1].ID {
		t.Fatalf("pushed %+v", pushed)
	}
	for _, p := range pushed {
		if p.spec.Protocol != "l2tp" || p.spec.PPPUser != "nmvpn-"+v.ID || p.spec.PPPPassword == "" {
			t.Fatalf("spec %+v", p.spec)
		}
	}
	if got.Protocol != "l2tp" || got.Hubs[0].SyncState != store.SyncStateSynced || got.Hubs[1].SyncState != store.SyncStateSynced {
		t.Fatalf("view %+v", got)
	}
	if _, err := f.core.SetRouterProtocol(ctx, v.ID, "l2tp"); err != nil || len(rec.upserts) != before+2 {
		t.Fatalf("same protocol: err %v, upserts %d", err, len(rec.upserts))
	}
}

func TestSetRouterProtocolLeavesFailedHubPending(t *testing.T) {
	f, rec, hubs := l2tpFixture(t, 2)
	ctx := context.Background()
	v, _ := f.core.CreateRouter(ctx, "x", []string{hubs[0].ID, hubs[1].ID}, "")
	rec.failUpserts = 1
	got, err := f.core.SetRouterProtocol(ctx, v.ID, "l2tp")
	if err != nil {
		t.Fatal(err)
	}
	if got.Hubs[0].SyncState != store.SyncStatePending || got.Hubs[1].SyncState != store.SyncStateSynced {
		t.Fatalf("hubs %+v", got.Hubs)
	}
	before := len(rec.upserts)
	if err := f.core.SyncPending(ctx); err != nil {
		t.Fatal(err)
	}
	retried := rec.upserts[before:]
	if len(retried) != 1 || retried[0].hubID != hubs[0].ID || retried[0].spec.Protocol != "l2tp" {
		t.Fatalf("retried %+v", retried)
	}
	if got, _ = f.core.GetRouter(v.ID); got.Hubs[0].SyncState != store.SyncStateSynced {
		t.Fatalf("hubs %+v", got.Hubs)
	}
}

// A sync pass pushing from its snapshot while the router switches must not
// leave the hub on the old protocol marked synced.
func TestSwitchDuringSyncEndsOnNewProtocol(t *testing.T) {
	f, rec, hubs := l2tpFixture(t, 1)
	ctx := context.Background()
	rec.failUpserts = 1
	v, _ := f.core.CreateRouter(ctx, "x", []string{hubs[0].ID}, "")
	done := make(chan error, 1)
	rec.beforeUpsert = func() {
		go func() {
			_, err := f.core.SetRouterProtocol(ctx, v.ID, "l2tp")
			done <- err
		}()
		// Give the switch time to finish if nothing holds it back; a
		// serialised switch waits for this push instead.
		select {
		case err := <-done:
			done <- err
		case <-time.After(200 * time.Millisecond):
		}
	}
	if err := f.core.SyncPending(ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	last := rec.upserts[len(rec.upserts)-1]
	got, _ := f.core.GetRouter(v.ID)
	if last.spec.Protocol != "l2tp" || got.Protocol != "l2tp" || got.Hubs[0].SyncState != store.SyncStateSynced {
		t.Fatalf("hub last got %+v, router %+v", last.spec, got)
	}
}

func TestSetRouterProtocolSkipsOfflineHub(t *testing.T) {
	f, rec, hubs := l2tpFixture(t, 2)
	ctx := context.Background()
	v, _ := f.core.CreateRouter(ctx, "x", []string{hubs[0].ID, hubs[1].ID}, "")
	if err := f.st.UpdateHubStatus(hubs[1].ID, store.HubStatusOffline, nil); err != nil {
		t.Fatal(err)
	}
	before := len(rec.upserts)
	got, err := f.core.SetRouterProtocol(ctx, v.ID, "l2tp")
	if err != nil {
		t.Fatal(err)
	}
	pushed := rec.upserts[before:]
	if len(pushed) != 1 || pushed[0].hubID != hubs[0].ID || got.Hubs[1].SyncState != store.SyncStatePending {
		t.Fatalf("pushed %+v hubs %+v", pushed, got.Hubs)
	}
}

// ensurePPP works from a snapshot; it must neither write that snapshot's
// protocol back nor replace a login another caller stored meanwhile.
func TestEnsurePPPFromStaleSnapshot(t *testing.T) {
	f, _, hubs := l2tpFixture(t, 1)
	v, _ := f.core.CreateRouter(context.Background(), "x", []string{hubs[0].ID}, "")
	stale, _ := f.st.GetRouter(v.ID)
	if err := f.st.SetRouterProtocol(v.ID, "l2tp", "", ""); err != nil {
		t.Fatal(err)
	}
	first, err := f.core.ensurePPP(stale)
	if err != nil {
		t.Fatal(err)
	}
	second, err := f.core.ensurePPP(stale)
	if err != nil {
		t.Fatal(err)
	}
	stored, _ := f.st.GetRouter(v.ID)
	if stored.Protocol != "l2tp" {
		t.Fatalf("ensurePPP wrote protocol %q back", stored.Protocol)
	}
	if first.PPPPassword != stored.PPPPassword || second.PPPPassword != stored.PPPPassword {
		t.Fatal("racing ensurePPP calls minted different passwords")
	}
}

func TestSetRouterProtocolRejectsUnsupportedHub(t *testing.T) {
	f, rec, hubs := routerFixture(t, 1)
	v, _ := f.core.CreateRouter(context.Background(), "x", []string{hubs[0].ID}, "")
	before := len(rec.upserts)
	if _, err := f.core.SetRouterProtocol(context.Background(), v.ID, "l2tp"); !errors.Is(err, ErrValidation) {
		t.Fatalf("err = %v", err)
	}
	if got, _ := f.core.GetRouter(v.ID); got.Protocol != "wireguard" || len(rec.upserts) != before {
		t.Fatalf("protocol %q upserts %d", got.Protocol, len(rec.upserts))
	}
}

func TestPPPCredentialsKeptAcrossProtocolChanges(t *testing.T) {
	f, rec, hubs := l2tpFixture(t, 1)
	ctx := context.Background()
	v, _ := f.core.CreateRouter(ctx, "x", []string{hubs[0].ID}, "l2tp")
	first, _ := f.st.GetRouter(v.ID)
	firstPass := openOrFail(t, f, first.PPPPassword)
	if _, err := f.core.SetRouterProtocol(ctx, v.ID, "wireguard"); err != nil {
		t.Fatal(err)
	}
	if last := rec.upserts[len(rec.upserts)-1].spec; last.Protocol != "wireguard" || last.PPPUser != "" || last.PPPPassword != "" {
		t.Fatalf("WireGuard push carried a PPP login: %+v", last)
	}
	if _, err := f.core.SetRouterProtocol(ctx, v.ID, "l2tp"); err != nil {
		t.Fatal(err)
	}
	again, _ := f.st.GetRouter(v.ID)
	if again.PPPUser != first.PPPUser || openOrFail(t, f, again.PPPPassword) != firstPass {
		t.Fatal("PPP login changed across protocol switches")
	}
}

func TestCreateHubGeneratesPSK(t *testing.T) {
	f := newFixture(t)
	h, _, err := f.core.CreateHub("A", "a.example.com", 0)
	if err != nil {
		t.Fatal(err)
	}
	psk := openOrFail(t, f, h.IPsecPSK)
	if len(psk) != 43 || !ppp.PSKRE.MatchString(psk) {
		t.Fatalf("psk %q", psk)
	}
	views, _ := f.core.ListHubs()
	if len(views) != 1 || len(views[0].Protocols) != 1 || views[0].Protocols[0] != "wireguard" {
		t.Fatalf("views %+v", views)
	}
}

func TestSyncEnsuresPSKForOldHub(t *testing.T) {
	f, rec, hubs := routerFixture(t, 1)
	if err := f.st.UpdateHubPSK(hubs[0].ID, ""); err != nil {
		t.Fatal(err)
	}
	if err := f.core.SyncPending(context.Background()); err != nil {
		t.Fatal(err)
	}
	h, _ := f.st.GetHub(hubs[0].ID)
	if h.IPsecPSK == "" {
		t.Fatal("old hub still has no PSK")
	}
	psk := openOrFail(t, f, h.IPsecPSK)
	if len(rec.psks) != 1 || rec.psks[0] != (pskCall{h.ID, psk}) {
		t.Fatalf("psk pushes %+v", rec.psks)
	}
	if err := f.core.SyncPending(context.Background()); err != nil {
		t.Fatal(err)
	}
	if h2, _ := f.st.GetHub(h.ID); h2.IPsecPSK != h.IPsecPSK || rec.psks[1].psk != psk {
		t.Fatal("PSK rotated on the second pass")
	}
}

// A hub that did not take the PSK this pass may report L2TP on a key the core
// cannot vouch for; its stored protocols stay as they were.
func TestSyncKeepsProtocolsWhenPSKPushFails(t *testing.T) {
	f, rec, hubs := routerFixture(t, 1)
	rec.protocols = map[string][]string{hubs[0].ID: {"wireguard", "l2tp"}}
	rec.failPSK = true
	if err := f.core.SyncPending(context.Background()); err != nil {
		t.Fatal(err)
	}
	if h, _ := f.st.GetHub(hubs[0].ID); len(h.Protocols) != 1 || h.Protocols[0] != "wireguard" {
		t.Fatalf("protocols %v", h.Protocols)
	}
}

func TestSyncStoresHubProtocols(t *testing.T) {
	f, rec, hubs := routerFixture(t, 1)
	rec.protocols = map[string][]string{hubs[0].ID: {"wireguard", "l2tp"}}
	if err := f.core.SyncPending(context.Background()); err != nil {
		t.Fatal(err)
	}
	h, _ := f.st.GetHub(hubs[0].ID)
	if len(h.Protocols) != 2 || h.Protocols[1] != "l2tp" {
		t.Fatalf("protocols %v", h.Protocols)
	}
	views, _ := f.core.ListHubs()
	if len(views[0].Protocols) != 2 {
		t.Fatalf("view %+v", views[0])
	}
}

// A hub built before L2TP answers 404 on /v1/ipsec and /v1/info; the pass
// must not fail and must record the hub as WireGuard-only.
func TestSyncToleratesHubWithoutInfo(t *testing.T) {
	f, _, hubs := routerFixture(t, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" && r.URL.Path == "/v1/peers" {
			_, _ = w.Write([]byte("[]"))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	f.core.hubs = newHTTPHubClient(f.box, func(store.Hub) string { return "http://" + u.Host })
	if err := f.st.UpdateHubProtocols(hubs[0].ID, []string{"wireguard", "l2tp"}); err != nil {
		t.Fatal(err)
	}
	if err := f.core.SyncPending(context.Background()); err != nil {
		t.Fatalf("sync against an old hub: %v", err)
	}
	h, _ := f.st.GetHub(hubs[0].ID)
	if len(h.Protocols) != 1 || h.Protocols[0] != "wireguard" {
		t.Fatalf("protocols %v", h.Protocols)
	}
}

func TestFirstServerL2TPIncludesSecret(t *testing.T) {
	f, _, hubs := l2tpFixture(t, 2)
	v, err := f.core.CreateRouter(context.Background(), "x", []string{hubs[1].ID, hubs[0].ID}, "l2tp")
	if err != nil {
		t.Fatal(err)
	}
	got, err := f.core.FirstServer(v.ID)
	if err != nil {
		t.Fatal(err)
	}
	want := FirstServer{Protocol: "l2tp", Host: hubs[1].PublicHost, Port: 500, IPsecSecret: openOrFail(t, f, hubs[1].IPsecPSK)}
	if got != want {
		t.Fatalf("got %+v, want %+v", got, want)
	}
	wg, _ := f.core.CreateRouter(context.Background(), "y", []string{hubs[0].ID}, "")
	got, _ = f.core.FirstServer(wg.ID)
	want = FirstServer{Protocol: "wireguard", Host: hubs[0].PublicHost, Port: hubs[0].ListenPort, PublicKey: hubs[0].PublicKey}
	if got != want {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

func TestRouterScriptL2TPRendersPSKPerHub(t *testing.T) {
	f, _, hubs := l2tpFixture(t, 2)
	v, _ := f.core.CreateRouter(context.Background(), "x", []string{hubs[0].ID, hubs[1].ID}, routeros.ProtocolL2TP)
	script, err := f.core.RouterScript(v.ID, "full")
	if err != nil {
		t.Fatal(err)
	}
	for _, h := range hubs {
		if !strings.Contains(script, openOrFail(t, f, h.IPsecPSK)) {
			t.Fatalf("script lacks hub %s's PSK", h.Name)
		}
	}
	if !strings.Contains(script, "nmvpn-"+v.ID) {
		t.Fatal("script lacks the PPP user")
	}
}

// A push stuck on one router's hub must not hold up another router: the
// caller of CreateRouter gives up after a few seconds and would retry into a
// duplicate.
func TestStuckPushDoesNotBlockOtherRouter(t *testing.T) {
	f, rec, hubs := routerFixture(t, 2)
	ctx := context.Background()
	rec.failUpserts = 1
	a, _ := f.core.CreateRouter(ctx, "a", []string{hubs[0].ID}, "")
	rtA, _ := f.st.GetRouter(a.ID)
	entered, release := make(chan struct{}), make(chan struct{})
	rec.beforeUpsert = func() {
		close(entered)
		<-release
	}
	doneA := make(chan struct{})
	go func() {
		f.core.pushPeer(ctx, rtA, hubs[0])
		close(doneA)
	}()
	<-entered
	doneB := make(chan error, 1)
	go func() {
		_, err := f.core.CreateRouter(ctx, "b", []string{hubs[1].ID}, "")
		doneB <- err
	}()
	var errB error
	select {
	case errB = <-doneB:
	case <-time.After(2 * time.Second):
		t.Error("router B waited for router A's stuck push")
		close(release)
		errB = <-doneB
	}
	if errB != nil {
		t.Error(errB)
	}
	select {
	case <-release:
	default:
		close(release)
	}
	<-doneA
}
