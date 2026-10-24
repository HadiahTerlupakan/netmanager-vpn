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

	"github.com/hadiahterlupakan/netmanager-vpn/internal/ppp"
	"github.com/hadiahterlupakan/netmanager-vpn/internal/routeros"
	"github.com/hadiahterlupakan/netmanager-vpn/internal/store"
)

// l2tpFixture is routerFixture with every hub reporting L2TP.
func l2tpFixture(t *testing.T, hubCount int) (fixture, *recHubs, []store.Hub) {
	t.Helper()
	f, rec, hubs := routerFixture(t, hubCount)
	for i, h := range hubs {
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
