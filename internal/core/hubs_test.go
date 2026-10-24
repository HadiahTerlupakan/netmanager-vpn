package core

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/hadiahterlupakan/netmanager-vpn/internal/joinbundle"
	"github.com/hadiahterlupakan/netmanager-vpn/internal/secret"
	"github.com/hadiahterlupakan/netmanager-vpn/internal/store"
	"github.com/hadiahterlupakan/netmanager-vpn/internal/wgdevice"
)

var testNow = time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)

type fakeHubs struct{}

func (fakeHubs) UpsertPeer(context.Context, store.Hub, PeerSpec) error     { return nil }
func (fakeHubs) DeletePeer(context.Context, store.Hub, string) error       { return nil }
func (fakeHubs) Peers(context.Context, store.Hub) ([]HubPeerStatus, error) { return nil, nil }
func (fakeHubs) SetIPsecPSK(context.Context, store.Hub, string) error      { return nil }
func (fakeHubs) Info(context.Context, store.Hub) (HubInfo, error) {
	return HubInfo{Protocols: []string{"wireguard"}}, nil
}

type fixture struct {
	core *Core
	dev  *wgdevice.Memory
	st   *store.Store
	box  *secret.Box
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "core.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	box, err := secret.NewBox(base64.StdEncoding.EncodeToString(key))
	if err != nil {
		t.Fatal(err)
	}
	dev := wgdevice.NewMemory()
	c := New(dev, st, box, fakeHubs{}, Config{
		CoreEndpoint: "vpn.radpro.id:51822",
		InstallURL:   "https://example.test/install-hub.sh",
		HubImage:     "ghcr.io/example/netmanager-vpn:abc123def456-1760000000",
		Now:          func() time.Time { return testNow },
	})
	if err := c.Init(); err != nil {
		t.Fatal(err)
	}
	return fixture{core: c, dev: dev, st: st, box: box}
}

func peerByKey(cfg wgdevice.Config, pub string) (wgdevice.PeerConfig, bool) {
	for _, p := range cfg.Peers {
		if p.PublicKey == pub {
			return p, true
		}
	}
	return wgdevice.PeerConfig{}, false
}

func bundleOf(t *testing.T, cmd string) joinbundle.Bundle {
	t.Helper()
	prefix := "curl -fsSL https://example.test/install-hub.sh | $(command -v sudo) env NMVPN_IMAGE=ghcr.io/example/netmanager-vpn:abc123def456-1760000000 NMVPN_PORTS=\"51821/udp 500/udp 4500/udp\" sh -s -- "
	enc, ok := strings.CutPrefix(cmd, prefix)
	if !ok {
		t.Fatalf("unexpected install command %q", cmd)
	}
	b, err := joinbundle.Decode(enc)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestInitConfiguresWgCore(t *testing.T) {
	f := newFixture(t)
	cfg := f.dev.Last()
	if cfg.InterfaceName != "wg-core" || cfg.Address != "10.99.0.1/24" || cfg.ListenPort != 51822 || cfg.MTU != 1380 {
		t.Fatalf("unexpected wg-core config: %+v", cfg)
	}
	sealed, err := f.st.ServerKey("wg-core")
	if err != nil {
		t.Fatal(err)
	}
	if sealed == cfg.PrivateKey {
		t.Fatal("server key stored unsealed")
	}
	if err := f.core.Init(); err != nil {
		t.Fatal(err)
	}
	if f.dev.Last().PrivateKey != cfg.PrivateKey {
		t.Fatal("second Init regenerated the core key")
	}
}

func TestCreateHubAllocatesBackhaulAndAddsPeer(t *testing.T) {
	f := newFixture(t)
	hub, cmd, err := f.core.CreateHub("Jakarta", "hub1.example.com", 0)
	if err != nil {
		t.Fatal(err)
	}
	if hub.BackhaulAddr.String() != "10.99.0.2" || hub.ListenPort != 51821 || hub.Status != store.HubStatusPendingInstall {
		t.Fatalf("unexpected hub %+v", hub)
	}
	if !hub.JoinExpiresAt.Equal(testNow.Add(time.Hour)) {
		t.Fatalf("join expiry %v", hub.JoinExpiresAt)
	}
	p, ok := peerByKey(f.dev.Last(), hub.PublicKey)
	if !ok || len(p.AllowedIPs) != 1 || p.AllowedIPs[0] != "10.99.0.2/32" || p.Endpoint != "" || p.Keepalive != 0 {
		t.Fatalf("wg-core peer = %+v ok=%v", p, ok)
	}

	b := bundleOf(t, cmd)
	corePriv, _ := f.st.ServerKey("wg-core")
	plain, _ := f.box.Open(corePriv)
	k, _ := wgtypes.ParseKey(plain)
	if b.CorePublicKey != k.PublicKey().String() || b.CoreEndpoint != "vpn.radpro.id:51822" || b.BackhaulAddr != "10.99.0.2" {
		t.Fatalf("bundle %+v", b)
	}
	hubPriv, _ := wgtypes.ParseKey(b.PrivateKey)
	if hubPriv.PublicKey().String() != hub.PublicKey {
		t.Fatal("bundle private key does not match the stored public key")
	}
	tok, _ := f.box.Open(hub.APIToken)
	if tok != b.APIToken || tok == "" {
		t.Fatal("bundle token differs from sealed token")
	}

	second, _, err := f.core.CreateHub("Surabaya", "10.1.2.3", 51900)
	if err != nil || second.BackhaulAddr.String() != "10.99.0.3" {
		t.Fatalf("second hub: %+v %v", second, err)
	}
}

func TestCreateHubValidation(t *testing.T) {
	f := newFixture(t)
	for _, tc := range []struct {
		name, host string
		port       int
	}{
		{"", "h.example.com", 0},
		{"x", "", 0},
		{"x", "https://h.example.com", 0},
		{"x", "h.example.com:51821", 0},
		{"x", "bad host", 0},
		{"x", "999.1.1.1", 0},
		{"x", "1.2.3", 0},
		{"x", "h.example.com", 70000},
		{"x", "h.example.com", -1},
	} {
		if _, _, err := f.core.CreateHub(tc.name, tc.host, tc.port); !errors.Is(err, ErrValidation) {
			t.Errorf("%+v: err = %v, want ErrValidation", tc, err)
		}
	}
}

func TestHubStatusTransitions(t *testing.T) {
	now := testNow
	expiry := now.Add(time.Hour)
	ago := func(d time.Duration) *time.Time { v := now.Add(-d); return &v }
	for _, tc := range []struct {
		name      string
		stored    string
		expiry    time.Time
		handshake *time.Time
		want      string
	}{
		{"no handshake", store.HubStatusPendingInstall, expiry, nil, "pending_install"},
		{"30s", store.HubStatusPendingInstall, expiry, ago(30 * time.Second), "online"},
		{"10min", store.HubStatusOnline, expiry, ago(10 * time.Minute), "offline"},
		{"past expiry, never handshaked", store.HubStatusPendingInstall, now.Add(-time.Minute), nil, "expired"},
		{"stays expired", store.HubStatusExpired, now.Add(-time.Hour), nil, "expired"},
		{"handshaked once keeps offline past expiry", store.HubStatusOnline, now.Add(-time.Hour), nil, "offline"},
		{"first handshake after expiry is a leaked bundle", store.HubStatusPendingInstall, now.Add(-time.Hour), ago(5 * time.Second), "expired"},
		{"handshake before expiry, checked later", store.HubStatusPendingInstall, now.Add(-time.Second), ago(2 * time.Second), "online"},
		{"exactly 180s", store.HubStatusOnline, expiry, ago(180 * time.Second), "offline"},
		{"exactly at expiry", store.HubStatusPendingInstall, now, nil, "pending_install"},
		{"handshake exactly at expiry counts", store.HubStatusPendingInstall, now.Add(-5 * time.Second), ago(5 * time.Second), "online"},
	} {
		if got := hubStatus(tc.stored, tc.expiry, tc.handshake, now); got != tc.want {
			t.Errorf("%s: got %s want %s", tc.name, got, tc.want)
		}
	}
}

func TestRefreshHubStatusesPersistsAndDropsExpired(t *testing.T) {
	f := newFixture(t)
	live, _, _ := f.core.CreateHub("live", "a.example.com", 0)
	stale, _, _ := f.core.CreateHub("stale", "b.example.com", 0)
	hs := testNow.Add(-20 * time.Second)
	f.dev.SetStatus([]wgdevice.PeerStatus{{PublicKey: live.PublicKey, LastHandshakeAt: &hs}})

	f.core.cfg.Now = func() time.Time { return testNow.Add(2 * time.Hour) }
	if err := f.core.RefreshHubStatuses(); err != nil {
		t.Fatal(err)
	}
	got, _ := f.st.GetHub(live.ID)
	if got.Status != store.HubStatusOffline || got.LastSeenAt == nil || !got.LastSeenAt.Equal(hs) {
		t.Fatalf("live hub: %+v", got)
	}
	got, _ = f.st.GetHub(stale.ID)
	if got.Status != store.HubStatusExpired {
		t.Fatalf("stale hub status %s", got.Status)
	}
	if _, ok := peerByKey(f.dev.Last(), stale.PublicKey); ok {
		t.Fatal("expired hub kept its wg-core peer")
	}
	if _, ok := peerByKey(f.dev.Last(), live.PublicKey); !ok {
		t.Fatal("handshaked hub lost its wg-core peer")
	}
}

func TestReissueRotatesHubKeys(t *testing.T) {
	f := newFixture(t)
	hub, cmd, _ := f.core.CreateHub("h", "h.example.com", 0)
	old := bundleOf(t, cmd)
	_ = f.st.UpdateHubStatus(hub.ID, store.HubStatusExpired, nil)

	f.core.cfg.Now = func() time.Time { return testNow.Add(3 * time.Hour) }
	cmd2, err := f.core.ReissueJoin(hub.ID)
	if err != nil {
		t.Fatal(err)
	}
	nb := bundleOf(t, cmd2)
	if nb.PrivateKey == old.PrivateKey || nb.APIToken == old.APIToken {
		t.Fatal("keys not rotated")
	}
	got, _ := f.st.GetHub(hub.ID)
	if got.Status != store.HubStatusPendingInstall || !got.JoinExpiresAt.Equal(testNow.Add(4*time.Hour)) {
		t.Fatalf("hub after reissue: %+v", got)
	}
	if _, ok := peerByKey(f.dev.Last(), hub.PublicKey); ok {
		t.Fatal("old public key still on wg-core")
	}
	if _, ok := peerByKey(f.dev.Last(), got.PublicKey); !ok {
		t.Fatal("new public key missing from wg-core")
	}
}

func TestReissueRefusesLiveHub(t *testing.T) {
	f := newFixture(t)
	hub, _, _ := f.core.CreateHub("h", "h.example.com", 0)
	_ = f.st.UpdateHubStatus(hub.ID, store.HubStatusOnline, nil)
	if _, err := f.core.ReissueJoin(hub.ID); !errors.Is(err, ErrValidation) {
		t.Fatalf("err = %v", err)
	}
}

func TestDeleteHubInUse(t *testing.T) {
	f := newFixture(t)
	hub, _, _ := f.core.CreateHub("h", "h.example.com", 0)
	r, err := f.st.CreateRouter(store.Router{Label: "r", Address: netip.MustParseAddr("10.100.0.1"),
		PublicKey: "pk", PrivateKey: "sk", Status: store.RouterStatusPending})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.st.SetRouterHubs(r.ID, []string{hub.ID}); err != nil {
		t.Fatal(err)
	}
	if err := f.core.DeleteHub(hub.ID); !errors.Is(err, store.ErrInUse) {
		t.Fatalf("err = %v", err)
	}
	views, err := f.core.ListHubs()
	if err != nil || len(views) != 1 || views[0].RouterCount != 1 {
		t.Fatalf("views %+v err %v", views, err)
	}
	stored, err := f.st.GetHub(hub.ID)
	if err != nil {
		t.Fatal(err)
	}
	if views[0].PublicKey == "" || views[0].PublicKey != stored.PublicKey {
		t.Fatalf("list publicKey %q, want %q", views[0].PublicKey, stored.PublicKey)
	}

	if err := f.st.SetRouterHubs(r.ID, nil); err != nil {
		t.Fatal(err)
	}
	if err := f.core.DeleteHub(hub.ID); err != nil {
		t.Fatal(err)
	}
	if _, ok := peerByKey(f.dev.Last(), hub.PublicKey); ok {
		t.Fatal("deleted hub kept its wg-core peer")
	}
}

func TestApplyCoreIncludesActiveRoutersAndAdmins(t *testing.T) {
	f := newFixture(t)
	hub, _, _ := f.core.CreateHub("h", "h.example.com", 0)
	r, _ := f.st.CreateRouter(store.Router{Label: "r", Address: netip.MustParseAddr("10.100.0.7"),
		PublicKey: "pk", PrivateKey: "sk", Status: store.RouterStatusActive})
	f.core.mu.Lock()
	f.core.active[r.ID] = hub.ID
	f.core.mu.Unlock()
	_, _ = f.st.CreateAdminPeer(store.AdminPeer{Label: "a", Address: netip.MustParseAddr("10.99.128.1"),
		PublicKey: "adminpk", PrivateKey: "x"})
	if err := f.core.applyCore(); err != nil {
		t.Fatal(err)
	}
	p, _ := peerByKey(f.dev.Last(), hub.PublicKey)
	if len(p.AllowedIPs) != 2 || p.AllowedIPs[1] != "10.100.0.7/32" {
		t.Fatalf("hub allowed ips %v", p.AllowedIPs)
	}
	a, ok := peerByKey(f.dev.Last(), "adminpk")
	if !ok || len(a.AllowedIPs) != 1 || a.AllowedIPs[0] != "10.99.128.1/32" {
		t.Fatalf("admin peer %+v", a)
	}
}

type failingDevice struct {
	*wgdevice.Memory
	fail bool
}

func (d *failingDevice) Apply(cfg wgdevice.Config) error {
	if d.fail {
		return errors.New("apply failed")
	}
	return d.Memory.Apply(cfg)
}

func TestCreateHubRollsBackWhenApplyFails(t *testing.T) {
	f := newFixture(t)
	dev := &failingDevice{Memory: wgdevice.NewMemory()}
	f.core.dev = dev
	dev.fail = true
	if _, _, err := f.core.CreateHub("h", "h.example.com", 0); err == nil {
		t.Fatal("want error")
	}
	if views, _ := f.core.ListHubs(); len(views) != 0 {
		t.Fatalf("half-created hub left: %+v", views)
	}
	dev.fail = false
	hub, _, err := f.core.CreateHub("h", "h.example.com", 0)
	if err != nil || hub.BackhaulAddr.String() != "10.99.0.2" {
		t.Fatalf("address not free again: %+v %v", hub, err)
	}
}

func TestApplyCoreDropsPastExpiryPendingHub(t *testing.T) {
	f := newFixture(t)
	hub, _, _ := f.core.CreateHub("h", "h.example.com", 0)
	f.core.cfg.Now = func() time.Time { return testNow.Add(2 * time.Hour) }
	if err := f.core.applyCore(); err != nil {
		t.Fatal(err)
	}
	if _, ok := peerByKey(f.dev.Last(), hub.PublicKey); ok {
		t.Fatal("expired join still on wg-core before any refresh")
	}
}

func TestRefreshPromotesHubToOnline(t *testing.T) {
	f := newFixture(t)
	hub, _, _ := f.core.CreateHub("h", "h.example.com", 0)
	hs := testNow.Add(-10 * time.Second)
	f.dev.SetStatus([]wgdevice.PeerStatus{{PublicKey: hub.PublicKey, LastHandshakeAt: &hs}})
	if err := f.core.RefreshHubStatuses(); err != nil {
		t.Fatal(err)
	}
	got, _ := f.st.GetHub(hub.ID)
	if got.Status != store.HubStatusOnline {
		t.Fatalf("status %s", got.Status)
	}
	if _, ok := peerByKey(f.dev.Last(), hub.PublicKey); !ok {
		t.Fatal("online hub missing from wg-core")
	}
}

func TestCreateHubRejectsUnusableAddresses(t *testing.T) {
	f := newFixture(t)
	for _, host := range []string{"::1", "2001:db8::1", "fe80::1%eth0", "0.0.0.0", "127.0.0.1", "224.0.0.1"} {
		if _, _, err := f.core.CreateHub("x", host, 0); !errors.Is(err, ErrValidation) {
			t.Errorf("%s: err = %v", host, err)
		}
	}
}

func TestHubCommandCarriesPorts(t *testing.T) {
	f := newFixture(t)
	hub, install, err := f.core.CreateHub("Jakarta", "hub1.example.com", 51900)
	if err != nil {
		t.Fatal(err)
	}
	upgrade, err := f.core.UpgradeCommand(hub.ID)
	if err != nil {
		t.Fatal(err)
	}
	const ports = `NMVPN_PORTS="51900/udp 500/udp 4500/udp" sh -s -- `
	for name, cmd := range map[string]string{"install": install, "upgrade": upgrade} {
		if !strings.Contains(cmd, ports) {
			t.Errorf("%s command lacks the ports: %q", name, cmd)
		}
	}
}
