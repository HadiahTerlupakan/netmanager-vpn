package hub

import (
	"errors"
	"net/netip"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hadiahterlupakan/netmanager-vpn/internal/joinbundle"
	"github.com/hadiahterlupakan/netmanager-vpn/internal/ppp"
	"github.com/hadiahterlupakan/netmanager-vpn/internal/secret"
	"github.com/hadiahterlupakan/netmanager-vpn/internal/store"
	"github.com/hadiahterlupakan/netmanager-vpn/internal/wgdevice"
)

// recorder keeps the last config per interface, which wgdevice.Memory cannot:
// it holds only the most recent Apply regardless of interface.
type recorder struct {
	*wgdevice.Memory
	mu      sync.Mutex
	applied map[string]wgdevice.Config
	calls   int
}

func newRecorder() *recorder {
	return &recorder{Memory: wgdevice.NewMemory(), applied: map[string]wgdevice.Config{}}
}

func (r *recorder) Apply(c wgdevice.Config) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls++
	r.applied[c.InterfaceName] = c
	return r.Memory.Apply(c)
}

type fakeFW struct{ rules string }

func (f *fakeFW) Apply(s string) error { f.rules = s; return nil }

// fakeIPTables has a DOCKER-USER chain, as every hub with Docker does.
type fakeIPTables struct{ calls [][]string }

func (f *fakeIPTables) Run(args ...string) (bool, error) {
	f.calls = append(f.calls, args)
	return args[0] != "-C", nil
}

type env struct {
	svc     *Service
	st      *store.Store
	dev     *recorder
	fw      *fakeFW
	ipt     *fakeIPTables
	sysctls map[string]string
	now     time.Time
}

func newEnv(t *testing.T) *env {
	t.Helper()
	return newEnvWith(t, nil)
}

// newEnvWith lets a test add PPP to the options; nil keeps the hub
// WireGuard-only.
func newEnvWith(t *testing.T, ppp *pppEnv) *env {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "hub.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	box, err := secret.NewBox("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
	if err != nil {
		t.Fatal(err)
	}
	e := &env{st: st, dev: newRecorder(), fw: &fakeFW{}, ipt: &fakeIPTables{}, sysctls: map[string]string{},
		now: time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)}
	opts := Options{
		Now:      func() time.Time { return e.now },
		Sysctl:   func(k, v string) error { e.sysctls[k] = v; return nil },
		IPTables: e.ipt,
	}
	if ppp != nil {
		opts.Sessions, opts.PPP = ppp.sessions, ppp.rt
	}
	e.svc = New(e.dev, st, e.fw, box, opts)
	return e
}

func (e *env) bundle() joinbundle.Bundle {
	return joinbundle.Bundle{
		CoreEndpoint: "core.example:51820", CorePublicKey: "corepub", BackhaulAddr: "10.99.0.2",
		PrivateKey: "hubpriv", APIToken: "tok", ExpiresAt: e.now.Add(time.Hour),
	}
}

func wgPeer(pub, addr string) PeerSpec {
	return PeerSpec{PublicKey: pub, Address: netip.MustParseAddr(addr)}
}

func TestReconcileBuildsBothInterfaces(t *testing.T) {
	e := newEnv(t)
	if err := e.svc.Join(e.bundle()); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.UpsertPeer(wgPeer("routerpub", "10.100.0.10")); err != nil {
		t.Fatal(err)
	}
	nm := e.dev.applied["wg-nm"]
	if len(nm.Peers) != 1 || nm.Peers[0].PublicKey != "routerpub" ||
		nm.Peers[0].AllowedIPs[0] != "10.100.0.10/32" || nm.ListenPort != 51821 || nm.PrivateKey != "hubpriv" {
		t.Fatalf("wg-nm = %+v", nm)
	}
	up := e.dev.applied["wg-up"]
	if len(up.Peers) != 1 || up.Peers[0].Endpoint != "core.example:51820" ||
		up.Peers[0].Keepalive != 25*time.Second || up.Address != "10.99.0.2/24" ||
		len(up.Peers[0].AllowedIPs) != 2 || up.Peers[0].PublicKey != "corepub" {
		t.Fatalf("wg-up = %+v", up)
	}
	if e.fw.rules == "" || e.sysctls["net.ipv4.ip_forward"] != "1" {
		t.Fatalf("firewall %q sysctl %v", e.fw.rules, e.sysctls)
	}
	var inserted []string
	for _, c := range e.ipt.calls {
		if c[0] == "-I" {
			inserted = append(inserted, strings.Join(c, " "))
		}
	}
	if len(inserted) < 2 || inserted[0] != "-I DOCKER-USER -i wg-nm -o wg-up -j ACCEPT" ||
		inserted[1] != "-I DOCKER-USER -i wg-up -o wg-nm -j ACCEPT" {
		t.Fatalf("DOCKER-USER accepts not requested: %v", inserted)
	}
}

func TestReconcileWithEmptyStoreDoesNotWipeBeforeLoad(t *testing.T) {
	e := newEnv(t)
	e.st.Close()
	if err := e.svc.Reconcile(); err == nil {
		t.Fatal("expected load error")
	}
	if e.dev.calls != 0 {
		t.Fatalf("Apply called %d times after a failed load", e.dev.calls)
	}
}

func TestJoinRejectsExpiredBundle(t *testing.T) {
	e := newEnv(t)
	b := e.bundle()
	b.ExpiresAt = e.now.Add(-time.Second)
	if err := e.svc.Join(b); err == nil {
		t.Fatal("expected expiry error")
	}
	if _, err := e.st.LoadHubConfig(); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("config saved despite expiry: %v", err)
	}
}

func TestPeerStatusesJoinsStoredAddress(t *testing.T) {
	e := newEnv(t)
	if err := e.svc.Join(e.bundle()); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.UpsertPeer(wgPeer("routerpub", "10.100.0.10")); err != nil {
		t.Fatal(err)
	}
	hs := e.now.Add(-time.Minute)
	e.dev.SetStatus([]wgdevice.PeerStatus{
		{PublicKey: "routerpub", LastHandshakeAt: &hs, RxBytes: 5, TxBytes: 7},
		{PublicKey: "stray", RxBytes: 1},
	})
	got, err := e.svc.PeerStatuses()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Address != "10.100.0.10" || got[0].RxBytes != 5 || got[0].LastHandshakeAt == nil {
		t.Fatalf("statuses = %+v", got)
	}
}

func TestUpsertPeerRejectsAddressHeldByOtherKey(t *testing.T) {
	e := newEnv(t)
	if err := e.svc.Join(e.bundle()); err != nil {
		t.Fatal(err)
	}
	a := netip.MustParseAddr("10.100.0.10")
	if err := e.svc.UpsertPeer(PeerSpec{PublicKey: "keyA", Address: a}); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.UpsertPeer(PeerSpec{PublicKey: "keyA", Address: a}); err != nil {
		t.Fatalf("same key and address must stay idempotent: %v", err)
	}
	if err := e.svc.UpsertPeer(PeerSpec{PublicKey: "keyB", Address: a}); !errors.Is(err, ErrAddressInUse) {
		t.Fatalf("err = %v", err)
	}
	if err := e.svc.UpsertPeer(wgPeer("keyA", "10.100.0.11")); err != nil {
		t.Fatalf("same key, new address: %v", err)
	}
	if err := e.svc.UpsertPeer(PeerSpec{PublicKey: "keyB", Address: a}); err != nil {
		t.Fatalf("freed address: %v", err)
	}
}

// fakePPP records what the hub hands the PPP daemons.
type fakePPP struct {
	mu                     sync.Mutex
	applies                int
	secrets, ipsec, daemon string
	running                bool
}

func (f *fakePPP) Apply(secrets, ipsec, daemon string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.applies++
	f.secrets, f.ipsec, f.daemon = secrets, ipsec, daemon
	return nil
}

func (f *fakePPP) Running() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.running
}

func (f *fakePPP) SecretsPath() string { return "/run/test/chap-secrets" }

type pppEnv struct {
	sessions *ppp.MemorySessions
	rt       *fakePPP
}

const (
	testPSK     = "pskpskpskpskpskpskpskpskpskpskpsk"
	testPPPPass = "passpasspasspasspasspass"
)

// newPPPEnv is a joined hub that serves L2TP: it has the daemons and a PSK.
func newPPPEnv(t *testing.T) (*env, *pppEnv) {
	t.Helper()
	p := &pppEnv{sessions: ppp.NewMemorySessions(), rt: &fakePPP{running: true}}
	e := newEnvWith(t, p)
	if err := e.svc.Join(e.bundle()); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.SetIPsec(testPSK, "hub1.example.net"); err != nil {
		t.Fatal(err)
	}
	return e, p
}

func l2tpPeer(pub, addr, user string) PeerSpec {
	return PeerSpec{PublicKey: pub, Address: netip.MustParseAddr(addr), Protocol: "l2tp", PPPUser: user, PPPPassword: testPPPPass}
}

func nmAllowed(e *env) []string {
	var out []string
	for _, p := range e.dev.applied["wg-nm"].Peers {
		out = append(out, p.AllowedIPs...)
	}
	return out
}

func TestNMConfigSkipsL2TPPeers(t *testing.T) {
	e, p := newPPPEnv(t)
	if err := e.svc.UpsertPeer(wgPeer("wgkey", "10.100.0.10")); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.UpsertPeer(l2tpPeer("l2tpkey", "10.100.0.11", "nmvpn-0b")); err != nil {
		t.Fatal(err)
	}
	if got := nmAllowed(e); len(got) != 1 || got[0] != "10.100.0.10/32" {
		t.Fatalf("wg-nm allowed IPs = %v", got)
	}
	want := `"nmvpn-0b" * "` + testPPPPass + `" 10.100.0.11` + "\n"
	if p.rt.secrets != want {
		t.Fatalf("chap-secrets = %q", p.rt.secrets)
	}
	if !strings.Contains(p.rt.ipsec, "id = hub1.example.net") || !strings.Contains(p.rt.ipsec, testPSK) {
		t.Fatalf("ipsec = %s", p.rt.ipsec)
	}
	if !strings.Contains(p.rt.daemon, "gw-ip-address=10.99.0.2\nchap-secrets=/run/test/chap-secrets\n") {
		t.Fatalf("daemon = %s", p.rt.daemon)
	}
}

func TestReconcileLeavesPPPAloneWithoutPSK(t *testing.T) {
	p := &pppEnv{sessions: ppp.NewMemorySessions(), rt: &fakePPP{}}
	e := newEnvWith(t, p)
	if err := e.svc.Join(e.bundle()); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.UpsertPeer(l2tpPeer("l2tpkey", "10.100.0.11", "nmvpn-0b")); err != nil {
		t.Fatal(err)
	}
	if p.rt.applies != 0 {
		t.Fatalf("PPP daemons started without a PSK (%d applies)", p.rt.applies)
	}
}

func TestUpsertPeerProtocolChangeTerminatesSession(t *testing.T) {
	e, p := newPPPEnv(t)
	addr := netip.MustParseAddr("10.100.0.11")
	if err := e.svc.UpsertPeer(l2tpPeer("key", addr.String(), "nmvpn-0b")); err != nil {
		t.Fatal(err)
	}
	p.sessions.SetLive(addr)
	if err := e.svc.UpsertPeer(wgPeer("key", addr.String())); err != nil {
		t.Fatal(err)
	}
	if got := p.sessions.Terminated(); len(got) != 1 || got[0] != addr {
		t.Fatalf("terminated = %v", got)
	}
	if got := nmAllowed(e); len(got) != 1 || got[0] != "10.100.0.11/32" {
		t.Fatalf("wg-nm allowed IPs = %v", got)
	}
	if strings.Contains(p.rt.secrets, "nmvpn-0b") {
		t.Fatalf("chap-secrets still holds the user: %q", p.rt.secrets)
	}
}

func TestUpsertPeerKeepsOwnSession(t *testing.T) {
	e, p := newPPPEnv(t)
	addr := netip.MustParseAddr("10.100.0.11")
	p.sessions.SetLive(addr)
	for i := 0; i < 2; i++ {
		if err := e.svc.UpsertPeer(l2tpPeer("key", addr.String(), "nmvpn-0b")); err != nil {
			t.Fatal(err)
		}
	}
	if got := p.sessions.Terminated(); len(got) != 0 {
		t.Fatalf("terminated the peer's own session: %v", got)
	}
}

func TestDeletePeerTerminatesSession(t *testing.T) {
	e, p := newPPPEnv(t)
	addr := netip.MustParseAddr("10.100.0.11")
	if err := e.svc.UpsertPeer(l2tpPeer("key", addr.String(), "nmvpn-0b")); err != nil {
		t.Fatal(err)
	}
	p.sessions.SetLive(addr)
	if err := e.svc.DeletePeer("key"); err != nil {
		t.Fatal(err)
	}
	if got := p.sessions.Terminated(); len(got) != 1 || got[0] != addr {
		t.Fatalf("terminated = %v", got)
	}
	if p.rt.secrets != "" {
		t.Fatalf("chap-secrets = %q", p.rt.secrets)
	}
}

func TestPeerStatusesStampsLivePPPSession(t *testing.T) {
	e, p := newPPPEnv(t)
	for _, s := range []PeerSpec{
		l2tpPeer("up", "10.100.0.11", "nmvpn-0b"),
		l2tpPeer("down", "10.100.0.12", "nmvpn-0c"),
		wgPeer("wg", "10.100.0.13"),
	} {
		if err := e.svc.UpsertPeer(s); err != nil {
			t.Fatal(err)
		}
	}
	p.sessions.SetLive(netip.MustParseAddr("10.100.0.11"))
	hs := e.now.Add(-time.Minute)
	e.dev.SetStatus([]wgdevice.PeerStatus{{PublicKey: "wg", LastHandshakeAt: &hs, RxBytes: 3}})
	got, err := e.svc.PeerStatuses()
	if err != nil {
		t.Fatal(err)
	}
	byKey := map[string]PeerStatus{}
	for _, s := range got {
		byKey[s.PublicKey] = s
	}
	if up := byKey["up"].LastHandshakeAt; up == nil || !up.Equal(e.now) {
		t.Fatalf("live session stamp = %v", up)
	}
	if down := byKey["down"].LastHandshakeAt; down != nil {
		t.Fatalf("no session but stamp = %v", down)
	}
	if wg := byKey["wg"]; wg.LastHandshakeAt == nil || !wg.LastHandshakeAt.Equal(hs) || wg.RxBytes != 3 {
		t.Fatalf("wireguard peer = %+v", wg)
	}
}

func TestJoinKeepsStoredIPsec(t *testing.T) {
	e, _ := newPPPEnv(t)
	if err := e.svc.Join(e.bundle()); err != nil {
		t.Fatal(err)
	}
	cfg, err := e.st.LoadHubConfig()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.IPsecPSK == "" || cfg.IPsecLocalID != "hub1.example.net" {
		t.Fatalf("rejoin dropped IPsec: psk set %v, local id %q", cfg.IPsecPSK != "", cfg.IPsecLocalID)
	}
}
