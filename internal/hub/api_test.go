package hub

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/hadiahterlupakan/netmanager-vpn/internal/ppp"
)

func apiEnv(t *testing.T) (*env, http.Handler) {
	e := newEnv(t)
	if err := e.svc.Join(e.bundle()); err != nil {
		t.Fatal(err)
	}
	return e, e.svc.Handler("tok")
}

func do(h http.Handler, method, path, body, token string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func peerPath() string {
	k, _ := wgtypes.GeneratePrivateKey()
	return "/v1/peers/" + url.PathEscape(k.PublicKey().String())
}

func TestAPIRejectsMissingToken(t *testing.T) {
	_, h := apiEnv(t)
	for _, token := range []string{"", "wrong"} {
		if rec := do(h, "GET", "/v1/peers", "", token); rec.Code != http.StatusUnauthorized {
			t.Fatalf("token %q: code %d", token, rec.Code)
		}
	}
	if rec := do(h, "GET", "/healthz", "", ""); rec.Code != http.StatusOK {
		t.Fatalf("healthz code %d", rec.Code)
	}
}

func TestAPIUpsertIsIdempotent(t *testing.T) {
	_, h := apiEnv(t)
	path := peerPath()
	for i := 0; i < 2; i++ {
		if rec := do(h, "PUT", path, `{"address":"10.100.0.10"}`, "tok"); rec.Code != http.StatusNoContent {
			t.Fatalf("put %d: code %d %s", i, rec.Code, rec.Body)
		}
	}
	var got []PeerStatus
	rec := do(h, "GET", "/v1/peers", "", "tok")
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil || len(got) != 1 {
		t.Fatalf("peers %s err %v", rec.Body, err)
	}
	if !strings.Contains(rec.Body.String(), `"lastHandshakeAt":null`) {
		t.Fatalf("shape: %s", rec.Body)
	}
	if rec := do(h, "DELETE", path, "", "tok"); rec.Code != http.StatusNoContent {
		t.Fatalf("delete code %d", rec.Code)
	}
	rec = do(h, "GET", "/v1/peers", "", "tok")
	if strings.TrimSpace(rec.Body.String()) != "[]" {
		t.Fatalf("after delete: %s", rec.Body)
	}
}

func TestAPIRejectsBadKeyAndAddress(t *testing.T) {
	_, h := apiEnv(t)
	cases := map[string][3]string{
		"bad key":      {"PUT", "/v1/peers/notakey", `{"address":"10.100.0.10"}`},
		"bad key del":  {"DELETE", "/v1/peers/notakey", ""},
		"out of pool":  {"PUT", peerPath(), `{"address":"192.168.1.5"}`},
		"unparsable":   {"PUT", peerPath(), `{"address":"x"}`},
		"missing body": {"PUT", peerPath(), ``},
	}
	for name, c := range cases {
		if rec := do(h, c[0], c[1], c[2], "tok"); rec.Code != http.StatusBadRequest {
			t.Errorf("%s: code %d", name, rec.Code)
		}
	}
}

func TestAPIAddressConflictAndEdges(t *testing.T) {
	_, h := apiEnv(t)
	if rec := do(h, "PUT", peerPath(), `{"address":"10.100.0.10"}`, "tok"); rec.Code != http.StatusNoContent {
		t.Fatalf("first put %d", rec.Code)
	}
	rec := do(h, "PUT", peerPath(), `{"address":"10.100.0.10"}`, "tok")
	if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), `"address_in_use"`) {
		t.Fatalf("conflict: %d %s", rec.Code, rec.Body)
	}
	for _, a := range []string{"10.100.0.0", "10.103.255.255"} {
		if rec := do(h, "PUT", peerPath(), `{"address":"`+a+`"}`, "tok"); rec.Code != http.StatusBadRequest {
			t.Errorf("%s: code %d", a, rec.Code)
		}
	}
	big := `{"address":"10.100.0.11","x":"` + strings.Repeat("a", 8192) + `"}`
	if rec := do(h, "PUT", peerPath(), big, "tok"); rec.Code != http.StatusBadRequest {
		t.Errorf("oversized body: %d", rec.Code)
	}
}

func TestAPIBareTokenIsRejected(t *testing.T) {
	_, h := apiEnv(t)
	req := httptest.NewRequest("GET", "/v1/peers", nil)
	req.Header.Set("Authorization", "tok")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("code %d", rec.Code)
	}
}

func TestAPISlashAndPlusKey(t *testing.T) {
	_, h := apiEnv(t)
	raw := make([]byte, 32)
	for i := range raw {
		raw[i] = 0xfb
	}
	key, _ := wgtypes.NewKey(raw)
	if !strings.Contains(key.String(), "/") || !strings.Contains(key.String(), "+") {
		t.Fatalf("fixture key %s lacks / or +", key)
	}
	path := "/v1/peers/" + url.PathEscape(key.String())
	if rec := do(h, "PUT", path, `{"address":"10.100.0.20"}`, "tok"); rec.Code != http.StatusNoContent {
		t.Fatalf("put %d", rec.Code)
	}
	if rec := do(h, "GET", "/v1/peers", "", "tok"); !strings.Contains(rec.Body.String(), "10.100.0.20") {
		t.Fatalf("not listed: %s", rec.Body)
	}
	if rec := do(h, "DELETE", path, "", "tok"); rec.Code != http.StatusNoContent {
		t.Fatalf("delete %d", rec.Code)
	}
	if rec := do(h, "GET", "/v1/peers", "", "tok"); strings.TrimSpace(rec.Body.String()) != "[]" {
		t.Fatalf("not deleted: %s", rec.Body)
	}
}

func TestPutPeerWithoutProtocolIsWireGuard(t *testing.T) {
	e, h := apiEnv(t)
	if rec := do(h, "PUT", peerPath(), `{"address":"10.100.0.10"}`, "tok"); rec.Code != http.StatusNoContent {
		t.Fatalf("code %d %s", rec.Code, rec.Body)
	}
	peers, err := e.st.ListPeers()
	if err != nil || len(peers) != 1 || peers[0].Protocol != "wireguard" || peers[0].PPPUser != "" {
		t.Fatalf("peers %+v err %v", peers, err)
	}
}

func TestPutPeerStoresSealedPPPPassword(t *testing.T) {
	e, h := apiEnv(t)
	body := `{"address":"10.100.0.10","protocol":"l2tp","pppUsername":"nmvpn-0a","pppPassword":"` + testPPPPass + `"}`
	if rec := do(h, "PUT", peerPath(), body, "tok"); rec.Code != http.StatusNoContent {
		t.Fatalf("code %d %s", rec.Code, rec.Body)
	}
	peers, err := e.st.ListPeers()
	if err != nil || len(peers) != 1 || peers[0].Protocol != "l2tp" || peers[0].PPPUser != "nmvpn-0a" {
		t.Fatalf("peers %+v err %v", peers, err)
	}
	if peers[0].PPPPassword == testPPPPass || peers[0].PPPPassword == "" {
		t.Fatal("password not sealed")
	}
	if rec := do(h, "GET", "/v1/peers", "", "tok"); strings.Contains(rec.Body.String(), testPPPPass) {
		t.Fatalf("listing leaks the password: %s", rec.Body)
	}
}

func TestPutPeerRejectsBadPPPFields(t *testing.T) {
	_, h := apiEnv(t)
	ok := testPPPPass
	for name, body := range map[string]string{
		"wireguard with user":     `{"address":"10.100.0.10","pppUsername":"nmvpn-0a"}`,
		"wireguard with password": `{"address":"10.100.0.10","protocol":"wireguard","pppPassword":"` + ok + `"}`,
		"unknown protocol":        `{"address":"10.100.0.10","protocol":"sstp"}`,
		"l2tp without user":       `{"address":"10.100.0.10","protocol":"l2tp","pppPassword":"` + ok + `"}`,
		"l2tp bad user":           `{"address":"10.100.0.10","protocol":"l2tp","pppUsername":"nmvpn-XY","pppPassword":"` + ok + `"}`,
		"l2tp user too long":      `{"address":"10.100.0.10","protocol":"l2tp","pppUsername":"nmvpn-` + strings.Repeat("a", 65) + `","pppPassword":"` + ok + `"}`,
		"l2tp short password":     `{"address":"10.100.0.10","protocol":"l2tp","pppUsername":"nmvpn-0a","pppPassword":"short"}`,
		"l2tp quote in password":  `{"address":"10.100.0.10","protocol":"l2tp","pppUsername":"nmvpn-0a","pppPassword":"` + ok + `\""}`,
		"l2tp password too long":  `{"address":"10.100.0.10","protocol":"l2tp","pppUsername":"nmvpn-0a","pppPassword":"` + strings.Repeat("a", 65) + `"}`,
	} {
		if rec := do(h, "PUT", peerPath(), body, "tok"); rec.Code != http.StatusBadRequest {
			t.Errorf("%s: code %d", name, rec.Code)
		}
	}
}

func protocolsOf(t *testing.T, h http.Handler) string {
	t.Helper()
	rec := do(h, "GET", "/v1/info", "", "tok")
	if rec.Code != http.StatusOK {
		t.Fatalf("info code %d", rec.Code)
	}
	var body struct {
		Protocols []string `json:"protocols"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	return strings.Join(body.Protocols, ",")
}

func TestInfoReportsL2TPOnlyWhenReady(t *testing.T) {
	cases := map[string]struct {
		ppp     bool // host has /dev/ppp and l2tp_ppp, so the daemons are wired
		psk     bool
		running bool
		want    string
	}{
		"no ppp on host":      {false, false, false, "wireguard"},
		"no psk":              {true, false, true, "wireguard"},
		"daemons not running": {true, true, false, "wireguard"},
		"everything in place": {true, true, true, "wireguard,l2tp"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			var p *pppEnv
			if c.ppp {
				p = &pppEnv{sessions: ppp.NewMemorySessions(), rt: &fakePPP{running: c.running}}
			}
			e := newEnvWith(t, p)
			if err := e.svc.Join(e.bundle()); err != nil {
				t.Fatal(err)
			}
			h := e.svc.Handler("tok")
			if c.psk {
				body := `{"psk":"` + testPSK + `","localId":"31.56.30.53"}`
				if rec := do(h, "PUT", "/v1/ipsec", body, "tok"); rec.Code != http.StatusNoContent {
					t.Fatalf("ipsec code %d", rec.Code)
				}
			}
			if got := protocolsOf(t, h); got != c.want {
				t.Fatalf("protocols = %s", got)
			}
		})
	}
}

func TestPutIPsecSamePSKNoReload(t *testing.T) {
	e, p := newPPPEnv(t)
	h := e.svc.Handler("tok")
	before := p.rt.applies
	body := `{"psk":"` + testPSK + `","localId":"hub1.example.net"}`
	if rec := do(h, "PUT", "/v1/ipsec", body, "tok"); rec.Code != http.StatusNoContent {
		t.Fatalf("code %d", rec.Code)
	}
	if p.rt.applies != before {
		t.Fatalf("same PSK and local id re-applied IPsec (%d -> %d)", before, p.rt.applies)
	}
	other := `{"psk":"` + strings.Repeat("z", 32) + `","localId":"hub1.example.net"}`
	if rec := do(h, "PUT", "/v1/ipsec", other, "tok"); rec.Code != http.StatusNoContent {
		t.Fatalf("code %d", rec.Code)
	}
	if p.rt.applies != before+1 || !strings.Contains(p.rt.ipsec, strings.Repeat("z", 32)) {
		t.Fatalf("new PSK not applied: %d applies", p.rt.applies)
	}
	moved := `{"psk":"` + strings.Repeat("z", 32) + `","localId":"hub2.example.net"}`
	if rec := do(h, "PUT", "/v1/ipsec", moved, "tok"); rec.Code != http.StatusNoContent {
		t.Fatalf("code %d", rec.Code)
	}
	if !strings.Contains(p.rt.ipsec, "id = hub2.example.net") {
		t.Fatalf("new local id not applied: %s", p.rt.ipsec)
	}
}

func TestPutIPsecRejectsBadBody(t *testing.T) {
	_, h := apiEnv(t)
	psk := testPSK
	for name, body := range map[string]string{
		"short psk":      `{"psk":"short","localId":"hub1.example.net"}`,
		"psk with quote": `{"psk":"` + psk + `\"","localId":"hub1.example.net"}`,
		"long psk":       `{"psk":"` + strings.Repeat("a", 129) + `","localId":"hub1.example.net"}`,
		"no local id":    `{"psk":"` + psk + `"}`,
		"bad local id":   `{"psk":"` + psk + `","localId":"hub one"}`,
		"ipv6 local id":  `{"psk":"` + psk + `","localId":"2001:db8::1"}`,
		"not json":       `psk`,
	} {
		if rec := do(h, "PUT", "/v1/ipsec", body, "tok"); rec.Code != http.StatusBadRequest {
			t.Errorf("%s: code %d", name, rec.Code)
		}
	}
}
