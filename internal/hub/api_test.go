package hub

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
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
