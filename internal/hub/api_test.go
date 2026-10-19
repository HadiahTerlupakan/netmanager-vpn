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
