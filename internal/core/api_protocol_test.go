package core

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func TestCreateRouterProtocolField(t *testing.T) {
	f, _, hubs := l2tpFixture(t, 1)
	h := f.core.Handler(testToken)
	rec := call(t, h, "POST", "/v1/routers", `{"label":"r","hubIds":["`+hubs[0].ID+`"],"protocol":"l2tp"}`, true)
	var m map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil || rec.Code != http.StatusOK || m["protocol"] != "l2tp" {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	rec = call(t, h, "POST", "/v1/routers", `{"label":"r2","hubIds":["`+hubs[0].ID+`"]}`, true)
	if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil || m["protocol"] != "wireguard" {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	rec = call(t, h, "POST", "/v1/routers", `{"label":"r3","hubIds":["`+hubs[0].ID+`"],"protocol":"sstp"}`, true)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), `"validation"`) {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
}

func TestHubViewListsProtocols(t *testing.T) {
	f, _, _ := l2tpFixture(t, 1)
	rec := call(t, f.core.Handler(testToken), "GET", "/v1/hubs", "", true)
	if !strings.Contains(rec.Body.String(), `"protocols":["wireguard","l2tp"]`) {
		t.Fatalf("%s", rec.Body)
	}
	rec = call(t, f.core.Handler(testToken), "POST", "/v1/hubs", `{"name":"n","publicHost":"n.example.com"}`, true)
	if !strings.Contains(rec.Body.String(), `"protocols":["wireguard"]`) {
		t.Fatalf("%s", rec.Body)
	}
}

func TestProtocolEndpoints(t *testing.T) {
	f, _, hubs := l2tpFixture(t, 1)
	h := f.core.Handler(testToken)
	rv, _ := f.core.CreateRouter(t.Context(), "r", []string{hubs[0].ID}, "")
	base := "/v1/routers/" + rv.ID
	rec := call(t, h, "POST", base+"/protocol-script", `{"protocol":"l2tp"}`, true)
	if rec.Code != http.StatusOK || !strings.HasPrefix(rec.Header().Get("Content-Type"), "text/plain") ||
		!strings.Contains(rec.Body.String(), "nmvpn-"+rv.ID) {
		t.Fatalf("%d %q", rec.Code, rec.Header().Get("Content-Type"))
	}
	if rec := call(t, h, "POST", base+"/protocol-script", `{"protocol":"x"}`, true); rec.Code != http.StatusBadRequest {
		t.Fatalf("bad protocol script: %d", rec.Code)
	}
	rec = call(t, h, "POST", base+"/protocol", `{"protocol":"l2tp"}`, true)
	var v RouterView
	if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil || rec.Code != http.StatusOK || v.Protocol != "l2tp" {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	if rec := call(t, h, "POST", "/v1/routers/nope/protocol", `{"protocol":"l2tp"}`, true); rec.Code != http.StatusNotFound {
		t.Fatalf("unknown router: %d", rec.Code)
	}
}

func TestFirstServerEndpointOmitsUnusedFields(t *testing.T) {
	f, _, hubs := l2tpFixture(t, 1)
	h := f.core.Handler(testToken)
	wg, _ := f.core.CreateRouter(t.Context(), "w", []string{hubs[0].ID}, "")
	l2, _ := f.core.CreateRouter(t.Context(), "l", []string{hubs[0].ID}, "l2tp")
	cases := map[string][]string{
		wg.ID: {"protocol", "host", "port", "publicKey"},
		l2.ID: {"protocol", "host", "port", "ipsecSecret"},
	}
	for id, keys := range cases {
		rec := call(t, h, "GET", "/v1/routers/"+id+"/first-server", "", true)
		var m map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil || rec.Code != http.StatusOK || len(m) != len(keys) {
			t.Fatalf("%d %s", rec.Code, rec.Body)
		}
		for _, k := range keys {
			if _, ok := m[k]; !ok {
				t.Fatalf("missing %q in %s", k, rec.Body)
			}
		}
	}
}
