package core

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/hadiahterlupakan/netmanager-vpn/internal/store"
)

const testToken = "tok-123"

func call(t *testing.T, h http.Handler, method, path, body string, auth bool) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if auth {
		req.Header.Set("Authorization", "Bearer "+testToken)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestCoreAPIRequiresToken(t *testing.T) {
	f := newFixture(t)
	h := f.core.Handler(testToken)
	for _, path := range []string{"/v1/hubs", "/v1/admin-peers", "/v1/routers/x"} {
		if rec := call(t, h, "GET", path, "", false); rec.Code != http.StatusUnauthorized {
			t.Fatalf("%s without token: %d", path, rec.Code)
		}
	}
	if rec := call(t, h, "GET", "/v1/hubs", "", true); rec.Code != http.StatusOK {
		t.Fatalf("with token: %d", rec.Code)
	}
}

func TestAPIRejectsBareToken(t *testing.T) {
	h := newFixture(t).core.Handler(testToken)
	req := httptest.NewRequest("GET", "/v1/hubs", nil)
	req.Header.Set("Authorization", testToken)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("bare token: %d", rec.Code)
	}
}

func TestCreateRouterValidationIs400(t *testing.T) {
	h := newFixture(t).core.Handler(testToken)
	rec := call(t, h, "POST", "/v1/routers", `{"label":"","hubIds":[]}`, true)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("code %d", rec.Code)
	}
	var body map[string]string
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if body["error"] != "validation" || body["message"] == "" {
		t.Fatalf("body %s", rec.Body)
	}
	if rec := call(t, h, "POST", "/v1/routers", `{not json`, true); rec.Code != http.StatusBadRequest {
		t.Fatalf("bad json: %d", rec.Code)
	}
}

func TestOversizedBodyIs400(t *testing.T) {
	h := newFixture(t).core.Handler(testToken)
	big := `{"label":"` + strings.Repeat("a", 20<<10) + `","hubIds":[]}`
	if rec := call(t, h, "POST", "/v1/routers", big, true); rec.Code != http.StatusBadRequest {
		t.Fatalf("code %d", rec.Code)
	}
}

func TestDeleteHubInUseIs409(t *testing.T) {
	f, _, hubs := routerFixture(t, 1)
	h := f.core.Handler(testToken)
	if _, err := f.core.CreateRouter(t.Context(), "r", []string{hubs[0].ID}); err != nil {
		t.Fatal(err)
	}
	rec := call(t, h, "DELETE", "/v1/hubs/"+hubs[0].ID, "", true)
	if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), `"in_use"`) {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	if rec := call(t, h, "DELETE", "/v1/hubs/nope", "", true); rec.Code != http.StatusNotFound {
		t.Fatalf("unknown hub: %d", rec.Code)
	}
}

func TestCreateHubReturnsViewAndCommand(t *testing.T) {
	h := newFixture(t).core.Handler(testToken)
	rec := call(t, h, "POST", "/v1/hubs", `{"name":"jkt","publicHost":"jkt.example.com","listenPort":0}`, true)
	if rec.Code != http.StatusOK {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	var out struct {
		Hub            HubView
		InstallCommand string
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.Hub.Status != store.HubStatusPendingInstall || out.Hub.RouterCount != 0 ||
		out.Hub.PublicHost != "jkt.example.com" || !strings.HasPrefix(out.InstallCommand, "curl ") {
		t.Fatalf("%+v", out)
	}
}

func TestRouterOSEndpointIsPlainText(t *testing.T) {
	f, _, hubs := routerFixture(t, 1)
	h := f.core.Handler(testToken)
	rv, err := f.core.CreateRouter(t.Context(), "kantor", []string{hubs[0].ID})
	if err != nil {
		t.Fatal(err)
	}
	rec := call(t, h, "GET", "/v1/routers/"+rv.ID+"/routeros?part=full", "", true)
	if rec.Code != http.StatusOK || !strings.HasPrefix(rec.Header().Get("Content-Type"), "text/plain") {
		t.Fatalf("%d %q", rec.Code, rec.Header().Get("Content-Type"))
	}
	if !strings.Contains(rec.Body.String(), "A.example.com") {
		t.Fatalf("script lacks hub host:\n%s", rec.Body)
	}
	if rec := call(t, h, "GET", "/v1/routers/"+rv.ID+"/routeros?part=bogus", "", true); rec.Code != http.StatusBadRequest {
		t.Fatalf("bad part: %d", rec.Code)
	}
}

func TestAdminConfigEndpointIsPlainText(t *testing.T) {
	h := newFixture(t).core.Handler(testToken)
	rec := call(t, h, "POST", "/v1/admin-peers", `{"label":"laptop"}`, true)
	var p AdminPeer
	if err := json.Unmarshal(rec.Body.Bytes(), &p); err != nil || p.ID == "" {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	rec = call(t, h, "GET", "/v1/admin-peers/"+p.ID+"/config", "", true)
	if !strings.HasPrefix(rec.Header().Get("Content-Type"), "text/plain") || !strings.Contains(rec.Body.String(), "PrivateKey = ") {
		t.Fatalf("%q %s", rec.Header().Get("Content-Type"), rec.Body)
	}
	if rec := call(t, h, "DELETE", "/v1/admin-peers/"+p.ID, "", true); rec.Code != http.StatusNoContent {
		t.Fatalf("delete: %d", rec.Code)
	}
}

func TestAPIJSONIsCamelCase(t *testing.T) {
	f, _, hubs := routerFixture(t, 1)
	h := f.core.Handler(testToken)
	rv, err := f.core.CreateRouter(t.Context(), "kantor", []string{hubs[0].ID})
	if err != nil {
		t.Fatal(err)
	}
	rec := call(t, h, "GET", "/v1/routers/"+rv.ID, "", true)
	var m map[string]json.RawMessage
	if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"id", "label", "ref", "address", "status", "hubs", "activeHubId", "lastHandshakeAt", "events"} {
		if _, ok := m[k]; !ok {
			t.Fatalf("missing key %q in %s", k, rec.Body)
		}
	}
	var hv []map[string]any
	_ = json.Unmarshal(m["hubs"], &hv)
	for _, k := range []string{"hubId", "name", "priority", "syncState"} {
		if _, ok := hv[0][k]; !ok {
			t.Fatalf("hub entry lacks %q: %v", k, hv[0])
		}
	}
}

func TestRouterLifecycleEndpoints(t *testing.T) {
	f, _, hubs := routerFixture(t, 2)
	h := f.core.Handler(testToken)
	body, _ := json.Marshal(map[string]any{"label": "r", "hubIds": []string{hubs[0].ID}})
	rec := call(t, h, "POST", "/v1/routers", string(body), true)
	var rv RouterView
	if err := json.Unmarshal(rec.Body.Bytes(), &rv); err != nil || rec.Code != http.StatusOK {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	body, _ = json.Marshal(map[string]any{"hubIds": []string{hubs[1].ID, hubs[0].ID}})
	rec = call(t, h, "PUT", "/v1/routers/"+rv.ID+"/hubs", string(body), true)
	_ = json.Unmarshal(rec.Body.Bytes(), &rv)
	if rec.Code != http.StatusOK || len(rv.Hubs) != 2 || rv.Hubs[0].HubID != hubs[1].ID {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	rec = call(t, h, "POST", "/v1/routers/"+rv.ID+"/claim", `{"ref":"nas-1"}`, true)
	_ = json.Unmarshal(rec.Body.Bytes(), &rv)
	if rec.Code != http.StatusOK || rv.Ref != "nas-1" {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	if rec := call(t, h, "DELETE", "/v1/routers/"+rv.ID, "", true); rec.Code != http.StatusNoContent {
		t.Fatalf("delete: %d", rec.Code)
	}
	if rec := call(t, h, "GET", "/v1/routers/"+rv.ID, "", true); rec.Code != http.StatusNotFound {
		t.Fatalf("after delete: %d", rec.Code)
	}
}

func TestHealthzFailsWhenReconcileStale(t *testing.T) {
	f := newFixture(t)
	h := f.core.Handler(testToken)
	if rec := call(t, h, "GET", "/healthz", "", false); rec.Code != http.StatusOK {
		t.Fatalf("fresh: %d", rec.Code)
	}
	f.core.cfg.Now = func() time.Time { return testNow.Add(61 * time.Second) }
	rec := call(t, h, "GET", "/healthz", "", false)
	if rec.Code != http.StatusServiceUnavailable || rec.Body.Len() != 0 {
		t.Fatalf("stale: %d %q", rec.Code, rec.Body)
	}
}

func TestRouterScriptOrdersServersByPriority(t *testing.T) {
	f, _, hubs := routerFixture(t, 2)
	rv, err := f.core.CreateRouter(t.Context(), "r", []string{hubs[1].ID, hubs[0].ID})
	if err != nil {
		t.Fatal(err)
	}
	for _, part := range []string{"full", "scheduler"} {
		s, err := f.core.RouterScript(rv.ID, part)
		if err != nil {
			t.Fatal(part, err)
		}
		if a, b := strings.Index(s, "B.example.com"), strings.Index(s, "A.example.com"); a < 0 || b < 0 || a > b {
			t.Fatalf("%s: B should precede A (%d, %d):\n%s", part, a, b, s)
		}
	}
}

func TestRouterScriptUnknownPart(t *testing.T) {
	f, _, hubs := routerFixture(t, 1)
	rv, _ := f.core.CreateRouter(t.Context(), "r", []string{hubs[0].ID})
	if _, err := f.core.RouterScript(rv.ID, "other"); !errors.Is(err, ErrValidation) {
		t.Fatalf("err %v", err)
	}
	if _, err := f.core.RouterScript("nope", "full"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("unknown router: %v", err)
	}
}

func TestRouterScriptWithoutHubsIsValidationError(t *testing.T) {
	f, _, hubs := routerFixture(t, 1)
	rv, _ := f.core.CreateRouter(t.Context(), "r", []string{hubs[0].ID})
	if err := f.st.SetRouterHubs(rv.ID, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := f.core.RouterScript(rv.ID, "full"); !errors.Is(err, ErrValidation) {
		t.Fatalf("err %v", err)
	}
}
