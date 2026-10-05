package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/xjeey8iust/sen-sbom-inventory/internal/store"
)

func openRouterStore(t *testing.T) (*store.Store, http.Handler) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "service.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	return st, NewRouter(st)
}

func doRequest(t *testing.T, handler http.Handler, method, target string, body string) *httptest.ResponseRecorder {
	t.Helper()
	var reader *bytes.Reader
	if body != "" {
		reader = bytes.NewReader([]byte(body))
	} else {
		reader = bytes.NewReader(nil)
	}
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(method, target, reader)
	request.Header.Set("Content-Type", "application/json")
	handler.ServeHTTP(recorder, request)
	return recorder
}

func decodeBody(t *testing.T, recorder *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var body map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode %q: %v", recorder.Body.String(), err)
	}
	return body
}

func TestPostSBOMsCreatesNormalizedManifest(t *testing.T) {
	_, handler := openRouterStore(t)

	// Whitespace around strings is trimmed; input order differs from output.
	payload := `{
		"artifact": "  artifact-x  ",
		"version": " 1.0 ",
		"components": [
			{"coordinate": "pkg-b", "license": " MIT ", "dependencies": ["pkg-a", "pkg-c"]},
			{"coordinate": "pkg-a", "license": " Apache-2.0", "dependencies": []},
			{"coordinate": "pkg-c", "license": "ISC", "dependencies": ["pkg-a"]}
		]
	}`
	recorder := doRequest(t, handler, http.MethodPost, "/sboms", payload)
	if recorder.Code != http.StatusCreated {
		t.Fatalf("status = %d, want %d; body %s", recorder.Code, http.StatusCreated, recorder.Body.String())
	}

	body := decodeBody(t, recorder)
	id, ok := body["id"].(float64)
	if !ok || id != float64(int64(id)) || int64(id) < 1 {
		t.Fatalf("id = %v, want positive integer", body["id"])
	}
	if body["artifact"] != "artifact-x" || body["version"] != "1.0" {
		t.Fatalf("header = %v %v", body["artifact"], body["version"])
	}

	components, ok := body["components"].([]any)
	if !ok || len(components) != 3 {
		t.Fatalf("components = %v", body["components"])
	}
	gotCoordinates := []string{}
	for _, item := range components {
		comp := item.(map[string]any)
		gotCoordinates = append(gotCoordinates, comp["coordinate"].(string))
	}
	wantCoordinates := []string{"pkg-a", "pkg-b", "pkg-c"}
	for i := range wantCoordinates {
		if gotCoordinates[i] != wantCoordinates[i] {
			t.Fatalf("component order = %v, want %v", gotCoordinates, wantCoordinates)
		}
	}
	first := components[0].(map[string]any)
	deps := first["dependencies"].([]any)
	if len(deps) != 0 {
		t.Fatalf("empty dependencies serialized as %v, want []", deps)
	}
	second := components[1].(map[string]any)
	deps = second["dependencies"].([]any)
	if len(deps) != 2 || deps[0] != "pkg-a" || deps[1] != "pkg-c" {
		t.Fatalf("pkg-b dependencies = %v, want sorted [pkg-a pkg-c]", deps)
	}
}

func TestPostSBOMsAcceptsEmptyComponentsAndCycles(t *testing.T) {
	_, handler := openRouterStore(t)

	recorder := doRequest(t, handler, http.MethodPost, "/sboms",
		`{"artifact":"a","version":"1","components":[]}`)
	if recorder.Code != http.StatusCreated {
		t.Fatalf("empty components: status = %d body %s", recorder.Code, recorder.Body.String())
	}
	body := decodeBody(t, recorder)
	if components, ok := body["components"].([]any); !ok || len(components) != 0 {
		t.Fatalf("components = %v, want empty array", body["components"])
	}

	recorder = doRequest(t, handler, http.MethodPost, "/sboms", `{
		"artifact":"cyc","version":"1","components":[
			{"coordinate":"x","license":"MIT","dependencies":["y"]},
			{"coordinate":"y","license":"MIT","dependencies":["x"]}
		]}`)
	if recorder.Code != http.StatusCreated {
		t.Fatalf("cyclic deps: status = %d body %s", recorder.Code, recorder.Body.String())
	}
}

func TestPostSBOMsRejectsInvalidInput(t *testing.T) {
	cases := map[string]string{
		"empty body":                     ``,
		"json array":                     `["not","an","object"]`,
		"json scalar":                    `"artifact"`,
		"json null":                      `null`,
		"two objects":                    `{"artifact":"a","version":"1","components":[]}{}`,
		"trailing garbage":               `{"artifact":"a","version":"1","components":[]}x`,
		"missing artifact":               `{"version":"1","components":[]}`,
		"missing version":                `{"artifact":"a","components":[]}`,
		"missing components":             `{"artifact":"a","version":"1"}`,
		"null artifact":                  `{"artifact":null,"version":"1","components":[]}`,
		"numeric artifact":               `{"artifact":7,"version":"1","components":[]}`,
		"components as object":           `{"artifact":"a","version":"1","components":{}}`,
		"empty artifact":                 `{"artifact":"   ","version":"1","components":[]}`,
		"empty version":                  `{"artifact":"a","version":" ","components":[]}`,
		"component missing coordinate":   `{"artifact":"a","version":"1","components":[{"license":"MIT","dependencies":[]}]}`,
		"component missing license":      `{"artifact":"a","version":"1","components":[{"coordinate":"x","dependencies":[]}]}`,
		"component missing dependencies": `{"artifact":"a","version":"1","components":[{"coordinate":"x","license":"MIT"}]}`,
		"component null fields":          `{"artifact":"a","version":"1","components":[{"coordinate":null,"license":"MIT","dependencies":[]}]}`,
		"component wrong shape":          `{"artifact":"a","version":"1","components":["x"]}`,
		"empty coordinate":               `{"artifact":"a","version":"1","components":[{"coordinate":"  ","license":"MIT","dependencies":[]}]}`,
		"empty license":                  `{"artifact":"a","version":"1","components":[{"coordinate":"x","license":"","dependencies":[]}]}`,
		"duplicate coordinates":          `{"artifact":"a","version":"1","components":[{"coordinate":"x","license":"MIT","dependencies":[]},{"coordinate":"x","license":"ISC","dependencies":[]}]}`,
		"duplicate dependencies":         `{"artifact":"a","version":"1","components":[{"coordinate":"x","license":"MIT","dependencies":["y","y"]},{"coordinate":"y","license":"MIT","dependencies":[]}]}`,
		"self dependency":                `{"artifact":"a","version":"1","components":[{"coordinate":"x","license":"MIT","dependencies":["x"]}]}`,
		"missing dependency target":      `{"artifact":"a","version":"1","components":[{"coordinate":"x","license":"MIT","dependencies":["y"]}]}`,
		"dependency wrong type":          `{"artifact":"a","version":"1","components":[{"coordinate":"x","license":"MIT","dependencies":[7]}]}`,
		"empty dependency string":        `{"artifact":"a","version":"1","components":[{"coordinate":"x","license":"MIT","dependencies":["  "]}]}`,
	}
	for name, payload := range cases {
		t.Run(name, func(t *testing.T) {
			_, handler := openRouterStore(t)
			recorder := doRequest(t, handler, http.MethodPost, "/sboms", payload)
			if recorder.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want %d; body %s", recorder.Code, http.StatusBadRequest, recorder.Body.String())
			}
			assertErrorCode(t, recorder, "InvalidSbomInputError")
		})
	}
}

func TestPostSBOMsDuplicateRegistrationSemantics(t *testing.T) {
	_, handler := openRouterStore(t)

	first := doRequest(t, handler, http.MethodPost, "/sboms", `{
		"artifact":"dup","version":"1.0","components":[
			{"coordinate":"a","license":"MIT","dependencies":["b"]},
			{"coordinate":"b","license":"ISC","dependencies":[]}
		]}`)
	if first.Code != http.StatusCreated {
		t.Fatalf("first: status %d %s", first.Code, first.Body.String())
	}
	firstBody := decodeBody(t, first)

	// Same content, components and dependencies in different order.
	second := doRequest(t, handler, http.MethodPost, "/sboms", `{
		"artifact":"dup","version":"1.0","components":[
			{"coordinate":"b","license":"ISC","dependencies":[]},
			{"coordinate":"a","license":"MIT","dependencies":["b"]}
		]}`)
	if second.Code != http.StatusCreated {
		t.Fatalf("identical resubmit: status = %d body %s", second.Code, second.Body.String())
	}
	secondBody := decodeBody(t, second)
	if secondBody["id"] != firstBody["id"] {
		t.Fatalf("id changed: %v != %v", secondBody["id"], firstBody["id"])
	}

	// Different license for the same component set -> conflict.
	conflict := doRequest(t, handler, http.MethodPost, "/sboms", `{
		"artifact":"dup","version":"1.0","components":[
			{"coordinate":"a","license":"GPL-3.0","dependencies":["b"]},
			{"coordinate":"b","license":"ISC","dependencies":[]}
		]}`)
	if conflict.Code != http.StatusConflict {
		t.Fatalf("conflict: status = %d, want %d", conflict.Code, http.StatusConflict)
	}
	assertErrorCode(t, conflict, "SbomConflictError")

	// The original record is unchanged.
	listing := doRequest(t, handler, http.MethodGet, "/sboms?artifact=dup", "")
	items := decodeBody(t, listing)["items"].([]any)
	if len(items) != 1 || items[0].(map[string]any)["id"] != firstBody["id"] {
		t.Fatalf("stored records changed after conflict: %s", listing.Body.String())
	}
}

func TestGetSBOMsPagination(t *testing.T) {
	_, handler := openRouterStore(t)

	for i := 0; i < 3; i++ {
		versions := []string{"1.0", "2.0", "3.0"}
		payload := `{"artifact":"lib","version":"` + versions[i] + `","components":[]}`
		if recorder := doRequest(t, handler, http.MethodPost, "/sboms", payload); recorder.Code != http.StatusCreated {
			t.Fatalf("seed %d: %s", i, recorder.Body.String())
		}
	}

	// Defaults: page 1, pageSize 20.
	recorder := doRequest(t, handler, http.MethodGet, "/sboms?artifact=lib", "")
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d", recorder.Code)
	}
	body := decodeBody(t, recorder)
	if body["total"].(float64) != 3 || body["page"].(float64) != 1 || body["pageSize"].(float64) != 20 {
		t.Fatalf("metadata = %v", body)
	}
	if items := body["items"].([]any); len(items) != 3 {
		t.Fatalf("items = %v", items)
	}

	// Explicit paging.
	recorder = doRequest(t, handler, http.MethodGet, "/sboms?artifact=lib&page=2&pageSize=2", "")
	body = decodeBody(t, recorder)
	if body["total"].(float64) != 3 || body["page"].(float64) != 2 || body["pageSize"].(float64) != 2 {
		t.Fatalf("metadata = %v", body)
	}
	items := body["items"].([]any)
	if len(items) != 1 || items[0].(map[string]any)["version"] != "3.0" {
		t.Fatalf("page 2 items = %v", items)
	}

	// Unknown artifact and a page past the end return empty items.
	for _, target := range []string{"/sboms?artifact=missing", "/sboms?artifact=lib&page=9&pageSize=2"} {
		recorder = doRequest(t, handler, http.MethodGet, target, "")
		body = decodeBody(t, recorder)
		if items, _ := body["items"].([]any); len(items) != 0 {
			t.Fatalf("%s items = %v, want empty", target, body["items"])
		}
	}
}

func TestGetSBOMsRejectsInvalidQuery(t *testing.T) {
	cases := map[string]string{
		"missing artifact":    "/sboms",
		"blank artifact":      "/sboms?artifact=%20%20",
		"page zero":           "/sboms?artifact=a&page=0",
		"page negative":       "/sboms?artifact=a&page=-1",
		"page fractional":     "/sboms?artifact=a&page=1.5",
		"page non numeric":    "/sboms?artifact=a&page=abc",
		"pageSize zero":       "/sboms?artifact=a&pageSize=0",
		"pageSize over 100":   "/sboms?artifact=a&pageSize=101",
		"pageSize fractional": "/sboms?artifact=a&pageSize=2.5",
	}
	for name, target := range cases {
		t.Run(name, func(t *testing.T) {
			_, handler := openRouterStore(t)
			recorder := doRequest(t, handler, http.MethodGet, target, "")
			if recorder.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want %d", recorder.Code, http.StatusBadRequest)
			}
			assertErrorCode(t, recorder, "InvalidSbomInputError")
		})
	}
}

func TestSBOMEndpointsStorageUnavailable(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "service.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	handler := NewRouter(st)
	if err := st.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	post := doRequest(t, handler, http.MethodPost, "/sboms",
		`{"artifact":"a","version":"1","components":[]}`)
	if post.Code != http.StatusServiceUnavailable {
		t.Fatalf("post status = %d, want %d", post.Code, http.StatusServiceUnavailable)
	}
	assertErrorCode(t, post, "storage_unavailable")

	get := doRequest(t, handler, http.MethodGet, "/sboms?artifact=a", "")
	if get.Code != http.StatusServiceUnavailable {
		t.Fatalf("get status = %d, want %d", get.Code, http.StatusServiceUnavailable)
	}
	assertErrorCode(t, get, "storage_unavailable")
}

func TestErrorMessageStaysClean(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "service.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	handler := NewRouter(st)
	if err := st.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	recorder := doRequest(t, handler, http.MethodPost, "/sboms",
		`{"artifact":"a","version":"1","components":[]}`)
	errorBody := decodeBody(t, recorder)["error"].(map[string]any)
	message := errorBody["message"].(string)
	for _, banned := range []string{"SQL", "sql", "/", "goroutine", ".go:"} {
		if bytes.Contains([]byte(message), []byte(banned)) {
			t.Fatalf("message %q leaks %q", message, banned)
		}
	}
}

func assertErrorCode(t *testing.T, recorder *httptest.ResponseRecorder, want string) {
	t.Helper()
	body := decodeBody(t, recorder)
	errorBody, ok := body["error"].(map[string]any)
	if !ok {
		t.Fatalf("response lacks top-level error object: %s", recorder.Body.String())
	}
	if errorBody["code"] != want {
		t.Fatalf("code = %v, want %s; body %s", errorBody["code"], want, recorder.Body.String())
	}
	if _, ok := errorBody["message"].(string); !ok {
		t.Fatalf("message missing or not a string: %s", recorder.Body.String())
	}
}
