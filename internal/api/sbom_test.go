package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/xjeey8iust/sen-sbom-inventory/internal/model"
	"github.com/xjeey8iust/sen-sbom-inventory/internal/store"
)

func newTestRouter(t *testing.T) (*gin.Engine, *store.Store) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "service.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	return NewRouter(st), st
}

func postSBOM(t *testing.T, router *gin.Engine, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/sboms", bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec
}

func getSBOMs(t *testing.T, router *gin.Engine, target string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, target, nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec
}

func decodeBody(t *testing.T, rec *httptest.ResponseRecorder, v any) {
	t.Helper()
	if err := json.Unmarshal(rec.Body.Bytes(), v); err != nil {
		t.Fatalf("decode %q: %v", rec.Body.String(), err)
	}
}

func expectError(t *testing.T, rec *httptest.ResponseRecorder, status int, code string) {
	t.Helper()
	if rec.Code != status {
		t.Fatalf("status = %d, want %d; body %s", rec.Code, status, rec.Body.String())
	}
	var envelope struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	decodeBody(t, rec, &envelope)
	if envelope.Error.Code != code {
		t.Fatalf("code = %q, want %q", envelope.Error.Code, code)
	}
	if envelope.Error.Message == "" {
		t.Fatalf("error message is empty")
	}
	for _, leaked := range []string{"SQLITE", "sql:", "goroutine", "/", ".go:"} {
		if bytes.Contains(rec.Body.Bytes(), []byte(leaked)) {
			t.Fatalf("error response leaks %q: %s", leaked, rec.Body.String())
		}
	}
}

func TestRegisterCreatesNormalizedManifest(t *testing.T) {
	router, _ := newTestRouter(t)

	// Whitespace everywhere, components and dependencies in non-sorted order.
	body := `{
		"artifact": "  atlas  ",
		"version": " 1.2.0 ",
		"components": [
			{"coordinate": " lib-z ", "license": " MIT ", "dependencies": [" lib-a "]},
			{"coordinate": "lib-a", "license": "Apache-2.0", "dependencies": []}
		]
	}`
	rec := postSBOM(t, router, body)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, body %s", rec.Code, rec.Body.String())
	}
	var got model.SBOM
	decodeBody(t, rec, &got)
	if got.ID <= 0 {
		t.Fatalf("id = %d, want positive integer", got.ID)
	}
	want := model.SBOM{
		ID:       got.ID,
		Artifact: "atlas",
		Version:  "1.2.0",
		Components: []model.Component{
			{Coordinate: "lib-a", License: "Apache-2.0", Dependencies: []string{}},
			{Coordinate: "lib-z", License: "MIT", Dependencies: []string{"lib-a"}},
		},
	}
	assertSBOMEqual(t, &got, &want)
}

func TestRegisterAllowsEmptyComponentsAndDependencies(t *testing.T) {
	router, _ := newTestRouter(t)
	rec := postSBOM(t, router, `{"artifact":"a","version":"1","components":[]}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("empty components: status = %d, body %s", rec.Code, rec.Body.String())
	}
	var got model.SBOM
	decodeBody(t, rec, &got)
	if len(got.Components) != 0 {
		t.Fatalf("components = %v, want empty array", got.Components)
	}

	rec = postSBOM(t, router, `{"artifact":"b","version":"1","components":[{"coordinate":"c","license":"l","dependencies":[]}]}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("empty dependencies: status = %d, body %s", rec.Code, rec.Body.String())
	}
	decodeBody(t, rec, &got)
	if len(got.Components[0].Dependencies) != 0 {
		t.Fatalf("dependencies = %v, want empty array", got.Components[0].Dependencies)
	}
}

func TestRegisterAllowsNonSelfCycles(t *testing.T) {
	router, _ := newTestRouter(t)
	body := `{"artifact":"cyc","version":"1","components":[
		{"coordinate":"a","license":"MIT","dependencies":["b"]},
		{"coordinate":"b","license":"MIT","dependencies":["a"]}
	]}`
	if rec := postSBOM(t, router, body); rec.Code != http.StatusCreated {
		t.Fatalf("cycle status = %d, body %s", rec.Code, rec.Body.String())
	}
}

func TestRegisterRejectsInvalidInput(t *testing.T) {
	cases := map[string]string{
		"empty body":                   ``,
		"malformed json":               `{`,
		"top-level array":              `[]`,
		"top-level null":               `null`,
		"top-level number":             `42`,
		"top-level string":             `"x"`,
		"two objects":                  `{"artifact":"a","version":"1","components":[]}{}`,
		"object then garbage":          `{"artifact":"a","version":"1","components":[]} xxx`,
		"missing all":                  `{}`,
		"missing version":              `{"artifact":"a","components":[]}`,
		"missing artifact":             `{"version":"1","components":[]}`,
		"missing components":           `{"artifact":"a","version":"1"}`,
		"null components":              `{"artifact":"a","version":"1","components":null}`,
		"empty artifact":               `{"artifact":"","version":"1","components":[]}`,
		"blank version":                `{"artifact":"a","version":"   ","components":[]}`,
		"artifact wrong type":          `{"artifact":7,"version":"1","components":[]}`,
		"components wrong type":        `{"artifact":"a","version":"1","components":"x"}`,
		"component element scalar":     `{"artifact":"a","version":"1","components":["x"]}`,
		"component null element":       `{"artifact":"a","version":"1","components":[null]}`,
		"component missing coordinate": `{"artifact":"a","version":"1","components":[{"license":"l","dependencies":[]}]}`,
		"component missing license":    `{"artifact":"a","version":"1","components":[{"coordinate":"c","dependencies":[]}]}`,
		"component missing deps":       `{"artifact":"a","version":"1","components":[{"coordinate":"c","license":"l"}]}`,
		"null license":                 `{"artifact":"a","version":"1","components":[{"coordinate":"c","license":null,"dependencies":[]}]}`,
		"null dependencies":            `{"artifact":"a","version":"1","components":[{"coordinate":"c","license":"l","dependencies":null}]}`,
		"empty coordinate":             `{"artifact":"a","version":"1","components":[{"coordinate":"  ","license":"l","dependencies":[]}]}`,
		"coordinate wrong type":        `{"artifact":"a","version":"1","components":[{"coordinate":1,"license":"l","dependencies":[]}]}`,
		"duplicate coordinates":        `{"artifact":"a","version":"1","components":[{"coordinate":"c","license":"l","dependencies":[]},{"coordinate":"c","license":"l","dependencies":[]}]}`,
		"duplicate after trimming":     `{"artifact":"a","version":"1","components":[{"coordinate":" c ","license":"l","dependencies":[]},{"coordinate":"c","license":"l","dependencies":[]}]}`,
		"duplicate dependency":         `{"artifact":"a","version":"1","components":[{"coordinate":"c","license":"l","dependencies":["x","x"]},{"coordinate":"x","license":"l","dependencies":[]}]}`,
		"self dependency":              `{"artifact":"a","version":"1","components":[{"coordinate":"c","license":"l","dependencies":["c"]}]}`,
		"empty dependency":             `{"artifact":"a","version":"1","components":[{"coordinate":"c","license":"l","dependencies":["  "]}]}`,
		"dependency wrong type":        `{"artifact":"a","version":"1","components":[{"coordinate":"c","license":"l","dependencies":[1]}]}`,
		"dangling dependency":          `{"artifact":"a","version":"1","components":[{"coordinate":"c","license":"l","dependencies":["ghost"]}]}`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			router, _ := newTestRouter(t)
			expectError(t, postSBOM(t, router, body), http.StatusBadRequest, "InvalidSbomInputError")
		})
	}
}

func TestRegisterIsIdempotentRegardlessOfOrder(t *testing.T) {
	router, _ := newTestRouter(t)

	first := `{"artifact":"app","version":"1","components":[
		{"coordinate":"a","license":"L1","dependencies":["b","c"]},
		{"coordinate":"b","license":"L2","dependencies":["c"]},
		{"coordinate":"c","license":"L3","dependencies":[]}
	]}`
	rec := postSBOM(t, router, first)
	if rec.Code != http.StatusCreated {
		t.Fatalf("first register: %d %s", rec.Code, rec.Body.String())
	}
	var original model.SBOM
	decodeBody(t, rec, &original)

	// Same content, arrays shuffled and whitespace added: still 201, same id.
	again := `{"artifact":" app ","version":" 1 ","components":[
		{"coordinate":"c","license":" L3 ","dependencies":[]},
		{"coordinate":"a","license":"L1","dependencies":["c","b"]},
		{"coordinate":"b","license":"L2","dependencies":["c"]}
	]}`
	rec = postSBOM(t, router, again)
	if rec.Code != http.StatusCreated {
		t.Fatalf("idempotent register: status = %d, body %s", rec.Code, rec.Body.String())
	}
	var repeated model.SBOM
	decodeBody(t, rec, &repeated)
	if repeated.ID != original.ID {
		t.Fatalf("id changed: %d -> %d", original.ID, repeated.ID)
	}
	assertSBOMEqual(t, &repeated, &original)
}

func TestRegisterConflictLeavesOriginalUntouched(t *testing.T) {
	changed := []string{
		// Different license.
		`{"artifact":"app","version":"1","components":[{"coordinate":"a","license":"OTHER","dependencies":[]}]}`,
		// Different component set.
		`{"artifact":"app","version":"1","components":[{"coordinate":"b","license":"L","dependencies":[]}]}`,
		// Different dependency relation.
		`{"artifact":"app","version":"1","components":[{"coordinate":"a","license":"L","dependencies":[]},{"coordinate":"b","license":"L","dependencies":["a"]}]}`,
	}
	for i, mutated := range changed {
		t.Run(fmt.Sprintf("mutation-%d", i), func(t *testing.T) {
			router, _ := newTestRouter(t)
			base := `{"artifact":"app","version":"1","components":[
				{"coordinate":"a","license":"L","dependencies":[]},
				{"coordinate":"b","license":"L","dependencies":[]}
			]}`
			if rec := postSBOM(t, router, base); rec.Code != http.StatusCreated {
				t.Fatalf("base: %d %s", rec.Code, rec.Body.String())
			}
			expectError(t, postSBOM(t, router, mutated), http.StatusConflict, "SbomConflictError")

			rec := getSBOMs(t, router, "/sboms?artifact=app")
			if rec.Code != http.StatusOK {
				t.Fatalf("list after conflict: %d", rec.Code)
			}
			var page listResponse
			decodeBody(t, rec, &page)
			if page.Total != 1 || len(page.Items) != 1 {
				t.Fatalf("original record changed: total=%d items=%d", page.Total, len(page.Items))
			}
			if len(page.Items[0].Components) != 2 {
				t.Fatalf("components after conflict = %v", page.Items[0].Components)
			}
		})
	}
}

func TestComparisonsAreCaseSensitive(t *testing.T) {
	router, _ := newTestRouter(t)

	postSBOM(t, router, `{"artifact":"App","version":"1","components":[{"coordinate":"a","license":"L","dependencies":[]}]}`)
	// Different casing on artifact is a different manifest.
	rec := postSBOM(t, router, `{"artifact":"app","version":"1","components":[{"coordinate":"a","license":"L","dependencies":[]}]}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("cased artifact: %d %s", rec.Code, rec.Body.String())
	}
	// Same artifact/version, coordinate differing only in case conflicts.
	expectError(t, postSBOM(t, router,
		`{"artifact":"App","version":"1","components":[{"coordinate":"A","license":"L","dependencies":[]}]}`),
		http.StatusConflict, "SbomConflictError")

	rec = getSBOMs(t, router, "/sboms?artifact=App")
	var page listResponse
	decodeBody(t, rec, &page)
	if page.Total != 1 {
		t.Fatalf("case-sensitive filter total = %d, want 1", page.Total)
	}
}

func TestListPaginatesByIDWithTotal(t *testing.T) {
	router, _ := newTestRouter(t)
	// Five manifests for "app" registered out of order, plus two others.
	for _, v := range []string{"3", "1", "4", "2", "5"} {
		body := fmt.Sprintf(`{"artifact":"app","version":"%s","components":[{"coordinate":"c","license":"L","dependencies":[]}]}`, v)
		if rec := postSBOM(t, router, body); rec.Code != http.StatusCreated {
			t.Fatalf("register %s: %d", v, rec.Code)
		}
	}
	for _, v := range []string{"1", "2"} {
		body := fmt.Sprintf(`{"artifact":"other","version":"%s","components":[]}`, v)
		if rec := postSBOM(t, router, body); rec.Code != http.StatusCreated {
			t.Fatalf("register other %s: %d", v, rec.Code)
		}
	}

	var seen []int64
	for page := 1; page <= 3; page++ {
		rec := getSBOMs(t, router, fmt.Sprintf("/sboms?artifact=app&page=%d&pageSize=2", page))
		if rec.Code != http.StatusOK {
			t.Fatalf("page %d: %d", page, rec.Code)
		}
		var got listResponse
		decodeBody(t, rec, &got)
		if got.Total != 5 {
			t.Fatalf("page %d total = %d, want 5", page, got.Total)
		}
		if got.Page != page || got.PageSize != 2 {
			t.Fatalf("echoed paging = %d/%d", got.Page, got.PageSize)
		}
		wantItems := 2
		if page == 3 {
			wantItems = 1
		}
		if len(got.Items) != wantItems {
			t.Fatalf("page %d items = %d, want %d", page, len(got.Items), wantItems)
		}
		for _, item := range got.Items {
			if len(item.Components) != 1 || item.Components[0].Coordinate != "c" {
				t.Fatalf("page item is not a full manifest: %+v", item)
			}
			seen = append(seen, item.ID)
		}
	}
	for i := 1; i < len(seen); i++ {
		if seen[i-1] >= seen[i] {
			t.Fatalf("ids not ascending: %v", seen)
		}
	}

	// Past the last page: empty items, total unchanged.
	rec := getSBOMs(t, router, "/sboms?artifact=app&page=4&pageSize=2")
	var past listResponse
	decodeBody(t, rec, &past)
	if len(past.Items) != 0 || past.Total != 5 {
		t.Fatalf("past-end page = %+v", past)
	}

	// Unknown artifact.
	rec = getSBOMs(t, router, "/sboms?artifact=ghost")
	var unknown listResponse
	decodeBody(t, rec, &unknown)
	if len(unknown.Items) != 0 || unknown.Total != 0 {
		t.Fatalf("unknown artifact = %+v", unknown)
	}
	if unknown.Page != 1 || unknown.PageSize != 20 {
		t.Fatalf("defaults = %d/%d, want 1/20", unknown.Page, unknown.PageSize)
	}
}

func TestListRejectsBadQuery(t *testing.T) {
	bad := []string{
		"/sboms",
		"/sboms?artifact=%20%20",
		"/sboms?artifact=a&page=",
		"/sboms?artifact=a&page=0",
		"/sboms?artifact=a&page=-1",
		"/sboms?artifact=a&page=abc",
		"/sboms?artifact=a&page=1.5",
		"/sboms?artifact=a&pageSize=0",
		"/sboms?artifact=a&pageSize=101",
		"/sboms?artifact=a&pageSize=abc",
		"/sboms?artifact=a&pageSize=-20",
	}
	for _, target := range bad {
		router, _ := newTestRouter(t)
		expectError(t, getSBOMs(t, router, target), http.StatusBadRequest, "InvalidSbomInputError")
	}

	router, _ := newTestRouter(t)
	// pageSize=100 is allowed; page=1 default applies.
	rec := getSBOMs(t, router, "/sboms?artifact=a&pageSize=100")
	if rec.Code != http.StatusOK {
		t.Fatalf("pageSize 100: %d %s", rec.Code, rec.Body.String())
	}
}

func TestPersistsAcrossReopen(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "service.db")

	st, err := store.Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	router1 := NewRouter(st)
	rec := postSBOM(t, router1, `{"artifact":"app","version":"1","components":[{"coordinate":"c","license":"L","dependencies":[]}]}`)
	var first model.SBOM
	decodeBody(t, rec, &first)
	if err := st.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	st2, err := store.Open(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer st2.Close()
	router2 := NewRouter(st2)

	// Same manifest after reopen: same id, 201.
	rec = postSBOM(t, router2, `{"artifact":"app","version":"1","components":[{"coordinate":"c","license":"L","dependencies":[]}]}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("re-register after reopen: %d %s", rec.Code, rec.Body.String())
	}
	var again model.SBOM
	decodeBody(t, rec, &again)
	if again.ID != first.ID {
		t.Fatalf("id after reopen = %d, want %d", again.ID, first.ID)
	}

	// Changed content after reopen still conflicts.
	expectError(t, postSBOM(t, router2,
		`{"artifact":"app","version":"1","components":[{"coordinate":"c","license":"X","dependencies":[]}]}`),
		http.StatusConflict, "SbomConflictError")

	// Query sees the persisted record.
	rec = getSBOMs(t, router2, "/sboms?artifact=app")
	var page listResponse
	decodeBody(t, rec, &page)
	if page.Total != 1 || page.Items[0].ID != first.ID {
		t.Fatalf("list after reopen = %+v", page)
	}
}

func TestConcurrentIdenticalRegistersShareOneRecord(t *testing.T) {
	router, _ := newTestRouter(t)
	body := `{"artifact":"race","version":"1","components":[
		{"coordinate":"a","license":"L","dependencies":["b"]},
		{"coordinate":"b","license":"L","dependencies":[]}
	]}`
	const n = 8
	var wg sync.WaitGroup
	ids := make(chan int64, n)
	statuses := make(chan int, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rec := postSBOM(t, router, body)
			statuses <- rec.Code
			if rec.Code == http.StatusCreated {
				var got model.SBOM
				json.Unmarshal(rec.Body.Bytes(), &got)
				ids <- got.ID
			}
		}()
	}
	wg.Wait()
	close(ids)
	close(statuses)

	first := int64(-1)
	for status := range statuses {
		if status != http.StatusCreated {
			t.Fatalf("concurrent register status = %d, want 201", status)
		}
	}
	count := 0
	for id := range ids {
		if first == -1 {
			first = id
		} else if id != first {
			t.Fatalf("concurrent registers produced ids %d and %d", first, id)
		}
		count++
	}
	if count != n {
		t.Fatalf("created responses = %d, want %d", count, n)
	}
}

func TestStorageFailureMapsTo503(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "service.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	router := NewRouter(st)
	if err := st.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	expectError(t, postSBOM(t, router, `{"artifact":"a","version":"1","components":[]}`),
		http.StatusServiceUnavailable, "storage_unavailable")
	expectError(t, getSBOMs(t, router, "/sboms?artifact=a"),
		http.StatusServiceUnavailable, "storage_unavailable")
}

func assertSBOMEqual(t *testing.T, got, want *model.SBOM) {
	t.Helper()
	if got.Artifact != want.Artifact || got.Version != want.Version {
		t.Fatalf("artifact/version = %q/%q, want %q/%q", got.Artifact, got.Version, want.Artifact, want.Version)
	}
	if len(got.Components) != len(want.Components) {
		t.Fatalf("components len = %d, want %d", len(got.Components), len(want.Components))
	}
	for i := range want.Components {
		g, w := got.Components[i], want.Components[i]
		if g.Coordinate != w.Coordinate || g.License != w.License {
			t.Fatalf("component %d = %+v, want %+v", i, g, w)
		}
		if len(g.Dependencies) != len(w.Dependencies) {
			t.Fatalf("deps of %s = %v, want %v", g.Coordinate, g.Dependencies, w.Dependencies)
		}
		for j := range w.Dependencies {
			if g.Dependencies[j] != w.Dependencies[j] {
				t.Fatalf("deps of %s = %v, want %v", g.Coordinate, g.Dependencies, w.Dependencies)
			}
		}
	}
}
