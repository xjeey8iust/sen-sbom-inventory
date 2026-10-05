package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"path/filepath"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/xjeey8iust/sen-sbom-inventory/internal/model"
	"github.com/xjeey8iust/sen-sbom-inventory/internal/store"
	"github.com/xjeey8iust/sen-sbom-inventory/internal/storetest"
)

// newCountedRouter builds the real HTTP router on a Store backed by the
// counting driver, so the SELECT budget can be measured for a whole request.
func newCountedRouter(t *testing.T) (*gin.Engine, *storetest.Driver) {
	t.Helper()
	counted := storetest.Register()
	st, err := store.OpenWithDriver(filepath.Join(t.TempDir(), "counted-service.db"), storetest.DriverName)
	if err != nil {
		t.Fatalf("open counted store: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	return NewRouter(st), counted
}

// TestListRequestUsesAtMostFourSelects proves the end-to-end budget through
// the real HTTP handler: a page of one and a page of a hundred each issue
// exactly four SELECTs, and detail rows never cover anything off the page.
func TestListRequestUsesAtMostFourSelects(t *testing.T) {
	register := func(router *gin.Engine, artifact, version, body string) {
		t.Helper()
		if rec := postSBOM(t, router, body); rec.Code != http.StatusCreated {
			t.Fatalf("register %s@%s: %d %s", artifact, version, rec.Code, rec.Body.String())
		}
	}

	t.Run("one item", func(t *testing.T) {
		router, counted := newCountedRouter(t)
		register(router, "app", "1", `{"artifact":"app","version":"1","components":[
			{"coordinate":"a","license":"A","dependencies":["b","c"]},
			{"coordinate":"b","license":"B","dependencies":["c"]},
			{"coordinate":"c","license":"C","dependencies":[]}
		]}`)
		counted.Reset()

		rec := getSBOMs(t, router, "/sboms?artifact=app")
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body %s", rec.Code, rec.Body.String())
		}
		counters := counted.Snapshot()
		if counters.Selects > 4 {
			t.Fatalf("request issued %d SELECTs, want at most 4", counters.Selects)
		}
		if counters.Selects != 4 {
			t.Fatalf("non-empty page issued %d SELECTs, want exactly 4", counters.Selects)
		}
		if counters.RowsByKind["components"] != 3 || counters.RowsByKind["dependencies"] != 3 {
			t.Fatalf("detail row counts wrong: %+v", counters.RowsByKind)
		}
	})

	t.Run("hundred items", func(t *testing.T) {
		router, counted := newCountedRouter(t)
		for i := 0; i < 100; i++ {
			v := fmt.Sprintf("%02d", i)
			body := fmt.Sprintf(`{"artifact":"app","version":"%s","components":[
				{"coordinate":"a","license":"A","dependencies":["b"]},
				{"coordinate":"b","license":"B","dependencies":[]}
			]}`, v)
			register(router, "app", v, body)
		}
		// A different artifact whose components share coordinates; never part
		// of an "app" page.
		register(router, "other", "1", `{"artifact":"other","version":"1","components":[
			{"coordinate":"a","license":"SECRET","dependencies":[]}
		]}`)
		counted.Reset()

		rec := getSBOMs(t, router, "/sboms?artifact=app&pageSize=100")
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, body %s", rec.Code, rec.Body.String())
		}
		counters := counted.Snapshot()
		if counters.Selects != 4 {
			t.Fatalf("100-item request issued %d SELECTs, want exactly 4", counters.Selects)
		}
		if counters.RowsByKind["sboms"] != 100 ||
			counters.RowsByKind["components"] != 200 ||
			counters.RowsByKind["dependencies"] != 100 {
			t.Fatalf("detail reads escaped the page/artifact: %+v", counters.RowsByKind)
		}

		var got listResponse
		decodeBody(t, rec, &got)
		if got.Total != 100 || len(got.Items) != 100 {
			t.Fatalf("total/items = %d/%d", got.Total, len(got.Items))
		}
		for _, item := range got.Items {
			if item.Artifact != "app" {
				t.Fatalf("foreign item on page: %q", item.Artifact)
			}
			for _, c := range item.Components {
				if c.License == "SECRET" {
					t.Fatalf("other artifact's component leaked: %+v", c)
				}
			}
		}
	})

	t.Run("empty page", func(t *testing.T) {
		router, counted := newCountedRouter(t)
		register(router, "app", "1", `{"artifact":"app","version":"1","components":[]}`)
		counted.Reset()

		// Unknown artifact: count plus page scan, and the detail queries must
		// not run against an empty IN-list.
		rec := getSBOMs(t, router, "/sboms?artifact=ghost")
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d", rec.Code)
		}
		counters := counted.Snapshot()
		if counters.Selects > 4 {
			t.Fatalf("SELECTs = %d, want at most 4", counters.Selects)
		}
		if counters.Selects != 2 || counters.RowsByKind["components"] != 0 || counters.RowsByKind["dependencies"] != 0 {
			t.Fatalf("empty page issued %d selects, rows %+v; want 2 and no details",
				counters.Selects, counters.RowsByKind)
		}
	})
}

// TestListServesCompleteManifestsAcrossPages verifies through HTTP that every
// manifest on every page is complete: components and dependencies ordered,
// empty arrays present, cycles intact and coordinates correctly scoped when
// versions repeat them.
func TestListServesCompleteManifestsAcrossPages(t *testing.T) {
	router, _ := newCountedRouter(t)

	// Three versions of "app" share coordinates but differ in license/edges.
	bodies := []string{
		`{"artifact":"app","version":"1","components":[
			{"coordinate":"lib","license":"Apache-2.0","dependencies":["util"]},
			{"coordinate":"util","license":"BSD-3-Clause","dependencies":[]}
		]}`,
		`{"artifact":"app","version":"2","components":[
			{"coordinate":"lib","license":"GPL-3.0","dependencies":[]},
			{"coordinate":"util","license":"MIT","dependencies":["lib"]}
		]}`,
		`{"artifact":"app","version":"3","components":[
			{"coordinate":"lib","license":"ISC","dependencies":["util"]},
			{"coordinate":"util","license":"Unlicense","dependencies":["lib"]}
		]}`,
	}
	// Plus an empty manifest.
	bodies = append(bodies, `{"artifact":"app","version":"empty","components":[]}`)
	// Plus another artifact that must never appear on "app" pages.
	bodies = append(bodies, `{"artifact":"vendor","version":"1","components":[
		{"coordinate":"lib","license":"PROPRIETARY","dependencies":[]}
	]}`)
	for _, body := range bodies {
		if rec := postSBOM(t, router, body); rec.Code != http.StatusCreated {
			t.Fatalf("register: %d %s", rec.Code, rec.Body.String())
		}
	}

	// Walk every page with pageSize=2 and collect the complete "app" result.
	var collected []*model.SBOM
	total := -1
	for page := 1; ; page++ {
		rec := getSBOMs(t, router, fmt.Sprintf("/sboms?artifact=app&page=%d&pageSize=2", page))
		if rec.Code != http.StatusOK {
			t.Fatalf("page %d: %d %s", page, rec.Code, rec.Body.String())
		}
		var got listResponse
		decodeBody(t, rec, &got)
		if got.Total != 4 {
			t.Fatalf("page %d total = %d, want 4", page, got.Total)
		}
		if got.Page != page || got.PageSize != 2 {
			t.Fatalf("page echo = %d/%d", got.Page, got.PageSize)
		}
		total = got.Total
		if len(got.Items) == 0 {
			break
		}
		collected = append(collected, got.Items...)
		if page > 5 {
			t.Fatalf("pagination did not terminate")
		}
	}
	if len(collected) != total {
		t.Fatalf("collected %d items across pages, want total %d", len(collected), total)
	}

	byVersion := map[string]*model.SBOM{}
	var prevID int64
	for i, item := range collected {
		if i > 0 && item.ID <= prevID {
			t.Fatalf("items not ascending by id across pages: %d after %d", item.ID, prevID)
		}
		prevID = item.ID
		if item.Artifact != "app" {
			t.Fatalf("foreign artifact on page: %q", item.Artifact)
		}
		byVersion[item.Version] = item
	}

	empty, ok := byVersion["empty"]
	if !ok {
		t.Fatalf("empty manifest missing across pages")
	}
	if empty.Components == nil || len(empty.Components) != 0 {
		t.Fatalf("empty components = %v, want [] not null", empty.Components)
	}

	type expectation struct {
		libLicense, utilLicense string
		libDeps, utilDeps       []string
	}
	want := map[string]expectation{
		"1": {"Apache-2.0", "BSD-3-Clause", []string{"util"}, []string{}},
		"2": {"GPL-3.0", "MIT", []string{}, []string{"lib"}},
		"3": {"ISC", "Unlicense", []string{"util"}, []string{"lib"}},
	}
	for version, exp := range want {
		item := byVersion[version]
		comps := map[string]model.Component{}
		for _, c := range item.Components {
			comps[c.Coordinate] = c
			if c.Dependencies == nil {
				t.Fatalf("version %s component %s dependencies are null", version, c.Coordinate)
			}
		}
		if len(item.Components) != 2 {
			t.Fatalf("version %s lost components across pages: %+v", version, item.Components)
		}
		if comps["lib"].License != exp.libLicense || !eqStrings(comps["lib"].Dependencies, exp.libDeps) {
			t.Fatalf("version %s lib = %+v, want %q %v", version, comps["lib"], exp.libLicense, exp.libDeps)
		}
		if comps["util"].License != exp.utilLicense || !eqStrings(comps["util"].Dependencies, exp.utilDeps) {
			t.Fatalf("version %s util = %+v, want %q %v", version, comps["util"], exp.utilLicense, exp.utilDeps)
		}
	}

	// A legal cycle must read back completely through the batched loader.
	cycleBody := `{"artifact":"cyc","version":"1","components":[
		{"coordinate":"a","license":"A","dependencies":["b"]},
		{"coordinate":"b","license":"B","dependencies":["a"]}
	]}`
	if rec := postSBOM(t, router, cycleBody); rec.Code != http.StatusCreated {
		t.Fatalf("register cycle: %d %s", rec.Code, rec.Body.String())
	}
	rec := getSBOMs(t, router, "/sboms?artifact=cyc")
	var cyc listResponse
	decodeBody(t, rec, &cyc)
	if len(cyc.Items) != 1 {
		t.Fatalf("cycle items = %d", len(cyc.Items))
	}
	edges := map[string][]string{}
	for _, c := range cyc.Items[0].Components {
		edges[c.Coordinate] = c.Dependencies
	}
	if len(edges["a"]) != 1 || edges["a"][0] != "b" || len(edges["b"]) != 1 || edges["b"][0] != "a" {
		t.Fatalf("dependency cycle not read back completely: %+v", edges)
	}
}

// TestListEmptyArraysAreNeverNull inspects the raw JSON so the guarantee is
// proven at the wire level, not just on Go structs.
func TestListEmptyArraysAreNeverNull(t *testing.T) {
	router, _ := newCountedRouter(t)
	postSBOM(t, router, `{"artifact":"app","version":"1","components":[]}`)
	postSBOM(t, router, `{"artifact":"app","version":"2","components":[
		{"coordinate":"a","license":"A","dependencies":[]}
	]}`)

	rec := getSBOMs(t, router, "/sboms?artifact=app")
	body := rec.Body.Bytes()
	if !json.Valid(body) {
		t.Fatalf("invalid json: %s", body)
	}
	var raw struct {
		Items []struct {
			Components *[]struct {
				Dependencies *[]string `json:"dependencies"`
			} `json:"components"`
		} `json:"items"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(raw.Items) != 2 {
		t.Fatalf("items = %d", len(raw.Items))
	}
	if raw.Items[0].Components == nil {
		t.Fatalf("empty components serialized as null")
	}
	if raw.Items[1].Components == nil || len(*raw.Items[1].Components) != 1 {
		t.Fatalf("second item components wrong")
	}
	if (*raw.Items[1].Components)[0].Dependencies == nil {
		t.Fatalf("empty dependencies serialized as null")
	}
}

// TestListStorageFailureReturns503WithoutPartialItems forces each of the four
// reads to fail and asserts the HTTP contract: 503, single top-level error,
// storage_unavailable code, no partial items, no internals leaked.
func TestListStorageFailureReturns503WithoutPartialItems(t *testing.T) {
	for _, kind := range []string{"count", "sboms", "components", "dependencies"} {
		t.Run(kind, func(t *testing.T) {
			router, counted := newCountedRouter(t)
			postSBOM(t, router, `{"artifact":"app","version":"1","components":[
				{"coordinate":"a","license":"A","dependencies":["b"]},
				{"coordinate":"b","license":"B","dependencies":[]}
			]}`)
			counted.FailNextRead(kind)

			rec := getSBOMs(t, router, "/sboms?artifact=app")
			if rec.Code != http.StatusServiceUnavailable {
				t.Fatalf("%s failure: status = %d, want 503; body %s", kind, rec.Code, rec.Body.String())
			}
			var envelope struct {
				Error struct {
					Code    string `json:"code"`
					Message string `json:"message"`
				} `json:"error"`
				Items json.RawMessage `json:"items"`
			}
			decodeBody(t, rec, &envelope)
			if envelope.Error.Code != "storage_unavailable" {
				t.Fatalf("code = %q", envelope.Error.Code)
			}
			if envelope.Error.Message == "" {
				t.Fatalf("empty error message")
			}
			if envelope.Items != nil {
				t.Fatalf("partial items present on failure: %s", envelope.Items)
			}
			for _, leaked := range []string{"SELECT", "SQLITE", "sql:", "goroutine", ".go:", "forced read failure"} {
				if bytes.Contains(rec.Body.Bytes(), []byte(leaked)) {
					t.Fatalf("response leaks %q: %s", leaked, rec.Body.String())
				}
			}
		})
	}
}

// TestListTrimsArtifactAndEchoesPaging covers the request normalization and
// response echo semantics on the refactored path.
func TestListTrimsArtifactAndEchoesPaging(t *testing.T) {
	router, _ := newCountedRouter(t)
	postSBOM(t, router, `{"artifact":"  app  ","version":"1","components":[]}`)

	rec := getSBOMs(t, router, "/sboms?artifact=%20%20app%20%20&page=3&pageSize=50")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body %s", rec.Code, rec.Body.String())
	}
	var got listResponse
	decodeBody(t, rec, &got)
	// Trimmed artifact matches the single manifest; past-end page keeps total.
	if got.Total != 1 || len(got.Items) != 0 {
		t.Fatalf("trimmed filter = %+v", got)
	}
	if got.Page != 3 || got.PageSize != 50 {
		t.Fatalf("paging echo = %d/%d", got.Page, got.PageSize)
	}

	// Case sensitivity: "APP" matches nothing.
	rec = getSBOMs(t, router, "/sboms?artifact=APP")
	decodeBody(t, rec, &got)
	if got.Total != 0 || len(got.Items) != 0 {
		t.Fatalf("case-insensitive leak: %+v", got)
	}
}

func eqStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
