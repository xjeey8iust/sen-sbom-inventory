package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/xjeey8iust/sen-sbom-inventory/internal/model"
	"github.com/xjeey8iust/sen-sbom-inventory/internal/store"
)

func decodeDiff(t *testing.T, rec *httptest.ResponseRecorder) diffResponse {
	t.Helper()
	var got diffResponse
	decodeBody(t, rec, &got)
	return got
}

// TestDiffPartitionsAddedRemovedChanged drives the full HTTP contract:
// added/removed/changed are sorted by coordinate and changed entries carry
// the complete before/after components.
func TestDiffPartitionsAddedRemovedChanged(t *testing.T) {
	router, _ := newTestRouter(t)

	postSBOM(t, router, `{"artifact":"app","version":"1","components":[
		{"coordinate":"gone","license":"G","dependencies":[]},
		{"coordinate":"stable","license":"S","dependencies":[]},
		{"coordinate":"moved-edge","license":"M","dependencies":["stable"]},
		{"coordinate":"rel","license":"OLD","dependencies":["stable"]},
		{"coordinate":"zeta-change","license":"Z","dependencies":[]},
		{"coordinate":"alpha-change","license":"A","dependencies":[]}
	]}`)
	postSBOM(t, router, `{"artifact":"app","version":"2","components":[
		{"coordinate":"born","license":"B","dependencies":[]},
		{"coordinate":"stable","license":"S","dependencies":[]},
		{"coordinate":"moved-edge","license":"M","dependencies":["born","stable"]},
		{"coordinate":"rel","license":"NEW","dependencies":["stable"]},
		{"coordinate":"zeta-change","license":"Z","dependencies":["stable"]},
		{"coordinate":"alpha-change","license":"A2","dependencies":[]}
	]}`)

	rec := getSBOMs(t, router, "/sboms/diff?artifact=app&fromVersion=1&toVersion=2")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body %s", rec.Code, rec.Body.String())
	}
	got := decodeDiff(t, rec)
	if got.Artifact != "app" || got.FromVersion != "1" || got.ToVersion != "2" {
		t.Fatalf("identifiers = %+v", got)
	}

	if len(got.Added) != 1 || got.Added[0].Coordinate != "born" ||
		got.Added[0].License != "B" || len(got.Added[0].Dependencies) != 0 {
		t.Fatalf("added = %+v, want full born component", got.Added)
	}
	if len(got.Removed) != 1 || got.Removed[0].Coordinate != "gone" ||
		got.Removed[0].License != "G" || len(got.Removed[0].Dependencies) != 0 {
		t.Fatalf("removed = %+v, want full gone component", got.Removed)
	}

	wantChanged := []string{"alpha-change", "moved-edge", "rel", "zeta-change"}
	if len(got.Changed) != len(wantChanged) {
		t.Fatalf("changed = %d entries %+v, want %d", len(got.Changed), got.Changed, len(wantChanged))
	}
	for i, coordinate := range wantChanged {
		if got.Changed[i].Coordinate != coordinate {
			t.Fatalf("changed not coordinate-sorted at %d: %q want %q; %+v",
				i, got.Changed[i].Coordinate, coordinate, got.Changed)
		}
		if got.Changed[i].Before.Coordinate != coordinate || got.Changed[i].After.Coordinate != coordinate {
			t.Fatalf("changed %s before/after missing coordinate", coordinate)
		}
		if got.Changed[i].Before.Dependencies == nil || got.Changed[i].After.Dependencies == nil {
			t.Fatalf("changed %s carries nil dependency arrays", coordinate)
		}
	}
	byCoord := map[string]componentChange{}
	for _, ch := range got.Changed {
		byCoord[ch.Coordinate] = ch
	}
	if byCoord["rel"].Before.License != "OLD" || byCoord["rel"].After.License != "NEW" {
		t.Fatalf("rel before/after licenses = %q/%q", byCoord["rel"].Before.License, byCoord["rel"].After.License)
	}
	edge := byCoord["moved-edge"]
	if len(edge.Before.Dependencies) != 1 || edge.Before.Dependencies[0] != "stable" {
		t.Fatalf("moved-edge before = %+v", edge.Before)
	}
	if len(edge.After.Dependencies) != 2 ||
		edge.After.Dependencies[0] != "born" || edge.After.Dependencies[1] != "stable" {
		t.Fatalf("moved-edge after = %+v, want full sorted component", edge.After)
	}
	// License must be carried on both sides of an edge-only change.
	if edge.Before.License != "M" || edge.After.License != "M" {
		t.Fatalf("moved-edge licenses = %q/%q", edge.Before.License, edge.After.License)
	}
}

// TestDiffSortsAddedAndRemovedAcrossMultipleComponents makes sure both
// presence arrays are coordinate-sorted, not registration-ordered.
func TestDiffSortsAddedAndRemovedAcrossMultipleComponents(t *testing.T) {
	router, _ := newTestRouter(t)
	postSBOM(t, router, `{"artifact":"app","version":"1","components":[
		{"coordinate":"z","license":"L","dependencies":[]},
		{"coordinate":"m","license":"L","dependencies":[]},
		{"coordinate":"a","license":"L","dependencies":[]}
	]}`)
	postSBOM(t, router, `{"artifact":"app","version":"2","components":[
		{"coordinate":"y","license":"L","dependencies":[]},
		{"coordinate":"b","license":"L","dependencies":[]},
		{"coordinate":"n","license":"L","dependencies":[]}
	]}`)

	got := decodeDiff(t, getSBOMs(t, router, "/sboms/diff?artifact=app&fromVersion=1&toVersion=2"))
	gotAdded := []string{}
	for _, c := range got.Added {
		gotAdded = append(gotAdded, c.Coordinate)
	}
	gotRemoved := []string{}
	for _, c := range got.Removed {
		gotRemoved = append(gotRemoved, c.Coordinate)
	}
	if fmt.Sprint(gotAdded) != "[b n y]" {
		t.Fatalf("added order = %v, want [b n y]", gotAdded)
	}
	if fmt.Sprint(gotRemoved) != "[a m z]" {
		t.Fatalf("removed order = %v, want [a m z]", gotRemoved)
	}
	if len(got.Changed) != 0 {
		t.Fatalf("changed = %+v, want empty", got.Changed)
	}
}

// TestDiffCoordinateRenameIsRemovePlusAdd: the same component under a new
// coordinate must never be reported as a change.
func TestDiffCoordinateRenameIsRemovePlusAdd(t *testing.T) {
	router, _ := newTestRouter(t)
	postSBOM(t, router, `{"artifact":"app","version":"1","components":[
		{"coordinate":"old-name","license":"MIT","dependencies":[]}
	]}`)
	postSBOM(t, router, `{"artifact":"app","version":"2","components":[
		{"coordinate":"new-name","license":"MIT","dependencies":[]}
	]}`)

	got := decodeDiff(t, getSBOMs(t, router, "/sboms/diff?artifact=app&fromVersion=1&toVersion=2"))
	if len(got.Removed) != 1 || got.Removed[0].Coordinate != "old-name" {
		t.Fatalf("removed = %+v", got.Removed)
	}
	if len(got.Added) != 1 || got.Added[0].Coordinate != "new-name" {
		t.Fatalf("added = %+v", got.Added)
	}
	if len(got.Changed) != 0 {
		t.Fatalf("rename produced changed entries: %+v", got.Changed)
	}
}

// TestDiffOnlyDirectRelationsAndNoPropagation: a license change on a
// dependency target and a transitive edge change deeper in the graph must not
// mark the referencing components as changed — only components whose own
// license or own direct dependency set changed appear.
func TestDiffOnlyDirectRelationsAndNoPropagation(t *testing.T) {
	router, _ := newTestRouter(t)
	postSBOM(t, router, `{"artifact":"app","version":"1","components":[
		{"coordinate":"a","license":"L","dependencies":["b"]},
		{"coordinate":"b","license":"L","dependencies":["c"]},
		{"coordinate":"c","license":"OLD","dependencies":[]}
	]}`)
	// c changes license AND gains a direct edge to the new d; a and b keep
	// identical own license and own direct edges.
	postSBOM(t, router, `{"artifact":"app","version":"2","components":[
		{"coordinate":"a","license":"L","dependencies":["b"]},
		{"coordinate":"b","license":"L","dependencies":["c"]},
		{"coordinate":"c","license":"NEW","dependencies":["d"]},
		{"coordinate":"d","license":"L","dependencies":[]}
	]}`)

	got := decodeDiff(t, getSBOMs(t, router, "/sboms/diff?artifact=app&fromVersion=1&toVersion=2"))
	if len(got.Changed) != 1 || got.Changed[0].Coordinate != "c" {
		t.Fatalf("changed = %+v, want only c", got.Changed)
	}
	if len(got.Added) != 1 || got.Added[0].Coordinate != "d" {
		t.Fatalf("added = %+v, want only d", got.Added)
	}
	if len(got.Removed) != 0 {
		t.Fatalf("removed = %+v, want empty", got.Removed)
	}
}

// TestDiffSelfComparisonReturnsThreeEmptyArrays: same version with itself
// returns 200 and empty diff arrays as long as the manifest exists.
func TestDiffSelfComparisonReturnsThreeEmptyArrays(t *testing.T) {
	router, _ := newTestRouter(t)
	postSBOM(t, router, `{"artifact":"app","version":"1","components":[
		{"coordinate":"a","license":"L","dependencies":["b"]},
		{"coordinate":"b","license":"L","dependencies":["a"]}
	]}`)

	rec := getSBOMs(t, router, "/sboms/diff?artifact=app&fromVersion=1&toVersion=1")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body %s", rec.Code, rec.Body.String())
	}
	got := decodeDiff(t, rec)
	if len(got.Added) != 0 || len(got.Removed) != 0 || len(got.Changed) != 0 {
		t.Fatalf("self diff = %+v, want all empty", got)
	}
}

// TestDiffIdenticalDistinctVersionsReturnsEmpty: two different versions with
// identical content produce no changes (versions are not ordered, just
// compared).
func TestDiffIdenticalDistinctVersionsReturnsEmpty(t *testing.T) {
	router, _ := newTestRouter(t)
	manifest := `{"artifact":"app","version":"%s","components":[
		{"coordinate":"a","license":"L","dependencies":["b"]},
		{"coordinate":"b","license":"L","dependencies":[]}
	]}`
	postSBOM(t, router, fmt.Sprintf(manifest, "2"))
	postSBOM(t, router, fmt.Sprintf(manifest, "1"))

	got := decodeDiff(t, getSBOMs(t, router, "/sboms/diff?artifact=app&fromVersion=2&toVersion=1"))
	if len(got.Added) != 0 || len(got.Removed) != 0 || len(got.Changed) != 0 {
		t.Fatalf("identical versions differ: %+v", got)
	}
}

// TestDiffEmptyManifestsAndEmptyArraysNeverNull checks the wire shape for the
// empty manifest cases and proves every diff array serializes as [] not null.
func TestDiffEmptyManifestsAndEmptyArraysNeverNull(t *testing.T) {
	router, _ := newTestRouter(t)
	postSBOM(t, router, `{"artifact":"app","version":"1","components":[]}`)
	postSBOM(t, router, `{"artifact":"app","version":"2","components":[]}`)

	rec := getSBOMs(t, router, "/sboms/diff?artifact=app&fromVersion=1&toVersion=2")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	var raw struct {
		Added   *[]json.RawMessage `json:"added"`
		Removed *[]json.RawMessage `json:"removed"`
		Changed *[]json.RawMessage `json:"changed"`
	}
	decodeBody(t, rec, &raw)
	for name, arr := range map[string]*[]json.RawMessage{
		"added": raw.Added, "removed": raw.Removed, "changed": raw.Changed,
	} {
		if arr == nil {
			t.Fatalf("%s serialized as null", name)
		}
		if len(*arr) != 0 {
			t.Fatalf("%s = %v, want empty", name, *arr)
		}
	}
}

// TestDiffCyclesFollowSameRules makes sure allowed non-self cycles compare by
// the same direct-edge rule and round-trip complete inside changed entries.
func TestDiffCyclesFollowSameRules(t *testing.T) {
	router, _ := newTestRouter(t)
	postSBOM(t, router, `{"artifact":"cyc","version":"1","components":[
		{"coordinate":"a","license":"L","dependencies":["b"]},
		{"coordinate":"b","license":"L","dependencies":["a"]}
	]}`)
	// Same cycle, only a's license changes. No expansion, no propagation: b
	// must stay out of changed.
	postSBOM(t, router, `{"artifact":"cyc","version":"2","components":[
		{"coordinate":"a","license":"OTHER","dependencies":["b"]},
		{"coordinate":"b","license":"L","dependencies":["a"]}
	]}`)

	got := decodeDiff(t, getSBOMs(t, router, "/sboms/diff?artifact=cyc&fromVersion=1&toVersion=2"))
	if len(got.Changed) != 1 || got.Changed[0].Coordinate != "a" {
		t.Fatalf("changed = %+v, want only a", got.Changed)
	}
	if got.Changed[0].Before.License != "L" || got.Changed[0].After.License != "OTHER" {
		t.Fatalf("a sides = %+v", got.Changed[0])
	}
	if len(got.Changed[0].After.Dependencies) != 1 || got.Changed[0].After.Dependencies[0] != "b" {
		t.Fatalf("cycle edge missing from after: %+v", got.Changed[0].After)
	}
}

// TestDiffRejectsMissingOrBlankParams covers required-param validation.
func TestDiffRejectsMissingOrBlankParams(t *testing.T) {
	bad := []string{
		"/sboms/diff",
		"/sboms/diff?fromVersion=1&toVersion=2",
		"/sboms/diff?artifact=app&toVersion=2",
		"/sboms/diff?artifact=app&fromVersion=1",
		"/sboms/diff?artifact=%20%20&fromVersion=1&toVersion=2",
		"/sboms/diff?artifact=app&fromVersion=%09&toVersion=2",
		"/sboms/diff?artifact=app&fromVersion=1&toVersion=",
		"/sboms/diff?artifact=app&fromVersion=1&toVersion=%20%20",
	}
	for _, target := range bad {
		router, _ := newTestRouter(t)
		expectError(t, getSBOMs(t, router, target), http.StatusBadRequest, "InvalidSbomInputError")
	}
}

// TestDiffMissingVersionsReturns404 covers unknown artifact, either side
// missing and both sides missing (still exactly one SbomNotFoundError), plus
// the self-comparison of a missing version.
func TestDiffMissingVersionsReturns404(t *testing.T) {
	cases := []struct {
		name   string
		target string
	}{
		{"both versions missing", "/sboms/diff?artifact=app&fromVersion=8&toVersion=9"},
		{"from missing", "/sboms/diff?artifact=app&fromVersion=9&toVersion=1"},
		{"to missing", "/sboms/diff?artifact=app&fromVersion=1&toVersion=9"},
		{"unknown artifact", "/sboms/diff?artifact=ghost&fromVersion=1&toVersion=2"},
		{"self missing", "/sboms/diff?artifact=app&fromVersion=3&toVersion=3"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			router, _ := newTestRouter(t)
			postSBOM(t, router, `{"artifact":"app","version":"1","components":[]}`)
			postSBOM(t, router, `{"artifact":"app","version":"2","components":[]}`)
			rec := getSBOMs(t, router, tc.target)
			expectError(t, rec, http.StatusNotFound, "SbomNotFoundError")
			assertErrorOnlyEnvelope(t, rec.Body.Bytes())
		})
	}
}

// TestDiffTrimsParamsAndMatchesCaseSensitively verifies normalization of the
// three identifiers and exact, case-sensitive matching.
func TestDiffTrimsParamsAndMatchesCaseSensitively(t *testing.T) {
	router, _ := newTestRouter(t)
	postSBOM(t, router, `{"artifact":"  App  ","version":" 1 ","components":[]}`)
	postSBOM(t, router, `{"artifact":"App","version":"2","components":[]}`)

	// Padding is trimmed and the normalized values are echoed.
	rec := getSBOMs(t, router, "/sboms/diff?artifact=%20%20App%20&fromVersion=%201%20%20&toVersion=%092%09")
	if rec.Code != http.StatusOK {
		t.Fatalf("trimmed params: %d %s", rec.Code, rec.Body.String())
	}
	got := decodeDiff(t, rec)
	if got.Artifact != "App" || got.FromVersion != "1" || got.ToVersion != "2" {
		t.Fatalf("identifiers not normalized: %+v", got)
	}

	// Different casing on artifact matches nothing: 404. A padded value
	// trims first, so " 9 " is looked up as the still-missing version "9".
	expectError(t, getSBOMs(t, router, "/sboms/diff?artifact=app&fromVersion=1&toVersion=2"),
		http.StatusNotFound, "SbomNotFoundError")
	expectError(t, getSBOMs(t, router, "/sboms/diff?artifact=App&fromVersion=1&toVersion=%209%20"),
		http.StatusNotFound, "SbomNotFoundError")
}

// TestDiffStorageFailureReturns503WithoutPartialResult forces each read to
// fail and asserts the contracted error-only envelope with no internals.
func TestDiffStorageFailureReturns503WithoutPartialResult(t *testing.T) {
	for _, kind := range []string{"sboms", "components", "dependencies"} {
		t.Run(kind, func(t *testing.T) {
			router, counted := newCountedRouter(t)
			postSBOM(t, router, `{"artifact":"app","version":"1","components":[
				{"coordinate":"a","license":"A","dependencies":["b"]},
				{"coordinate":"b","license":"B","dependencies":[]}
			]}`)
			postSBOM(t, router, `{"artifact":"app","version":"2","components":[
				{"coordinate":"a","license":"A2","dependencies":[]}
			]}`)
			counted.FailNextRead(kind)

			rec := getSBOMs(t, router, "/sboms/diff?artifact=app&fromVersion=1&toVersion=2")
			if rec.Code != http.StatusServiceUnavailable {
				t.Fatalf("%s failure: status = %d, want 503; body %s", kind, rec.Code, rec.Body.String())
			}
			assertErrorOnlyEnvelope(t, rec.Body.Bytes())
			expectError(t, rec, http.StatusServiceUnavailable, "storage_unavailable")
			for _, leaked := range []string{"SELECT", "SQLITE", "sql:", "goroutine", ".go:", "forced read failure"} {
				if bytes.Contains(rec.Body.Bytes(), []byte(leaked)) {
					t.Fatalf("response leaks %q: %s", leaked, rec.Body.String())
				}
			}
		})
	}
}

// TestDiffWithClosedStoreReturns503 mirrors the existing endpoints' behavior
// when the database handle is unusable.
func TestDiffWithClosedStoreReturns503(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "service.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	router := NewRouter(st)
	if err := st.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	expectError(t, getSBOMs(t, router, "/sboms/diff?artifact=a&fromVersion=1&toVersion=2"),
		http.StatusServiceUnavailable, "storage_unavailable")
}

// TestDiffKeepsExistingRoutesBehavior is a guard: registering /sboms/diff
// must not shadow GET /sboms or its paging.
func TestDiffKeepsExistingRoutesBehavior(t *testing.T) {
	router, _ := newTestRouter(t)
	postSBOM(t, router, `{"artifact":"app","version":"1","components":[]}`)

	rec := getSBOMs(t, router, "/sboms?artifact=app")
	if rec.Code != http.StatusOK {
		t.Fatalf("list broken by diff route: %d", rec.Code)
	}
	var page listResponse
	decodeBody(t, rec, &page)
	if page.Total != 1 || len(page.Items) != 1 {
		t.Fatalf("list page = %+v", page)
	}
}

// TestBuildDiffComparesDependenciesAsSets unit-tests the order-independence
// of the direct dependency comparison: stored reconstructions are always
// sorted, but the rule must hold regardless of array order.
func TestBuildDiffComparesDependenciesAsSets(t *testing.T) {
	before := &model.SBOM{Artifact: "app", Version: "1", Components: []model.Component{
		{Coordinate: "a", License: "L", Dependencies: []string{"x", "y", "z"}},
	}}
	after := &model.SBOM{Artifact: "app", Version: "2", Components: []model.Component{
		{Coordinate: "a", License: "L", Dependencies: []string{"z", "x", "y"}},
	}}
	got := buildDiff("app", "1", "2", before, after)
	if len(got.Changed) != 0 {
		t.Fatalf("shuffled same dependency set reported as changed: %+v", got.Changed)
	}

	after.Components[0].Dependencies = []string{"x", "y"}
	got = buildDiff("app", "1", "2", before, after)
	if len(got.Changed) != 1 || got.Changed[0].Coordinate != "a" {
		t.Fatalf("dropped dependency not detected: %+v", got.Changed)
	}
}
