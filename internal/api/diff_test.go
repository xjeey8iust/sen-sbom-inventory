package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/xjeey8iust/sen-sbom-inventory/internal/model"
)

// TestDiffEndpointComputesFullComparison drives the contract end to end: both
// manifests are registered with shuffled component and dependency order, then
// compared; the response carries only the normalized identifiers and the
// three ordered difference arrays, and every component keeps the registration
// response shape (coordinate/license/dependencies, empty deps as []).
func TestDiffEndpointComputesFullComparison(t *testing.T) {
	router, _ := newTestRouter(t)

	postSBOM(t, router, `{"artifact":"  app  ","version":"1","components":[
		{"coordinate":"d","license":"L4","dependencies":[]},
		{"coordinate":"a","license":"L1","dependencies":["c","b"]},
		{"coordinate":"c","license":"L3","dependencies":[]},
		{"coordinate":"b","license":"L2","dependencies":[]}
	]}`)
	postSBOM(t, router, `{"artifact":"app","version":"2","components":[
		{"coordinate":"e","license":"L5","dependencies":["a"]},
		{"coordinate":"b","license":"L2-new","dependencies":[]},
		{"coordinate":"a","license":"L1","dependencies":["b"]},
		{"coordinate":"c","license":"L3","dependencies":[]}
	]}`)

	rec := getSBOMs(t, router, "/sboms/diff?artifact=%20app%20&fromVersion=1&toVersion=2")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body %s", rec.Code, rec.Body.String())
	}

	var got model.DiffResult
	decodeBody(t, rec, &got)
	if got.Artifact != "app" || got.FromVersion != "1" || got.ToVersion != "2" {
		t.Fatalf("identifiers = %q/%q/%q, want app/1/2", got.Artifact, got.FromVersion, got.ToVersion)
	}

	if len(got.Added) != 1 {
		t.Fatalf("added = %+v, want [e]", got.Added)
	}
	added := got.Added[0]
	if added.Coordinate != "e" || added.License != "L5" || len(added.Dependencies) != 1 || added.Dependencies[0] != "a" {
		t.Fatalf("added component not the complete new component: %+v", added)
	}

	if len(got.Removed) != 1 {
		t.Fatalf("removed = %+v, want [d]", got.Removed)
	}
	removed := got.Removed[0]
	if removed.Coordinate != "d" || removed.License != "L4" || len(removed.Dependencies) != 0 {
		t.Fatalf("removed component not the complete old component: %+v", removed)
	}

	if len(got.Changed) != 2 || got.Changed[0].Coordinate != "a" || got.Changed[1].Coordinate != "b" {
		t.Fatalf("changed = %+v, want coordinates [a b]", got.Changed)
	}
	aChange := got.Changed[0]
	if len(aChange.Before.Dependencies) != 2 ||
		aChange.Before.Dependencies[0] != "b" || aChange.Before.Dependencies[1] != "c" {
		t.Fatalf("a before deps not the stored ascending order: %v", aChange.Before.Dependencies)
	}
	if len(aChange.After.Dependencies) != 1 || aChange.After.Dependencies[0] != "b" {
		t.Fatalf("a after deps = %v, want [b]", aChange.After.Dependencies)
	}
	if aChange.Before.License != "L1" || aChange.After.License != "L1" {
		t.Fatalf("a license must be unchanged: %q/%q", aChange.Before.License, aChange.After.License)
	}
	bChange := got.Changed[1]
	if bChange.Before.License != "L2" || bChange.After.License != "L2-new" {
		t.Fatalf("b licenses = %q/%q", bChange.Before.License, bChange.After.License)
	}
}

// TestDiffEndpointRenameAndDirection checks the rename rule and that the
// versions are labels: from=2,to=1 swaps added and removed.
func TestDiffEndpointRenameAndDirection(t *testing.T) {
	router, _ := newTestRouter(t)
	postSBOM(t, router, `{"artifact":"app","version":"1","components":[
		{"coordinate":"old","license":"L","dependencies":[]}
	]}`)
	postSBOM(t, router, `{"artifact":"app","version":"2","components":[
		{"coordinate":"new","license":"L","dependencies":[]}
	]}`)

	forward := getSBOMs(t, router, "/sboms/diff?artifact=app&fromVersion=1&toVersion=2")
	var fwd model.DiffResult
	decodeBody(t, forward, &fwd)
	if len(fwd.Added) != 1 || fwd.Added[0].Coordinate != "new" ||
		len(fwd.Removed) != 1 || fwd.Removed[0].Coordinate != "old" ||
		len(fwd.Changed) != 0 {
		t.Fatalf("rename forward = %+v, want added[new] removed[old] changed[]", fwd)
	}

	backward := getSBOMs(t, router, "/sboms/diff?artifact=app&fromVersion=2&toVersion=1")
	var back model.DiffResult
	decodeBody(t, backward, &back)
	if len(back.Added) != 1 || back.Added[0].Coordinate != "old" ||
		len(back.Removed) != 1 || back.Removed[0].Coordinate != "new" {
		t.Fatalf("rename backward = %+v", back)
	}
}

// TestDiffEndpointEmptyArraysAreNeverNull proves at the wire level that the
// three difference fields are always arrays: self comparison, two different
// empty manifests, and an equal pair of non-empty manifests.
func TestDiffEndpointEmptyArraysAreNeverNull(t *testing.T) {
	router, _ := newTestRouter(t)
	postSBOM(t, router, `{"artifact":"app","version":"empty1","components":[]}`)
	postSBOM(t, router, `{"artifact":"app","version":"empty2","components":[]}`)
	postSBOM(t, router, `{"artifact":"app","version":"same1","components":[
		{"coordinate":"a","license":"L","dependencies":[]}
	]}`)
	postSBOM(t, router, `{"artifact":"app","version":"same2","components":[
		{"coordinate":"a","license":"L","dependencies":[]}
	]}`)

	cases := []struct {
		name        string
		fromVersion string
		toVersion   string
	}{
		{"self comparison", "same1", "same1"},
		{"two empty manifests", "empty1", "empty2"},
		{"identical non-empty manifests", "same1", "same2"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := getSBOMs(t, router, "/sboms/diff?artifact=app&fromVersion="+tc.fromVersion+"&toVersion="+tc.toVersion)
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, body %s", rec.Code, rec.Body.String())
			}
			var raw struct {
				Added   *json.RawMessage `json:"added"`
				Removed *json.RawMessage `json:"removed"`
				Changed *json.RawMessage `json:"changed"`
			}
			decodeBody(t, rec, &raw)
			for field, value := range map[string]*json.RawMessage{
				"added": raw.Added, "removed": raw.Removed, "changed": raw.Changed,
			} {
				if value == nil {
					t.Fatalf("%s field missing", field)
				}
				if got := string(bytes.TrimSpace(*value)); got != "[]" {
					t.Fatalf("%s = %s, want []", field, got)
				}
			}
		})
	}
}

// TestDiffEndpointResponseShape inspects the raw JSON: top level has exactly
// the six contracted fields, a changed entry exactly coordinate/before/after
// and a component exactly coordinate/license/dependencies.
func TestDiffEndpointResponseShape(t *testing.T) {
	router, _ := newTestRouter(t)
	postSBOM(t, router, `{"artifact":"app","version":"1","components":[
		{"coordinate":"a","license":"L1","dependencies":[]}
	]}`)
	postSBOM(t, router, `{"artifact":"app","version":"2","components":[
		{"coordinate":"a","license":"L2","dependencies":[]}
	]}`)

	rec := getSBOMs(t, router, "/sboms/diff?artifact=app&fromVersion=1&toVersion=2")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body %s", rec.Code, rec.Body.String())
	}
	var top map[string]json.RawMessage
	decodeBody(t, rec, &top)
	assertExactKeys(t, top, "artifact", "fromVersion", "toVersion", "added", "removed", "changed")

	var changed []map[string]json.RawMessage
	if err := json.Unmarshal(top["changed"], &changed); err != nil {
		t.Fatalf("decode changed: %v", err)
	}
	if len(changed) != 1 {
		t.Fatalf("changed len = %d", len(changed))
	}
	assertExactKeys(t, changed[0], "coordinate", "before", "after")

	var component map[string]json.RawMessage
	if err := json.Unmarshal(changed[0]["after"], &component); err != nil {
		t.Fatalf("decode after: %v", err)
	}
	assertExactKeys(t, component, "coordinate", "license", "dependencies")
}

func assertExactKeys(t *testing.T, object map[string]json.RawMessage, want ...string) {
	t.Helper()
	if len(object) != len(want) {
		t.Fatalf("fields = %v, want exactly %v", keysOf(object), want)
	}
	for _, key := range want {
		if _, ok := object[key]; !ok {
			t.Fatalf("missing field %q in %v", key, keysOf(object))
		}
	}
}

// TestDiffEndpointRejectsInvalidQuery: every required parameter must be
// present and non-empty after trimming.
func TestDiffEndpointRejectsInvalidQuery(t *testing.T) {
	bad := []string{
		"/sboms/diff",
		"/sboms/diff?fromVersion=1&toVersion=2",
		"/sboms/diff?artifact=app&toVersion=2",
		"/sboms/diff?artifact=app&fromVersion=1",
		"/sboms/diff?artifact=&fromVersion=1&toVersion=2",
		"/sboms/diff?artifact=app&fromVersion=&toVersion=2",
		"/sboms/diff?artifact=app&fromVersion=1&toVersion=",
		"/sboms/diff?artifact=%20%20&fromVersion=1&toVersion=2",
		"/sboms/diff?artifact=app&fromVersion=%09&toVersion=2",
		"/sboms/diff?artifact=app&fromVersion=1&toVersion=%20",
	}
	for _, target := range bad {
		router, _ := newTestRouter(t)
		expectError(t, getSBOMs(t, router, target), http.StatusBadRequest, "InvalidSbomInputError")
	}
}

// TestDiffEndpointReturnsNotFound covers each missing-version shape; both
// versions absent still yields exactly one error, and the envelope never
// leaks internals.
func TestDiffEndpointReturnsNotFound(t *testing.T) {
	missing := []string{
		"/sboms/diff?artifact=app&fromVersion=1&toVersion=2",
		"/sboms/diff?artifact=app&fromVersion=2&toVersion=1",
		"/sboms/diff?artifact=app&fromVersion=8&toVersion=9",
		"/sboms/diff?artifact=app&fromVersion=9&toVersion=9",
		"/sboms/diff?artifact=ghost&fromVersion=1&toVersion=1",
	}
	for _, target := range missing {
		t.Run(target, func(t *testing.T) {
			router, _ := newTestRouter(t)
			postSBOM(t, router, `{"artifact":"app","version":"1","components":[]}`)
			rec := getSBOMs(t, router, target)
			assertErrorOnlyEnvelope(t, rec.Body.Bytes())
			expectError(t, rec, http.StatusNotFound, "SbomNotFoundError")
		})
	}
}

// TestDiffEndpointCaseSensitive: parameters match exactly after trimming; a
// differently cased artifact or version is a not-found, never a fuzzy match.
func TestDiffEndpointCaseSensitive(t *testing.T) {
	router, _ := newTestRouter(t)
	postSBOM(t, router, `{"artifact":"App","version":"1","components":[
		{"coordinate":"a","license":"L","dependencies":[]}
	]}`)

	// Whitespace is trimmed and the exact-cased manifest is found.
	rec := getSBOMs(t, router, "/sboms/diff?artifact=%20App%20&fromVersion=%201%20&toVersion=1")
	if rec.Code != http.StatusOK {
		t.Fatalf("trimmed exact match: %d %s", rec.Code, rec.Body.String())
	}

	// Cased artifact mismatch and cased version mismatch are not found.
	for _, target := range []string{
		"/sboms/diff?artifact=app&fromVersion=1&toVersion=1",
		"/sboms/diff?artifact=App&fromVersion=1&toVersion=01",
	} {
		expectError(t, getSBOMs(t, router, target), http.StatusNotFound, "SbomNotFoundError")
	}
}

// TestDiffEndpointStorageFailureReturns503: a closed handle yields the generic
// 503 and the fault-injecting driver proves each read step maps to 503 with no
// partial difference on the wire.
func TestDiffEndpointStorageFailureReturns503(t *testing.T) {
	t.Run("closed handle", func(t *testing.T) {
		router, st := newTestRouter(t)
		postSBOM(t, router, `{"artifact":"app","version":"1","components":[]}`)
		if err := st.Close(); err != nil {
			t.Fatalf("close: %v", err)
		}
		rec := getSBOMs(t, router, "/sboms/diff?artifact=app&fromVersion=1&toVersion=1")
		assertErrorOnlyEnvelope(t, rec.Body.Bytes())
		expectError(t, rec, http.StatusServiceUnavailable, "storage_unavailable")
	})

	for _, kind := range []string{"sboms", "components", "dependencies"} {
		t.Run("fault/"+kind, func(t *testing.T) {
			router, counted := newCountedRouter(t)
			postSBOM(t, router, `{"artifact":"app","version":"1","components":[
				{"coordinate":"a","license":"A","dependencies":["b"]},
				{"coordinate":"b","license":"B","dependencies":[]}
			]}`)
			postSBOM(t, router, `{"artifact":"app","version":"2","components":[
				{"coordinate":"a","license":"A","dependencies":[]},
				{"coordinate":"b","license":"B","dependencies":[]}
			]}`)
			counted.FailNextRead(kind)

			rec := getSBOMs(t, router, "/sboms/diff?artifact=app&fromVersion=1&toVersion=2")
			if rec.Code != http.StatusServiceUnavailable {
				t.Fatalf("%s failure: status = %d, want 503; body %s", kind, rec.Code, rec.Body.String())
			}
			assertErrorOnlyEnvelope(t, rec.Body.Bytes())
			expectError(t, rec, http.StatusServiceUnavailable, "storage_unavailable")
			for _, leaked := range []string{"SELECT", "SQLITE", "sql:", "goroutine", ".go:", "forced", "/"} {
				if bytes.Contains(rec.Body.Bytes(), []byte(leaked)) {
					t.Fatalf("response leaks %q: %s", leaked, rec.Body.String())
				}
			}

			// The one-shot fault is consumed; the identical request now succeeds.
			okRec := getSBOMs(t, router, "/sboms/diff?artifact=app&fromVersion=1&toVersion=2")
			if okRec.Code != http.StatusOK {
				t.Fatalf("retry status = %d, want 200; body %s", okRec.Code, okRec.Body.String())
			}
		})
	}
}

// TestDiffEndpointDoesNotChangeExistingRoutes ensures the new static route
// coexists with the collection route and the health check.
func TestDiffEndpointDoesNotChangeExistingRoutes(t *testing.T) {
	router, _ := newTestRouter(t)
	postSBOM(t, router, `{"artifact":"app","version":"1","components":[]}`)

	if rec := getSBOMs(t, router, "/sboms?artifact=app"); rec.Code != http.StatusOK {
		t.Fatalf("GET /sboms regressed: %d %s", rec.Code, rec.Body.String())
	}
	if rec := getSBOMs(t, router, "/healthz"); rec.Code != http.StatusOK {
		t.Fatalf("GET /healthz regressed: %d", rec.Code)
	}
	if rec := postSBOM(t, router, `{"artifact":"app","version":"1","components":[]}`); rec.Code != http.StatusCreated {
		t.Fatalf("POST /sboms idempotent path regressed: %d %s", rec.Code, rec.Body.String())
	}
}
