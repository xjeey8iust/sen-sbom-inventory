package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/xjeey8iust/sen-sbom-inventory/internal/model"
)

// assertErrorOnlyEnvelope proves the failure body carries exactly one
// top-level "error" object whose only fields are "code" and "message" — no
// partial manifest or page leaks onto the wire.
func assertErrorOnlyEnvelope(t *testing.T, body []byte) {
	t.Helper()
	var top map[string]json.RawMessage
	if err := json.Unmarshal(body, &top); err != nil {
		t.Fatalf("decode %s: %v", body, err)
	}
	if len(top) != 1 {
		t.Fatalf("top-level fields = %v, want only error", keysOf(top))
	}
	rawErr, ok := top["error"]
	if !ok {
		t.Fatalf("body has no error object: %s", body)
	}
	var inner map[string]json.RawMessage
	if err := json.Unmarshal(rawErr, &inner); err != nil {
		t.Fatalf("decode error object: %v", err)
	}
	if len(inner) != 2 {
		t.Fatalf("error fields = %v, want code and message only", keysOf(inner))
	}
	var code, message string
	if err := json.Unmarshal(inner["code"], &code); err != nil {
		t.Fatalf("code is not a string: %v", err)
	}
	if err := json.Unmarshal(inner["message"], &message); err != nil {
		t.Fatalf("message is not a string: %v", err)
	}
	if code == "" || message == "" {
		t.Fatalf("code/message must be non-empty strings: %q/%q", code, message)
	}
}

func keysOf(m map[string]json.RawMessage) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

// TestRegisterDetailWriteFailureReturns503 drives a failing component and a
// failing dependency insert through the real HTTP path: both must answer 503
// storage_unavailable with an error-only envelope, expose no internals, leave
// no trace of the failed registration, and the same request must succeed with
// 201 once the (one-shot) fault is consumed — the shared transaction lifecycle
// returned the connection and undid the partial write.
func TestRegisterDetailWriteFailureReturns503(t *testing.T) {
	body := `{"artifact":"app","version":"1","components":[
		{"coordinate":"a","license":"L-a","dependencies":["b"]},
		{"coordinate":"b","license":"L-b","dependencies":[]}
	]}`

	for _, kind := range []string{"components", "dependencies"} {
		t.Run(kind, func(t *testing.T) {
			router, counted := newCountedRouter(t)

			counted.FailNextWrite(kind)
			rec := postSBOM(t, router, body)
			if rec.Code != http.StatusServiceUnavailable {
				t.Fatalf("status = %d, want 503; body %s", rec.Code, rec.Body.String())
			}
			assertErrorOnlyEnvelope(t, rec.Body.Bytes())
			expectError(t, rec, http.StatusServiceUnavailable, "storage_unavailable")
			for _, leaked := range []string{"INSERT", "SQLITE", "sql:", "goroutine", ".go:", "forced", "/"} {
				if bytes.Contains(rec.Body.Bytes(), []byte(leaked)) {
					t.Fatalf("response leaks %q: %s", leaked, rec.Body.String())
				}
			}

			// The failed registration is not queryable: empty page, total 0.
			listRec := getSBOMs(t, router, "/sboms?artifact=app")
			var page listResponse
			decodeBody(t, listRec, &page)
			if listRec.Code != http.StatusOK || page.Total != 0 || len(page.Items) != 0 {
				t.Fatalf("failed register visible: status=%d total=%d items=%d",
					listRec.Code, page.Total, len(page.Items))
			}

			// Recovery: the fault was one-shot; the identical request now
			// creates the manifest and returns the complete record.
			okRec := postSBOM(t, router, body)
			if okRec.Code != http.StatusCreated {
				t.Fatalf("retry status = %d, want 201; body %s", okRec.Code, okRec.Body.String())
			}
			var created model.SBOM
			decodeBody(t, okRec, &created)
			if created.ID <= 0 || created.Artifact != "app" || created.Version != "1" {
				t.Fatalf("retry returned incomplete manifest: %+v", created)
			}
			if len(created.Components) != 2 ||
				len(created.Components[0].Dependencies) != 1 ||
				created.Components[0].Dependencies[0] != "b" {
				t.Fatalf("retry manifest details wrong: %+v", created.Components)
			}

			listRec = getSBOMs(t, router, "/sboms?artifact=app")
			decodeBody(t, listRec, &page)
			if page.Total != 1 || len(page.Items) != 1 {
				t.Fatalf("after recovery total/items = %d/%d, want 1/1", page.Total, len(page.Items))
			}
			assertSBOMEqual(t, page.Items[0], &created)
		})
	}
}

// TestRegisterWriteFailureLeavesExistingManifestsWhole makes sure a failed new
// registration next to an existing one neither modifies nor hides the
// existing manifest.
func TestRegisterWriteFailureLeavesExistingManifestsWhole(t *testing.T) {
	router, counted := newCountedRouter(t)
	first := postSBOM(t, router, `{"artifact":"app","version":"1","components":[
		{"coordinate":"a","license":"ORIGINAL","dependencies":[]}
	]}`)
	var original model.SBOM
	decodeBody(t, first, &original)

	counted.FailNextWrite("components")
	expectError(t, postSBOM(t, router, `{"artifact":"app","version":"2","components":[
		{"coordinate":"a","license":"NEW","dependencies":[]}
	]}`), http.StatusServiceUnavailable, "storage_unavailable")

	rec := getSBOMs(t, router, "/sboms?artifact=app")
	var page listResponse
	decodeBody(t, rec, &page)
	if page.Total != 1 || len(page.Items) != 1 {
		t.Fatalf("total/items = %d/%d, want 1/1", page.Total, len(page.Items))
	}
	assertSBOMEqual(t, page.Items[0], &original)
	if page.Items[0].Components[0].License != "ORIGINAL" {
		t.Fatalf("existing manifest changed: %+v", page.Items[0])
	}
}
