package api

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/xjeey8iust/sen-sbom-inventory/internal/model"
)

// TestRegisterAndParseSBOMShareNormalization proves the HTTP entry and the
// standalone entry are the same rule set: the manifest the endpoint stores
// and returns for a whitespace-padded, shuffled payload is exactly what
// model.ParseSBOM produces for the same bytes (modulo the store-assigned ID).
func TestRegisterAndParseSBOMShareNormalization(t *testing.T) {
	router, _ := newTestRouter(t)
	body := `{
		"artifact": "  atlas  ",
		"version": " 1.2.0 ",
		"components": [
			{"coordinate": " lib-z ", "license": " MIT ", "dependencies": [" lib-a ", "lib-b"]},
			{"coordinate": "lib-b", "license": "BSD-3-Clause", "dependencies": []},
			{"coordinate": "lib-a", "license": "Apache-2.0", "dependencies": ["lib-b"]}
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

	parsed, err := model.ParseSBOM([]byte(body))
	if err != nil {
		t.Fatalf("ParseSBOM rejected what the endpoint accepted: %v", err)
	}
	if parsed.ID != 0 {
		t.Fatalf("standalone parse assigned id %d, want zero", parsed.ID)
	}
	got.ID = 0
	if !reflect.DeepEqual(&got, parsed) {
		t.Fatalf("endpoint and standalone parse differ:\nendpoint: %+v\nparse:    %+v", &got, parsed)
	}

	// The shuffled, padded twin of the same manifest is the same record:
	// 201 again, original id, identical content.
	twin := `{"artifact":" atlas ","version":" 1.2.0","components":[
		{"coordinate":"lib-a","license":"Apache-2.0","dependencies":["lib-b"]},
		{"coordinate":" lib-z ","license":"MIT","dependencies":["lib-b","lib-a"]},
		{"coordinate":"lib-b","license":" BSD-3-Clause ","dependencies":[]}
	]}`
	rec = postSBOM(t, router, twin)
	if rec.Code != http.StatusCreated {
		t.Fatalf("twin status = %d, body %s", rec.Code, rec.Body.String())
	}
	var repeated model.SBOM
	decodeBody(t, rec, &repeated)
	if repeated.ID == 0 {
		t.Fatalf("twin returned zero id")
	}
	repeated.ID = 0
	if !reflect.DeepEqual(&repeated, parsed) {
		t.Fatalf("twin registration differs from shared normalization:\n%+v\n%+v", &repeated, parsed)
	}
}

// TestRegisterInvalidInputNeverReachesStorage drives rejected payloads
// through the real router on the counting driver: the 400 must be decided
// before any storage statement runs, so not even the dedup SELECT may appear.
func TestRegisterInvalidInputNeverReachesStorage(t *testing.T) {
	bodies := map[string]string{
		"malformed json":     `{`,
		"missing components": `{"artifact":"a","version":"1"}`,
		"trailing value":     `{"artifact":"a","version":"1","components":[]}{}`,
		"duplicate coordinate": `{"artifact":"a","version":"1","components":[
			{"coordinate":"c","license":"l","dependencies":[]},
			{"coordinate":"c","license":"l","dependencies":[]}
		]}`,
		"dangling dependency": `{"artifact":"a","version":"1","components":[
			{"coordinate":"c","license":"l","dependencies":["ghost"]}
		]}`,
	}
	for name, body := range bodies {
		t.Run(name, func(t *testing.T) {
			router, counted := newCountedRouter(t)
			counted.Reset()
			expectError(t, postSBOM(t, router, body), http.StatusBadRequest, "InvalidSbomInputError")
			if selects := counted.Snapshot().Selects; selects != 0 {
				t.Fatalf("invalid input reached storage: %d SELECTs issued", selects)
			}

			// Nothing was registered as a side effect.
			rec := getSBOMs(t, router, "/sboms?artifact=a")
			var page listResponse
			decodeBody(t, rec, &page)
			if page.Total != 0 || len(page.Items) != 0 {
				t.Fatalf("rejected input left a record: total=%d items=%d", page.Total, len(page.Items))
			}
		})
	}
}

// failingBody makes io.ReadAll(c.Request.Body) fail, simulating a transport
// error while the handler reads the request body.
type failingBody struct{}

func (failingBody) Read([]byte) (int, error) { return 0, errors.New("forced body read failure") }
func (failingBody) Close() error             { return nil }

var _ io.ReadCloser = failingBody{}

// TestRegisterBodyReadFailureReturns400 pins that a body the handler cannot
// even read is the same client-visible rejection as a malformed one, and
// again no storage statement runs.
func TestRegisterBodyReadFailureReturns400(t *testing.T) {
	router, counted := newCountedRouter(t)
	counted.Reset()

	req := httptest.NewRequest(http.MethodPost, "/sboms", nil)
	req.Body = failingBody{}
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	expectError(t, rec, http.StatusBadRequest, "InvalidSbomInputError")
	if selects := counted.Snapshot().Selects; selects != 0 {
		t.Fatalf("unreadable body reached storage: %d SELECTs issued", selects)
	}
}
