package api

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/xjeey8iust/sen-sbom-inventory/internal/manifest"
	"github.com/xjeey8iust/sen-sbom-inventory/internal/model"
)

// The same manifest twice: padded with whitespace and shuffled arrays, then
// the canonical ordering. Both entry points must derive identical content.
const sharedMessy = `{"artifact":" app ","version":" 1 ","components":[
	{"coordinate":"c","license":" L3 ","dependencies":[]},
	{"coordinate":"a","license":"L1","dependencies":["c","b"]},
	{"coordinate":"b","license":"L2","dependencies":["c"]}
]}`

const sharedShuffled = `{"artifact":"app","version":"1","components":[
	{"coordinate":"b","license":"L2","dependencies":["c"]},
	{"coordinate":"c","license":"L3","dependencies":[]},
	{"coordinate":"a","license":"L1","dependencies":["b","c"]}
]}`

// TestStandaloneParseAndHTTPRegistrationShareNormalization proves the two
// callers apply one rule set: the library entry and POST /sboms turn the
// padded, out-of-order payload into the same normalized content; replaying the
// shuffled variant still returns 201 with the original id.
func TestStandaloneParseAndHTTPRegistrationShareNormalization(t *testing.T) {
	router, _ := newTestRouter(t)

	parsed, err := manifest.ParseRegistration([]byte(sharedMessy))
	if err != nil {
		t.Fatalf("standalone parse: %v", err)
	}
	if parsed.ID != 0 {
		t.Fatalf("parsed id = %d, want zero before registration", parsed.ID)
	}

	rec := postSBOM(t, router, sharedMessy)
	if rec.Code != http.StatusCreated {
		t.Fatalf("register messy: %d %s", rec.Code, rec.Body.String())
	}
	var registered model.SBOM
	decodeBody(t, rec, &registered)
	if registered.ID <= 0 {
		t.Fatalf("registered id = %d, want store-assigned positive id", registered.ID)
	}

	// Same normalization, minus the store-assigned id.
	parsed.ID = registered.ID
	if !reflect.DeepEqual(*parsed, registered) {
		t.Fatalf("standalone vs HTTP content differs:\n%#v\n%#v", parsed, registered)
	}

	// Shuffled, re-padded replay: still 201 and the same record.
	rec = postSBOM(t, router, sharedShuffled)
	if rec.Code != http.StatusCreated {
		t.Fatalf("replay shuffled: %d %s", rec.Code, rec.Body.String())
	}
	var replayed model.SBOM
	decodeBody(t, rec, &replayed)
	if replayed.ID != registered.ID {
		t.Fatalf("replay id = %d, want %d", replayed.ID, registered.ID)
	}
	if !reflect.DeepEqual(replayed, registered) {
		t.Fatalf("replay content differs:\n%#v\n%#v", replayed, registered)
	}

	// GET /sboms returns the same normalized record, so the stored
	// reconstruction follows the identical rule too.
	pageRec := getSBOMs(t, router, "/sboms?artifact=app")
	var page listResponse
	decodeBody(t, pageRec, &page)
	if page.Total != 1 || len(page.Items) != 1 {
		t.Fatalf("page = total %d items %d, want 1/1", page.Total, len(page.Items))
	}
	if !reflect.DeepEqual(*page.Items[0], registered) {
		t.Fatalf("listed manifest differs from registered:\n%#v\n%#v", page.Items[0], registered)
	}
}

// TestParsedManifestRegistersThroughStore shows the intended Go workflow: the
// zero-id parse result is handed to the store as-is, and idempotency and
// conflict behavior match the HTTP entry.
func TestParsedManifestRegistersThroughStore(t *testing.T) {
	router, st := newTestRouter(t)

	first, err := manifest.ParseRegistration([]byte(sharedMessy))
	if err != nil {
		t.Fatalf("first parse: %v", err)
	}
	saved, created, err := st.Register(t.Context(), first)
	if err != nil || !created {
		t.Fatalf("register parsed: err=%v created=%v", err, created)
	}
	if saved.ID <= 0 || first.ID != 0 {
		t.Fatalf("store must assign id onto its own result, parse result stays zero-id: saved=%d input=%d",
			saved.ID, first.ID)
	}

	// A second, independently parsed copy of the same bytes is recognized as
	// the same manifest: same id, created=false.
	again, err := manifest.ParseRegistration([]byte(sharedShuffled))
	if err != nil {
		t.Fatalf("second parse: %v", err)
	}
	replayed, created, err := st.Register(t.Context(), again)
	if err != nil || created {
		t.Fatalf("re-register parsed: err=%v created=%v", err, created)
	}
	if replayed.ID != saved.ID {
		t.Fatalf("id = %d, want %d", replayed.ID, saved.ID)
	}

	// License change and direct-dependency change parsed standalone both
	// conflict and leave the stored record untouched.
	mutated := []string{
		`{"artifact":"app","version":"1","components":[
			{"coordinate":"a","license":"OTHER","dependencies":["b","c"]},
			{"coordinate":"b","license":"L2","dependencies":["c"]},
			{"coordinate":"c","license":"L3","dependencies":[]}]}`,
		`{"artifact":"app","version":"1","components":[
			{"coordinate":"a","license":"L1","dependencies":["b"]},
			{"coordinate":"b","license":"L2","dependencies":["c"]},
			{"coordinate":"c","license":"L3","dependencies":[]}]}`,
	}
	for i, body := range mutated {
		changed, err := manifest.ParseRegistration([]byte(body))
		if err != nil {
			t.Fatalf("mutation %d parse: %v", i, err)
		}
		if _, _, err := st.Register(t.Context(), changed); !errors.Is(err, model.ErrConflict) {
			t.Fatalf("mutation %d error = %v, want ErrConflict", i, err)
		}
	}

	// HTTP view: still one record, identical to the first response.
	rec := getSBOMs(t, router, "/sboms?artifact=app")
	var page listResponse
	decodeBody(t, rec, &page)
	if page.Total != 1 || len(page.Items) != 1 || page.Items[0].ID != saved.ID {
		t.Fatalf("record changed after conflicts: %+v", page)
	}
	assertSBOMEqual(t, page.Items[0], saved)
}

// TestInvalidRegistrationNeverReachesStore: every malformed request is rejected
// purely by the shared parser. The counting driver must observe no statement
// at all, and a later valid request proves the store was left empty and usable.
func TestInvalidRegistrationNeverReachesStore(t *testing.T) {
	router, counted := newCountedRouter(t)
	invalid := []string{
		``,
		`{`,
		`[]`,
		`{"artifact":"a","version":"1","components":[]} {}`,
		`{"artifact":"a","version":"1"}`,
		`{"artifact":"a","version":"1","components":null}`,
		`{"artifact":"a","version":"1","components":[{"coordinate":"c","license":"l","dependencies":["ghost"]}]}`,
		`{"artifact":"a","version":"1","components":[{"coordinate":"c","license":"l","dependencies":["c"]}]}`,
	}
	for i, body := range invalid {
		counted.Reset()
		rec := postSBOM(t, router, body)
		expectError(t, rec, http.StatusBadRequest, "InvalidSbomInputError")
		assertErrorOnlyEnvelope(t, rec.Body.Bytes())
		if counters := counted.Snapshot(); counters.Selects != 0 {
			t.Fatalf("case %d reached storage: %+v", i, counters)
		}
	}

	// Nothing was registered.
	rec := getSBOMs(t, router, "/sboms?artifact=a")
	var page listResponse
	decodeBody(t, rec, &page)
	if page.Total != 0 || len(page.Items) != 0 {
		t.Fatalf("invalid registrations became visible: %+v", page)
	}

	// The same store still serves a valid request.
	if rec := postSBOM(t, router, `{"artifact":"a","version":"1","components":[]}`); rec.Code != http.StatusCreated {
		t.Fatalf("valid request after invalid ones: %d %s", rec.Code, rec.Body.String())
	}
}

// failingReader errors on every Read, simulating a request body that cannot be
// delivered (broken pipe, size limit, ...). The handler must answer the same
// 400 input error and must not touch storage.
type failingReader struct{}

func (failingReader) Read(_ []byte) (int, error) { return 0, io.ErrUnexpectedEOF }

func TestRequestBodyReadFailureReturns400(t *testing.T) {
	router, counted := newCountedRouter(t)

	req := httptest.NewRequest(http.MethodPost, "/sboms", failingReader{})
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	expectError(t, rec, http.StatusBadRequest, "InvalidSbomInputError")
	assertErrorOnlyEnvelope(t, rec.Body.Bytes())
	if counters := counted.Snapshot(); counters.Selects != 0 {
		t.Fatalf("storage was touched despite unreadable body: %+v", counters)
	}
}

// TestParsedInvalidInputIsTheHTTPError ties the two error identities together:
// the parser's failures must be errors.Is-recognizable as model.ErrInvalidInput,
// the very sentinel the handler maps onto 400 InvalidSbomInputError.
func TestParsedInvalidInputIsTheHTTPError(t *testing.T) {
	if _, err := manifest.ParseRegistration([]byte(`{}`)); !errors.Is(err, model.ErrInvalidInput) {
		t.Fatalf("parser error = %v, want model.ErrInvalidInput", err)
	}
	if _, err := manifest.ParseRegistration(nil); !errors.Is(err, model.ErrInvalidInput) {
		t.Fatalf("nil bytes error = %v, want model.ErrInvalidInput", err)
	}

	// Sanity: the handler renders that sentinel's code on the wire.
	router, _ := newTestRouter(t)
	rec := postSBOM(t, router, `{}`)
	if !bytes.Contains(rec.Body.Bytes(), []byte(`"InvalidSbomInputError"`)) {
		t.Fatalf("body = %s", rec.Body.String())
	}
}
