package manifest

import (
	"bytes"
	"errors"
	"reflect"
	"testing"

	"github.com/xjeey8iust/sen-sbom-inventory/internal/model"
)

// validMessy is the canonical legal payload: padding on every business string
// and components/dependencies out of order, including a dependency that points
// at a component listed later.
const validMessy = `{
	"artifact": "  atlas  ",
	"version": " 1.2.0 ",
	"components": [
		{"coordinate": " lib-z ", "license": " MIT ", "dependencies": [" lib-a "]},
		{"coordinate": "lib-a", "license": "Apache-2.0", "dependencies": []}
	]
}`

// TestParseRegistrationNormalizes proves the standalone entry applies the
// documented rules: whitespace trimmed, case kept, components and per-component
// dependencies coordinate-sorted, empty arrays non-nil, ID left zero.
func TestParseRegistrationNormalizes(t *testing.T) {
	got, err := ParseRegistration([]byte(validMessy))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got == nil {
		t.Fatal("nil manifest on success")
	}
	if got.ID != 0 {
		t.Fatalf("id = %d, want zero (unregistered)", got.ID)
	}
	want := model.SBOM{
		Artifact: "atlas",
		Version:  "1.2.0",
		Components: []model.Component{
			{Coordinate: "lib-a", License: "Apache-2.0", Dependencies: []string{}},
			{Coordinate: "lib-z", License: "MIT", Dependencies: []string{"lib-a"}},
		},
	}
	if !reflect.DeepEqual(*got, want) {
		t.Fatalf("normalized manifest = %#v, want %#v", *got, want)
	}
	if got.Components == nil {
		t.Fatal("components nil, want empty-array-safe slice")
	}
	for i := range got.Components {
		if got.Components[i].Dependencies == nil {
			t.Fatalf("component %s dependencies nil, want [] not null", got.Components[i].Coordinate)
		}
	}
}

// TestParseEmptyArraysStayArrays checks the two legal empty shapes at the Go
// level: empty components and a component with empty dependencies.
func TestParseEmptyArraysStayArrays(t *testing.T) {
	got, err := ParseRegistration([]byte(`{"artifact":"a","version":"1","components":[]}`))
	if err != nil {
		t.Fatalf("empty components: %v", err)
	}
	if got.Components == nil || len(got.Components) != 0 {
		t.Fatalf("components = %#v, want non-nil empty", got.Components)
	}

	got, err = ParseRegistration([]byte(
		`{"artifact":"a","version":"1","components":[{"coordinate":"c","license":"l","dependencies":[]}]}`))
	if err != nil {
		t.Fatalf("empty dependencies: %v", err)
	}
	deps := got.Components[0].Dependencies
	if deps == nil || len(deps) != 0 {
		t.Fatalf("dependencies = %#v, want non-nil empty", deps)
	}
}

// TestParseAllowsForwardReferencesAndNonSelfCycles: a dependency may target a
// later component, and a non-self cycle is a valid manifest; self-dependency is
// rejected in the invalid table below.
func TestParseAllowsForwardReferencesAndNonSelfCycles(t *testing.T) {
	forward := []byte(`{"artifact":"a","version":"1","components":[
		{"coordinate":"a","license":"L","dependencies":["b"]},
		{"coordinate":"b","license":"L","dependencies":[]}
	]}`)
	if got, err := ParseRegistration(forward); err != nil {
		t.Fatalf("forward reference rejected: %v", err)
	} else if got.Components[0].Coordinate != "a" || got.Components[0].Dependencies[0] != "b" {
		t.Fatalf("forward edge lost: %+v", got.Components)
	}

	cycle := []byte(`{"artifact":"a","version":"1","components":[
		{"coordinate":"a","license":"L","dependencies":["b"]},
		{"coordinate":"b","license":"L","dependencies":["a"]}
	]}`)
	if got, err := ParseRegistration(cycle); err != nil {
		t.Fatalf("non-self cycle rejected: %v", err)
	} else if len(got.Components) != 2 {
		t.Fatalf("cycle components = %+v", got.Components)
	}
}

// TestParseRejectsInvalidInput mirrors the HTTP contract table: every rejected
// shape returns a nil manifest and an error errors.Is recognizes as
// model.ErrInvalidInput.
func TestParseRejectsInvalidInput(t *testing.T) {
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
		"null artifact":                `{"artifact":null,"version":"1","components":[]}`,
		"null version":                 `{"artifact":"a","version":null,"components":[]}`,
		"null components":              `{"artifact":"a","version":"1","components":null}`,
		"empty artifact":               `{"artifact":"","version":"1","components":[]}`,
		"blank version":                `{"artifact":"a","version":"   ","components":[]}`,
		"artifact wrong type":          `{"artifact":7,"version":"1","components":[]}`,
		"version wrong type":           `{"artifact":"a","version":true,"components":[]}`,
		"components wrong type":        `{"artifact":"a","version":"1","components":"x"}`,
		"component element scalar":     `{"artifact":"a","version":"1","components":["x"]}`,
		"component null element":       `{"artifact":"a","version":"1","components":[null]}`,
		"component missing coordinate": `{"artifact":"a","version":"1","components":[{"license":"l","dependencies":[]}]}`,
		"component missing license":    `{"artifact":"a","version":"1","components":[{"coordinate":"c","dependencies":[]}]}`,
		"component missing deps":       `{"artifact":"a","version":"1","components":[{"coordinate":"c","license":"l"}]}`,
		"null coordinate":              `{"artifact":"a","version":"1","components":[{"coordinate":null,"license":"l","dependencies":[]}]}`,
		"null license":                 `{"artifact":"a","version":"1","components":[{"coordinate":"c","license":null,"dependencies":[]}]}`,
		"null dependencies":            `{"artifact":"a","version":"1","components":[{"coordinate":"c","license":"l","dependencies":null}]}`,
		"empty coordinate":             `{"artifact":"a","version":"1","components":[{"coordinate":"  ","license":"l","dependencies":[]}]}`,
		"empty license":                `{"artifact":"a","version":"1","components":[{"coordinate":"c","license":"   ","dependencies":[]}]}`,
		"coordinate wrong type":        `{"artifact":"a","version":"1","components":[{"coordinate":1,"license":"l","dependencies":[]}]}`,
		"duplicate coordinates":        `{"artifact":"a","version":"1","components":[{"coordinate":"c","license":"l","dependencies":[]},{"coordinate":"c","license":"l","dependencies":[]}]}`,
		"duplicate after trimming":     `{"artifact":"a","version":"1","components":[{"coordinate":" c ","license":"l","dependencies":[]},{"coordinate":"c","license":"l","dependencies":[]}]}`,
		"duplicate dependency":         `{"artifact":"a","version":"1","components":[{"coordinate":"c","license":"l","dependencies":["x","x"]},{"coordinate":"x","license":"l","dependencies":[]}]}`,
		"duplicate dep after trimming": `{"artifact":"a","version":"1","components":[{"coordinate":"c","license":"l","dependencies":[" x ","x"]},{"coordinate":"x","license":"l","dependencies":[]}]}`,
		"self dependency":              `{"artifact":"a","version":"1","components":[{"coordinate":"c","license":"l","dependencies":["c"]}]}`,
		"self dep after trimming":      `{"artifact":"a","version":"1","components":[{"coordinate":"c","license":"l","dependencies":[" c "]}]}`,
		"empty dependency":             `{"artifact":"a","version":"1","components":[{"coordinate":"c","license":"l","dependencies":["  "]}]}`,
		"dependency wrong type":        `{"artifact":"a","version":"1","components":[{"coordinate":"c","license":"l","dependencies":[1]}]}`,
		"dependency null element":      `{"artifact":"a","version":"1","components":[{"coordinate":"c","license":"l","dependencies":[null]}]}`,
		"dangling dependency":          `{"artifact":"a","version":"1","components":[{"coordinate":"c","license":"l","dependencies":["ghost"]}]}`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			sbom, err := ParseRegistration([]byte(body))
			if err == nil {
				t.Fatalf("expected rejection, got %#v", sbom)
			}
			if !errors.Is(err, model.ErrInvalidInput) {
				t.Fatalf("error = %v, want errors.Is ErrInvalidInput", err)
			}
			if sbom != nil {
				t.Fatalf("invalid input returned non-nil manifest: %#v", sbom)
			}
		})
	}
}

// TestParseKeepsCaseAndUnknownFields: trimming never folds case, and fields the
// contract does not know are ignored rather than rejected.
func TestParseKeepsCaseAndUnknownFields(t *testing.T) {
	body := []byte(`{"artifact":" App ","extra":"ignored","version":"1","nested":{"x":[1,2]},"components":[
		{"coordinate":" Lib-A ","license":" Apache-2.0 ","dependencies":[],"notes":null}
	]}`)
	got, err := ParseRegistration(body)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got.Artifact != "App" {
		t.Fatalf("artifact = %q, want case preserved", got.Artifact)
	}
	if got.Components[0].Coordinate != "Lib-A" || got.Components[0].License != "Apache-2.0" {
		t.Fatalf("component casing lost: %+v", got.Components[0])
	}
}

// TestParseDoesNotMutateInput: the caller's byte slice must be byte-identical
// after a successful and after a failed parse.
func TestParseDoesNotMutateInput(t *testing.T) {
	for _, body := range []string{validMessy, `{"artifact":"a","version":"1","components":[]}`, `{broken`} {
		raw := []byte(body)
		snapshot := append([]byte(nil), raw...)
		_, _ = ParseRegistration(raw)
		if !bytes.Equal(raw, snapshot) {
			t.Fatalf("input bytes changed for %q", body)
		}
	}
}

// TestParseCallsAreIndependent: two parses never share slices, and mutating one
// result changes neither the input bytes nor later/earlier results.
func TestParseCallsAreIndependent(t *testing.T) {
	first, err := ParseRegistration([]byte(validMessy))
	if err != nil {
		t.Fatalf("first parse: %v", err)
	}
	second, err := ParseRegistration([]byte(validMessy))
	if err != nil {
		t.Fatalf("second parse: %v", err)
	}
	if first == second {
		t.Fatal("two parses returned the same manifest pointer")
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("same input parsed differently:\n%#v\n%#v", first, second)
	}

	// Mutate the first result in every reachable slice; the second result and
	// a fresh third parse must stay intact. Sorted order is lib-a, lib-z, and
	// only lib-z carries a dependency edge.
	first.Artifact = "changed"
	first.Components[0].Coordinate = "changed"
	first.Components[1].Dependencies[0] = "changed"
	first.Components = append(first.Components, model.Component{Coordinate: "z"})

	want, _ := ParseRegistration([]byte(validMessy))
	if !reflect.DeepEqual(second, want) {
		t.Fatalf("results share mutable state:\nsecond=%#v\nwant=%#v", second, want)
	}
}

// TestParseWhitespaceAndShuffleCanonicalizeEqually is the standalone half of
// the cross-path equivalence proof: the same manifest presented with padding
// and with shuffled arrays normalizes to one identical value.
func TestParseWhitespaceAndShuffleCanonicalizeEqually(t *testing.T) {
	messy := []byte(`{"artifact":" app ","version":" 1 ","components":[
		{"coordinate":"c","license":" L3 ","dependencies":[]},
		{"coordinate":"a","license":"L1","dependencies":["c","b"]},
		{"coordinate":"b","license":"L2","dependencies":["c"]}
	]}`)
	tidy := []byte(`{"artifact":"app","version":"1","components":[
		{"coordinate":"a","license":"L1","dependencies":["b","c"]},
		{"coordinate":"b","license":"L2","dependencies":["c"]},
		{"coordinate":"c","license":"L3","dependencies":[]}
	]}`)
	fromMessy, err := ParseRegistration(messy)
	if err != nil {
		t.Fatalf("messy: %v", err)
	}
	fromTidy, err := ParseRegistration(tidy)
	if err != nil {
		t.Fatalf("tidy: %v", err)
	}
	if !reflect.DeepEqual(fromMessy, fromTidy) {
		t.Fatalf("normalized manifests differ:\n%#v\n%#v", fromMessy, fromTidy)
	}
}
