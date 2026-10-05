package model_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"testing"

	"github.com/xjeey8iust/sen-sbom-inventory/internal/model"
)

// ExampleParseSBOM shows the standalone registration-input entry point: raw
// JSON bytes in, a normalized model.SBOM with a zero ID out; any rejection is
// recognized with errors.Is(err, model.ErrInvalidInput).
func ExampleParseSBOM() {
	body := []byte(`{
		"artifact": "  atlas  ",
		"version": " 1.0 ",
		"components": [
			{"coordinate": " svc-b ", "license": " MIT ", "dependencies": []},
			{"coordinate": "svc-a", "license": "Apache-2.0", "dependencies": [" svc-b "]}
		]
	}`)
	sbom, err := model.ParseSBOM(body)
	if err != nil {
		if errors.Is(err, model.ErrInvalidInput) {
			fmt.Println("invalid input")
		}
		return
	}
	out, _ := json.Marshal(sbom)
	fmt.Println(string(out))
	// Output: {"id":0,"artifact":"atlas","version":"1.0","components":[{"coordinate":"svc-a","license":"Apache-2.0","dependencies":["svc-b"]},{"coordinate":"svc-b","license":"MIT","dependencies":[]}]}
}

// TestParseSBOMNormalizes feeds a payload with whitespace padding everywhere
// and shuffled arrays, and expects the canonical manifest: trimmed strings,
// components and dependencies sorted ascending, ID still zero.
func TestParseSBOMNormalizes(t *testing.T) {
	body := []byte(`{
		"artifact": "  atlas  ",
		"version": " 1.2.0 ",
		"components": [
			{"coordinate": " lib-z ", "license": " MIT ", "dependencies": [" lib-b ", "lib-a"]},
			{"coordinate": "lib-b", "license": "BSD-3-Clause", "dependencies": []},
			{"coordinate": "lib-a", "license": "Apache-2.0", "dependencies": ["lib-b"]}
		]
	}`)
	sbom, err := model.ParseSBOM(body)
	if err != nil {
		t.Fatalf("ParseSBOM: %v", err)
	}
	want := &model.SBOM{
		ID:       0,
		Artifact: "atlas",
		Version:  "1.2.0",
		Components: []model.Component{
			{Coordinate: "lib-a", License: "Apache-2.0", Dependencies: []string{"lib-b"}},
			{Coordinate: "lib-b", License: "BSD-3-Clause", Dependencies: []string{}},
			{Coordinate: "lib-z", License: "MIT", Dependencies: []string{"lib-a", "lib-b"}},
		},
	}
	if sbom.ID != 0 {
		t.Fatalf("id = %d, want zero before registration", sbom.ID)
	}
	if !reflect.DeepEqual(sbom, want) {
		t.Fatalf("parsed = %+v, want %+v", sbom, want)
	}
}

// TestParseSBOMEquivalentInputsNormalizeIdentically proves that whitespace
// and array order carry no meaning: two serializations of the same manifest
// parse to deeply equal results.
func TestParseSBOMEquivalentInputsNormalizeIdentically(t *testing.T) {
	compact := []byte(`{"artifact":"app","version":"1","components":[
		{"coordinate":"a","license":"L1","dependencies":["b","c"]},
		{"coordinate":"b","license":"L2","dependencies":["c"]},
		{"coordinate":"c","license":"L3","dependencies":[]}
	]}`)
	shuffled := []byte(`{ "artifact": " app ", "version": " 1 ", "components": [
		{"coordinate":"c","license":" L3 ","dependencies":[]},
		{"coordinate":"a","license":"L1","dependencies":["c","b"]},
		{"coordinate":" b ","license":" L2","dependencies":[" c "]}
	]}`)

	first, err := model.ParseSBOM(compact)
	if err != nil {
		t.Fatalf("compact: %v", err)
	}
	second, err := model.ParseSBOM(shuffled)
	if err != nil {
		t.Fatalf("shuffled: %v", err)
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("equivalent inputs differ:\n%+v\n%+v", first, second)
	}
}

// TestParseSBOMKeepsCaseAndInnerFormat pins that trimming is the only string
// transformation: case and inner whitespace survive.
func TestParseSBOMKeepsCaseAndInnerFormat(t *testing.T) {
	sbom, err := model.ParseSBOM([]byte(`{"artifact":" My App ","version":" 1.0 RC1 ","components":[
		{"coordinate":"pkg:Example/Lib","license":"Apache 2.0 WITH LLVM-exception","dependencies":[]}
	]}`))
	if err != nil {
		t.Fatalf("ParseSBOM: %v", err)
	}
	if sbom.Artifact != "My App" || sbom.Version != "1.0 RC1" {
		t.Fatalf("artifact/version = %q/%q", sbom.Artifact, sbom.Version)
	}
	comp := sbom.Components[0]
	if comp.Coordinate != "pkg:Example/Lib" || comp.License != "Apache 2.0 WITH LLVM-exception" {
		t.Fatalf("component = %+v", comp)
	}
}

// TestParseSBOMDoesNotMutateInput makes sure the input bytes are only read.
func TestParseSBOMDoesNotMutateInput(t *testing.T) {
	body := []byte(`{"artifact":" a ","version":" 1 ","components":[
		{"coordinate":" b ","license":" l ","dependencies":[]}
	]}`)
	before := bytes.Clone(body)
	if _, err := model.ParseSBOM(body); err != nil {
		t.Fatalf("ParseSBOM: %v", err)
	}
	if !bytes.Equal(body, before) {
		t.Fatalf("input changed: %q -> %q", before, body)
	}
}

// TestParseSBOMResultsAreIndependent proves calls share no state: mutating
// one returned manifest changes neither another call's result nor a fresh
// parse of the same input.
func TestParseSBOMResultsAreIndependent(t *testing.T) {
	body := []byte(`{"artifact":"app","version":"1","components":[
		{"coordinate":"a","license":"L1","dependencies":["b"]},
		{"coordinate":"b","license":"L2","dependencies":[]}
	]}`)
	first, err := model.ParseSBOM(body)
	if err != nil {
		t.Fatalf("first: %v", err)
	}
	second, err := model.ParseSBOM(body)
	if err != nil {
		t.Fatalf("second: %v", err)
	}

	first.Artifact = "MUTATED"
	first.Components[0].License = "MUTATED"
	first.Components[0].Dependencies[0] = "MUTATED"
	first.Components[1].Dependencies = append(first.Components[1].Dependencies, "MUTATED")

	want := &model.SBOM{
		Artifact: "app",
		Version:  "1",
		Components: []model.Component{
			{Coordinate: "a", License: "L1", Dependencies: []string{"b"}},
			{Coordinate: "b", License: "L2", Dependencies: []string{}},
		},
	}
	if !reflect.DeepEqual(second, want) {
		t.Fatalf("second result changed after mutating the first: %+v", second)
	}
	third, err := model.ParseSBOM(body)
	if err != nil {
		t.Fatalf("third: %v", err)
	}
	if !reflect.DeepEqual(third, want) {
		t.Fatalf("fresh parse changed after mutating an earlier result: %+v", third)
	}
}

// TestParseSBOMEmptyArraysStayArrays pins that empty components/dependencies
// arrays are legal and never become nil (which would serialize as null).
func TestParseSBOMEmptyArraysStayArrays(t *testing.T) {
	sbom, err := model.ParseSBOM([]byte(`{"artifact":"a","version":"1","components":[]}`))
	if err != nil {
		t.Fatalf("empty components: %v", err)
	}
	if sbom.Components == nil || len(sbom.Components) != 0 {
		t.Fatalf("components = %#v, want non-nil empty slice", sbom.Components)
	}

	sbom, err = model.ParseSBOM([]byte(`{"artifact":"a","version":"1","components":[
		{"coordinate":"c","license":"l","dependencies":[]}
	]}`))
	if err != nil {
		t.Fatalf("empty dependencies: %v", err)
	}
	if deps := sbom.Components[0].Dependencies; deps == nil || len(deps) != 0 {
		t.Fatalf("dependencies = %#v, want non-nil empty slice", deps)
	}
}

// TestParseSBOMForwardReferencesAndCycles pins that a dependency may name a
// component listed later in the input and that non-self cycles are valid.
func TestParseSBOMForwardReferencesAndCycles(t *testing.T) {
	sbom, err := model.ParseSBOM([]byte(`{"artifact":"app","version":"1","components":[
		{"coordinate":"a","license":"L","dependencies":["b"]},
		{"coordinate":"b","license":"L","dependencies":["a"]}
	]}`))
	if err != nil {
		t.Fatalf("cycle: %v", err)
	}
	if len(sbom.Components) != 2 ||
		len(sbom.Components[0].Dependencies) != 1 || sbom.Components[0].Dependencies[0] != "b" ||
		len(sbom.Components[1].Dependencies) != 1 || sbom.Components[1].Dependencies[0] != "a" {
		t.Fatalf("cycle edges wrong: %+v", sbom.Components)
	}
}

// TestParseSBOMIgnoresUnknownFields pins that extra keys at any level are
// skipped, matching the registration contract.
func TestParseSBOMIgnoresUnknownFields(t *testing.T) {
	sbom, err := model.ParseSBOM([]byte(`{
		"artifact": "a", "version": "1", "spec": "future",
		"components": [
			{"coordinate": "c", "license": "l", "dependencies": [], "homepage": "https://x"}
		],
		"metadata": {"nested": true}
	}`))
	if err != nil {
		t.Fatalf("ParseSBOM: %v", err)
	}
	if sbom.Artifact != "a" || len(sbom.Components) != 1 {
		t.Fatalf("parsed = %+v", sbom)
	}
}

// TestParseSBOMRejectsInvalidInput mirrors the HTTP rejection table: every
// shape must return a nil manifest and an error that errors.Is recognizes as
// model.ErrInvalidInput — and as no other sentinel.
func TestParseSBOMRejectsInvalidInput(t *testing.T) {
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
			sbom, err := model.ParseSBOM([]byte(body))
			if sbom != nil {
				t.Fatalf("sbom = %+v, want nil on invalid input", sbom)
			}
			if err == nil {
				t.Fatalf("err = nil, want ErrInvalidInput")
			}
			if !errors.Is(err, model.ErrInvalidInput) {
				t.Fatalf("err = %v, want errors.Is ErrInvalidInput", err)
			}
			for _, other := range []error{model.ErrConflict, model.ErrNotFound, model.ErrStorageUnavailable} {
				if errors.Is(err, other) {
					t.Fatalf("err = %v, must not match %v", err, other)
				}
			}
		})
	}
}
