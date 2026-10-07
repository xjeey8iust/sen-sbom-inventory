package manifest

import (
	"bytes"
	"encoding/json"
	"errors"
	"reflect"
	"testing"

	"github.com/xjeey8iust/sen-sbom-inventory/internal/model"
)

// compareV1 and compareV2 are the canonical pair: one removed component, one
// added, one license change, one direct-edge change, one untouched component
// whose dependency target changed (no propagation), and a non-self cycle that
// keeps its shape. Registration payloads stay shuffled on purpose.
const compareV1 = `{"artifact":"app","version":"1","components":[
	{"coordinate":"gone","license":"G","dependencies":[]},
	{"coordinate":"stable","license":"S","dependencies":[]},
	{"coordinate":"rel","license":"OLD","dependencies":["stable"]},
	{"coordinate":"edge","license":"E","dependencies":["stable"]},
	{"coordinate":"watcher","license":"W","dependencies":["rel"]},
	{"coordinate":"cyc-a","license":"CA","dependencies":["cyc-b"]},
	{"coordinate":"cyc-b","license":"CB","dependencies":["cyc-a"]}
]}`

const compareV2 = `{"artifact":"app","version":"2","components":[
	{"coordinate":"born","license":"B","dependencies":[]},
	{"coordinate":"stable","license":"S","dependencies":[]},
	{"coordinate":"rel","license":"NEW","dependencies":["stable"]},
	{"coordinate":"edge","license":"E","dependencies":["born","stable"]},
	{"coordinate":"watcher","license":"W","dependencies":["rel"]},
	{"coordinate":"cyc-a","license":"CA","dependencies":["cyc-b"]},
	{"coordinate":"cyc-b","license":"CB","dependencies":["cyc-a"]}
]}`

func mustParse(t *testing.T, body string) *model.SBOM {
	t.Helper()
	sbom, err := ParseRegistration([]byte(body))
	if err != nil {
		t.Fatalf("parse fixture: %v", err)
	}
	return sbom
}

func mustCompare(t *testing.T, before, after *model.SBOM) *Diff {
	t.Helper()
	diff, err := Compare(before, after)
	if err != nil {
		t.Fatalf("compare: %v", err)
	}
	if diff == nil {
		t.Fatal("nil result on success")
	}
	return diff
}

func coordinates(components []model.Component) []string {
	out := make([]string, len(components))
	for i, comp := range components {
		out[i] = comp.Coordinate
	}
	return out
}

// TestComparePartitionsAndSorts drives the core rule set through the
// standalone entry: added/removed/changed by coordinate presence, license and
// direct dependency set; sorted arrays; complete before/after; no propagation
// onto watcher; the untouched cycle stays out.
func TestComparePartitionsAndSorts(t *testing.T) {
	diff := mustCompare(t, mustParse(t, compareV1), mustParse(t, compareV2))

	if diff.Artifact != "app" || diff.FromVersion != "1" || diff.ToVersion != "2" {
		t.Fatalf("identifiers = %+v", diff)
	}
	if got := coordinates(diff.Added); !reflect.DeepEqual(got, []string{"born"}) {
		t.Fatalf("added = %v", got)
	}
	if got := coordinates(diff.Removed); !reflect.DeepEqual(got, []string{"gone"}) {
		t.Fatalf("removed = %v", got)
	}
	wantChanged := []string{"edge", "rel"}
	gotChanged := make([]string, len(diff.Changed))
	for i, ch := range diff.Changed {
		gotChanged[i] = ch.Coordinate
	}
	if !reflect.DeepEqual(gotChanged, wantChanged) {
		t.Fatalf("changed = %v, want %v", gotChanged, wantChanged)
	}
	byCoordinate := map[string]ComponentChange{}
	for _, ch := range diff.Changed {
		byCoordinate[ch.Coordinate] = ch
	}
	rel := byCoordinate["rel"]
	if rel.Before.License != "OLD" || rel.After.License != "NEW" {
		t.Fatalf("rel licenses = %q/%q", rel.Before.License, rel.After.License)
	}
	edge := byCoordinate["edge"]
	if !reflect.DeepEqual(edge.After.Dependencies, []string{"born", "stable"}) {
		t.Fatalf("edge after dependencies = %v", edge.After.Dependencies)
	}
	if edge.Before.License != "E" || edge.After.License != "E" {
		t.Fatalf("edge-only change must carry the license on both sides: %+v", edge)
	}
}

// TestCompareRejectsNilAndForeignManifests covers the two rejection shapes:
// a nil side and two manifests of different artifacts. Both yield a nil
// result and an errors.Is-recognizable model.ErrInvalidInput.
func TestCompareRejectsNilAndForeignManifests(t *testing.T) {
	valid := mustParse(t, compareV1)

	for name, pair := range map[string][2]*model.SBOM{
		"nil before": {nil, valid},
		"nil after":  {valid, nil},
		"both nil":   {nil, nil},
	} {
		diff, err := Compare(pair[0], pair[1])
		if diff != nil {
			t.Fatalf("%s: result = %+v, want nil", name, diff)
		}
		if !errors.Is(err, model.ErrInvalidInput) {
			t.Fatalf("%s: error = %v, want model.ErrInvalidInput", name, err)
		}
	}

	other := mustParse(t, `{"artifact":"other","version":"1","components":[]}`)
	for name, pair := range map[string][2]*model.SBOM{
		"different artifact":          {valid, other},
		"different artifact reversed": {other, valid},
	} {
		diff, err := Compare(pair[0], pair[1])
		if diff != nil {
			t.Fatalf("%s: result = %+v, want nil", name, diff)
		}
		if !errors.Is(err, model.ErrInvalidInput) {
			t.Fatalf("%s: error = %v, want model.ErrInvalidInput", name, err)
		}
	}

	// Artifact comparison is exact and case-sensitive, like the HTTP lookup.
	upper := mustParse(t, `{"artifact":"APP","version":"1","components":[]}`)
	if _, err := Compare(valid, upper); !errors.Is(err, model.ErrInvalidInput) {
		t.Fatalf("case-different artifact: error = %v, want model.ErrInvalidInput", err)
	}
}

// TestCompareSelfYieldsThreeEmptyArrays: the same object compared with itself
// — and with an identical copy — produces three empty, non-nil arrays.
func TestCompareSelfYieldsThreeEmptyArrays(t *testing.T) {
	sbom := mustParse(t, compareV1)

	for name, pair := range map[string][2]*model.SBOM{
		"same object":  {sbom, sbom},
		"same content": {sbom, mustParse(t, compareV1)},
	} {
		diff := mustCompare(t, pair[0], pair[1])
		if diff.Added == nil || diff.Removed == nil || diff.Changed == nil {
			t.Fatalf("%s: arrays must be empty, never nil: %+v", name, diff)
		}
		if len(diff.Added) != 0 || len(diff.Removed) != 0 || len(diff.Changed) != 0 {
			t.Fatalf("%s: self diff = %+v, want all empty", name, diff)
		}
		if diff.FromVersion != "1" || diff.ToVersion != "1" {
			t.Fatalf("%s: self diff versions = %q/%q", name, diff.FromVersion, diff.ToVersion)
		}
	}
}

// TestCompareIgnoresIDsAndTreatsVersionsAsLabels: the store-assigned ID never
// enters the result or the content judgment, and versions are only copied as
// identifiers — never ordered, never compared.
func TestCompareIgnoresIDsAndTreatsVersionsAsLabels(t *testing.T) {
	older := mustParse(t, compareV1)
	newer := mustParse(t, compareV1)
	older.ID, newer.ID = 7, 99
	// Deliberately "backwards" version labels: identical content still diffs
	// empty, and the labels are echoed as given.
	older.Version, newer.Version = "2", "1"

	diff := mustCompare(t, older, newer)
	if len(diff.Added) != 0 || len(diff.Removed) != 0 || len(diff.Changed) != 0 {
		t.Fatalf("identical content with different ids differs: %+v", diff)
	}
	if diff.FromVersion != "2" || diff.ToVersion != "1" {
		t.Fatalf("versions not echoed as identifiers: %+v", diff)
	}

	raw, err := json.Marshal(diff)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if bytes.Contains(raw, []byte(`"id"`)) {
		t.Fatalf("manifest id leaked into result: %s", raw)
	}
}

// TestCompareArrayOrderIsIrrelevant shuffles component order and dependency
// order on both sides: the result is identical to the canonical comparison,
// and the emitted dependency lists come out sorted.
func TestCompareArrayOrderIsIrrelevant(t *testing.T) {
	before := mustParse(t, compareV1)
	after := mustParse(t, compareV2)
	want := mustCompare(t, before, after)

	shuffledBefore := mustParse(t, compareV1)
	shuffledAfter := mustParse(t, compareV2)
	reverseComponents(shuffledBefore.Components)
	reverseComponents(shuffledAfter.Components)
	for i := range shuffledAfter.Components {
		deps := shuffledAfter.Components[i].Dependencies
		for l, r := 0, len(deps)-1; l < r; l, r = l+1, r-1 {
			deps[l], deps[r] = deps[r], deps[l]
		}
	}

	got := mustCompare(t, shuffledBefore, shuffledAfter)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("shuffled inputs changed the result:\ngot:  %#v\nwant: %#v", got, want)
	}
}

func reverseComponents(components []model.Component) {
	for l, r := 0, len(components)-1; l < r; l, r = l+1, r-1 {
		components[l], components[r] = components[r], components[l]
	}
}

// TestCompareDependenciesComparedAsSets: the same direct targets in a
// different order are not a change; a dropped target is.
func TestCompareDependenciesComparedAsSets(t *testing.T) {
	before := &model.SBOM{Artifact: "app", Version: "1", Components: []model.Component{
		{Coordinate: "a", License: "L", Dependencies: []string{"x", "y", "z"}},
	}}
	after := &model.SBOM{Artifact: "app", Version: "2", Components: []model.Component{
		{Coordinate: "a", License: "L", Dependencies: []string{"z", "x", "y"}},
	}}
	diff := mustCompare(t, before, after)
	if len(diff.Changed) != 0 {
		t.Fatalf("shuffled same dependency set reported as changed: %+v", diff.Changed)
	}

	after.Components[0].Dependencies = []string{"x", "y"}
	diff = mustCompare(t, before, after)
	if len(diff.Changed) != 1 || diff.Changed[0].Coordinate != "a" {
		t.Fatalf("dropped dependency not detected: %+v", diff.Changed)
	}
	// The emitted after side carries the sorted, complete dependency list.
	if !reflect.DeepEqual(diff.Changed[0].After.Dependencies, []string{"x", "y"}) {
		t.Fatalf("after dependencies = %v", diff.Changed[0].After.Dependencies)
	}
	if !reflect.DeepEqual(diff.Changed[0].Before.Dependencies, []string{"x", "y", "z"}) {
		t.Fatalf("before dependencies = %v", diff.Changed[0].Before.Dependencies)
	}
}

// TestCompareRenameIsRemovePlusAdd: the same component under a new coordinate
// is one removed plus one added, never a change.
func TestCompareRenameIsRemovePlusAdd(t *testing.T) {
	before := mustParse(t, `{"artifact":"app","version":"1","components":[
		{"coordinate":"old-name","license":"MIT","dependencies":[]}]}`)
	after := mustParse(t, `{"artifact":"app","version":"2","components":[
		{"coordinate":"new-name","license":"MIT","dependencies":[]}]}`)

	diff := mustCompare(t, before, after)
	if len(diff.Removed) != 1 || diff.Removed[0].Coordinate != "old-name" {
		t.Fatalf("removed = %+v", diff.Removed)
	}
	if len(diff.Added) != 1 || diff.Added[0].Coordinate != "new-name" {
		t.Fatalf("added = %+v", diff.Added)
	}
	if len(diff.Changed) != 0 {
		t.Fatalf("rename produced changed entries: %+v", diff.Changed)
	}
}

// TestCompareReverseSwapsSides: swapping the inputs swaps added with removed
// and flips every changed entry's before/after; identifiers follow the inputs.
func TestCompareReverseSwapsSides(t *testing.T) {
	before, after := mustParse(t, compareV1), mustParse(t, compareV2)
	forward := mustCompare(t, before, after)
	reverse := mustCompare(t, after, before)

	if reverse.Artifact != forward.Artifact ||
		reverse.FromVersion != forward.ToVersion || reverse.ToVersion != forward.FromVersion {
		t.Fatalf("reversed identifiers = %+v, want swapped %+v", reverse, forward)
	}
	if !reflect.DeepEqual(reverse.Added, forward.Removed) {
		t.Fatalf("reversed added = %+v, want forward removed %+v", reverse.Added, forward.Removed)
	}
	if !reflect.DeepEqual(reverse.Removed, forward.Added) {
		t.Fatalf("reversed removed = %+v, want forward added %+v", reverse.Removed, forward.Added)
	}
	if len(reverse.Changed) != len(forward.Changed) {
		t.Fatalf("reversed changed = %+v, want %d entries", reverse.Changed, len(forward.Changed))
	}
	for i, ch := range forward.Changed {
		got := reverse.Changed[i]
		if got.Coordinate != ch.Coordinate {
			t.Fatalf("changed order differs at %d: %q vs %q", i, got.Coordinate, ch.Coordinate)
		}
		if !reflect.DeepEqual(got.Before, ch.After) || !reflect.DeepEqual(got.After, ch.Before) {
			t.Fatalf("changed %s not flipped:\nforward: %+v\nreverse: %+v", ch.Coordinate, ch, got)
		}
	}
}

// TestCompareEmptyArraysSerializeAsArrays pins the wire shape of the library
// result: every diff array marshals as [], never null.
func TestCompareEmptyArraysSerializeAsArrays(t *testing.T) {
	empty1 := mustParse(t, `{"artifact":"app","version":"1","components":[]}`)
	empty2 := mustParse(t, `{"artifact":"app","version":"2","components":[]}`)

	raw, err := json.Marshal(mustCompare(t, empty1, empty2))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, field := range []string{`"added":[]`, `"removed":[]`, `"changed":[]`} {
		if !bytes.Contains(raw, []byte(field)) {
			t.Fatalf("marshalled diff missing %s: %s", field, raw)
		}
	}
}

// TestCompareDoesNotShareMemory proves isolation in both directions: Compare
// leaves its inputs untouched, later mutations of the inputs cannot change an
// already returned result, and mutating a result cannot affect the inputs or
// another call's result.
func TestCompareDoesNotShareMemory(t *testing.T) {
	before, after := mustParse(t, compareV1), mustParse(t, compareV2)
	beforeSnapshot := mustParse(t, compareV1)
	afterSnapshot := mustParse(t, compareV2)

	first := mustCompare(t, before, after)
	firstSnapshot := mustCompare(t, before, after)

	// Mutating the result must not reach the inputs or a fresh comparison.
	first.Added[0].License = "MUTATED"
	first.Added[0].Dependencies = append(first.Added[0].Dependencies, "MUTATED")
	first.Removed[0].License = "MUTATED"
	first.Changed[0].Before.License = "MUTATED"
	first.Changed[0].After.Dependencies[0] = "MUTATED"
	if !reflect.DeepEqual(*before, *beforeSnapshot) || !reflect.DeepEqual(*after, *afterSnapshot) {
		t.Fatalf("result mutation leaked into inputs:\nbefore: %#v\nafter:  %#v", before, after)
	}
	second := mustCompare(t, before, after)
	if !reflect.DeepEqual(second, firstSnapshot) {
		t.Fatalf("result mutation affected a later call:\ngot:  %#v\nwant: %#v", second, firstSnapshot)
	}

	// Mutating the inputs afterwards must not rewrite the returned result.
	before.Components[0].License = "MUTATED"
	before.Components[0].Dependencies[0] = "MUTATED"
	after.Components[0].Coordinate = "MUTATED"
	if !reflect.DeepEqual(second, firstSnapshot) {
		t.Fatalf("input mutation changed the returned result:\ngot:  %#v\nwant: %#v", second, firstSnapshot)
	}
}
