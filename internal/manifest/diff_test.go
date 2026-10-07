package manifest

import (
	"encoding/json"
	"errors"
	"reflect"
	"testing"

	"github.com/xjeey8iust/sen-sbom-inventory/internal/model"
)

// parseForCompare parses a legal registration payload into a manifest that
// can be compared directly, mirroring how the HTTP handler obtains the
// before/after manifests without going through storage.
func parseForCompare(t *testing.T, raw string) *model.SBOM {
	t.Helper()
	sbom, err := ParseRegistration([]byte(raw))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return sbom
}

// TestComparePartitionsAddedRemovedChanged drives the full comparison
// contract: added/removed/changed are coordinate-sorted and changed
// entries carry the complete before/after components.
func TestComparePartitionsAddedRemovedChanged(t *testing.T) {
	before := parseForCompare(t, `{"artifact":"app","version":"1","components":[
		{"coordinate":"gone","license":"G","dependencies":[]},
		{"coordinate":"stable","license":"S","dependencies":[]},
		{"coordinate":"moved-edge","license":"M","dependencies":["stable"]},
		{"coordinate":"rel","license":"OLD","dependencies":["stable"]},
		{"coordinate":"zeta-change","license":"Z","dependencies":[]},
		{"coordinate":"alpha-change","license":"A","dependencies":[]}
	]}`)
	after := parseForCompare(t, `{"artifact":"app","version":"2","components":[
		{"coordinate":"born","license":"B","dependencies":[]},
		{"coordinate":"stable","license":"S","dependencies":[]},
		{"coordinate":"moved-edge","license":"M","dependencies":["born","stable"]},
		{"coordinate":"rel","license":"NEW","dependencies":["stable"]},
		{"coordinate":"zeta-change","license":"Z","dependencies":["stable"]},
		{"coordinate":"alpha-change","license":"A2","dependencies":[]}
	]}`)

	got, err := Compare(before, after)
	if err != nil {
		t.Fatalf("compare: %v", err)
	}
	if got == nil {
		t.Fatal("nil diff on success")
	}
	if got.Artifact != "app" || got.FromVersion != "1" || got.ToVersion != "2" {
		t.Fatalf("labels = %+v", got)
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
	byCoord := map[string]ComponentChange{}
	for _, ch := range got.Changed {
		byCoord[ch.Coordinate] = ch
	}
	if byCoord["rel"].Before.License != "OLD" || byCoord["rel"].After.License != "NEW" {
		t.Fatalf("rel before/after licenses = %q/%q", byCoord["rel"].Before.License, byCoord["rel"].After.License)
	}
	edge := byCoord["moved-edge"]
	if !reflect.DeepEqual(edge.Before.Dependencies, []string{"stable"}) {
		t.Fatalf("moved-edge before = %+v", edge.Before)
	}
	if !reflect.DeepEqual(edge.After.Dependencies, []string{"born", "stable"}) {
		t.Fatalf("moved-edge after = %+v, want full sorted component", edge.After)
	}
	// License must be carried on both sides of an edge-only change.
	if edge.Before.License != "M" || edge.After.License != "M" {
		t.Fatalf("moved-edge licenses = %q/%q", edge.Before.License, edge.After.License)
	}
}

// TestCompareOrderIndependent proves neither component array order nor
// dependency array order affects the result: reordered inputs compare as
// unchanged, and result dependency arrays come out coordinate-sorted.
func TestCompareOrderIndependent(t *testing.T) {
	before := &model.SBOM{Artifact: "app", Version: "1", Components: []model.Component{
		{Coordinate: "z", License: "L", Dependencies: []string{"m", "a"}},
		{Coordinate: "a", License: "L", Dependencies: []string{"z"}},
		{Coordinate: "m", License: "L", Dependencies: []string{"a", "z"}},
	}}
	after := &model.SBOM{Artifact: "app", Version: "2", Components: []model.Component{
		{Coordinate: "m", License: "L", Dependencies: []string{"z", "a"}},
		{Coordinate: "z", License: "L", Dependencies: []string{"a", "m"}},
		{Coordinate: "a", License: "L", Dependencies: []string{"z"}},
	}}

	got, err := Compare(before, after)
	if err != nil {
		t.Fatalf("compare: %v", err)
	}
	if len(got.Added) != 0 || len(got.Removed) != 0 || len(got.Changed) != 0 {
		t.Fatalf("reordered identical manifests reported as changed: %+v", got)
	}

	// Now actually change one dependency set while keeping it unsorted in
	// the input; the result must still detect it and sort the edges.
	after.Components[0].Dependencies = []string{"z", "a", "new-edge"}
	after.Components = append(after.Components,
		model.Component{Coordinate: "new-edge", License: "N", Dependencies: []string{}})
	got, err = Compare(before, after)
	if err != nil {
		t.Fatalf("compare: %v", err)
	}
	if len(got.Added) != 1 || got.Added[0].Coordinate != "new-edge" {
		t.Fatalf("added = %+v, want new-edge", got.Added)
	}
	if !reflect.DeepEqual(got.Added[0].Dependencies, []string{}) {
		t.Fatalf("added dependencies = %+v, want empty non-nil", got.Added[0].Dependencies)
	}
	if len(got.Changed) != 1 || got.Changed[0].Coordinate != "m" {
		t.Fatalf("changed = %+v, want only m", got.Changed)
	}
	if !reflect.DeepEqual(got.Changed[0].After.Dependencies, []string{"a", "new-edge", "z"}) {
		t.Fatalf("changed dependencies not sorted: %+v", got.Changed[0].After.Dependencies)
	}
}

// TestCompareReversedSwapsSides proves the comparison carries no direction
// semantics: swapping the inputs swaps added/removed and swaps the
// before/after of every changed entry.
func TestCompareReversedSwapsSides(t *testing.T) {
	forward := parseForCompare(t, `{"artifact":"app","version":"1","components":[
		{"coordinate":"gone","license":"OLD","dependencies":["keep"]},
		{"coordinate":"keep","license":"K","dependencies":[]}
	]}`)
	reverse := parseForCompare(t, `{"artifact":"app","version":"2","components":[
		{"coordinate":"born","license":"NEW","dependencies":["keep"]},
		{"coordinate":"keep","license":"K","dependencies":["born"]}
	]}`)

	aToB, err := Compare(forward, reverse)
	if err != nil {
		t.Fatalf("compare forward: %v", err)
	}
	bToA, err := Compare(reverse, forward)
	if err != nil {
		t.Fatalf("compare reverse: %v", err)
	}

	if len(aToB.Added) != 1 || aToB.Added[0].Coordinate != "born" {
		t.Fatalf("forward added = %+v", aToB.Added)
	}
	if len(aToB.Removed) != 1 || aToB.Removed[0].Coordinate != "gone" {
		t.Fatalf("forward removed = %+v", aToB.Removed)
	}
	if len(aToB.Changed) != 1 || aToB.Changed[0].Coordinate != "keep" {
		t.Fatalf("forward changed = %+v, want keep (edge gained)", aToB.Changed)
	}
	if !reflect.DeepEqual(aToB.Changed[0].Before.Dependencies, []string{}) ||
		!reflect.DeepEqual(aToB.Changed[0].After.Dependencies, []string{"born"}) {
		t.Fatalf("forward keep sides = %+v", aToB.Changed[0])
	}

	// Reversed: added/removed swap and labels/changed sides swap.
	if len(bToA.Added) != 1 || bToA.Added[0].Coordinate != "gone" {
		t.Fatalf("reversed added = %+v, want gone", bToA.Added)
	}
	if len(bToA.Removed) != 1 || bToA.Removed[0].Coordinate != "born" {
		t.Fatalf("reversed removed = %+v, want born", bToA.Removed)
	}
	if len(bToA.Changed) != 1 || bToA.Changed[0].Coordinate != "keep" {
		t.Fatalf("reversed changed = %+v, want keep", bToA.Changed)
	}
	if !reflect.DeepEqual(bToA.Changed[0].Before.Dependencies, []string{"born"}) ||
		!reflect.DeepEqual(bToA.Changed[0].After.Dependencies, []string{}) {
		t.Fatalf("reversed keep sides not swapped: %+v", bToA.Changed[0])
	}
	if bToA.Artifact != "app" || bToA.FromVersion != "2" || bToA.ToVersion != "1" {
		t.Fatalf("reversed labels = %+v", bToA)
	}
	if !reflect.DeepEqual(aToB.Changed[0].Before, bToA.Changed[0].After) ||
		!reflect.DeepEqual(aToB.Changed[0].After, bToA.Changed[0].Before) {
		t.Fatal("reversed changed before/after are not the forward after/before")
	}
}

// TestCompareSelfReturnsThreeEmptyArrays: the same manifest compared with
// itself produces three empty (non-nil) arrays.
func TestCompareSelfReturnsThreeEmptyArrays(t *testing.T) {
	sbom := parseForCompare(t, `{"artifact":"app","version":"1","components":[
		{"coordinate":"a","license":"L","dependencies":["b"]},
		{"coordinate":"b","license":"L","dependencies":["a"]}
	]}`)

	got, err := Compare(sbom, sbom)
	if err != nil {
		t.Fatalf("self compare: %v", err)
	}
	if got.Artifact != "app" || got.FromVersion != "1" || got.ToVersion != "1" {
		t.Fatalf("labels = %+v", got)
	}
	if len(got.Added) != 0 || len(got.Removed) != 0 || len(got.Changed) != 0 {
		t.Fatalf("self diff = %+v, want all empty", got)
	}
	if got.Added == nil || got.Removed == nil || got.Changed == nil {
		t.Fatalf("nil arrays: %+v", got)
	}
}

// TestCompareEmptyManifestsSerializeAsEmptyArrays covers the empty
// manifest case and proves every diff array marshals as [] not null.
func TestCompareEmptyManifestsSerializeAsEmptyArrays(t *testing.T) {
	before := parseForCompare(t, `{"artifact":"app","version":"1","components":[]}`)
	after := parseForCompare(t, `{"artifact":"app","version":"2","components":[]}`)

	got, err := Compare(before, after)
	if err != nil {
		t.Fatalf("compare: %v", err)
	}
	raw, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var wire map[string]json.RawMessage
	if err := json.Unmarshal(raw, &wire); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, name := range []string{"added", "removed", "changed"} {
		if string(wire[name]) != "[]" {
			t.Fatalf("%s serialized as %s, want []", name, wire[name])
		}
	}
}

// TestCompareRejectsNilAndMismatchedArtifact covers the two caller
// errors: a nil side and two manifests of different artifacts. Both
// return nil with model.ErrInvalidInput and never inspect components.
func TestCompareRejectsNilAndMismatchedArtifact(t *testing.T) {
	valid := parseForCompare(t, `{"artifact":"app","version":"1","components":[]}`)
	other := parseForCompare(t, `{"artifact":"ghost","version":"2","components":[]}`)

	cases := []struct {
		name   string
		before *model.SBOM
		after  *model.SBOM
	}{
		{"both nil", nil, nil},
		{"nil before", nil, valid},
		{"nil after", valid, nil},
		{"artifact mismatch", valid, other},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Compare(tc.before, tc.after)
			if got != nil {
				t.Fatalf("result = %+v, want nil", got)
			}
			if !errors.Is(err, model.ErrInvalidInput) {
				t.Fatalf("err = %v, want ErrInvalidInput", err)
			}
		})
	}
}

// TestCompareLabelsComeFromInputsAndIDStaysOut verifies the result is
// labeled from the inputs and that database IDs never enter it, neither as
// a field nor as part of the comparison (two manifests with different IDs
// but identical content compare equal).
func TestCompareLabelsComeFromInputsAndIDStaysOut(t *testing.T) {
	before := parseForCompare(t, `{"artifact":"app","version":"1","components":[
		{"coordinate":"a","license":"L","dependencies":[]}
	]}`)
	after := parseForCompare(t, `{"artifact":"app","version":"2","components":[
		{"coordinate":"a","license":"L","dependencies":[]}
	]}`)
	before.ID = 42
	after.ID = 99

	got, err := Compare(before, after)
	if err != nil {
		t.Fatalf("compare: %v", err)
	}
	if got.Artifact != "app" || got.FromVersion != "1" || got.ToVersion != "2" {
		t.Fatalf("labels = %+v", got)
	}
	raw, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var wire map[string]json.RawMessage
	if err := json.Unmarshal(raw, &wire); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, present := wire["id"]; present {
		t.Fatalf("id leaked into result JSON: %s", raw)
	}
}

// TestCompareDoesNotMutateInputsAndResultsAreIsolated proves the
// comparison is read-only over its inputs and that components and
// dependencies returned in one result share no storage with the inputs or
// with results of later calls.
func TestCompareDoesNotMutateInputsAndResultsAreIsolated(t *testing.T) {
	parsePair := func() (before, after *model.SBOM) {
		return parseForCompare(t, `{"artifact":"app","version":"1","components":[
				{"coordinate":"a","license":"L","dependencies":["b"]},
				{"coordinate":"b","license":"OLD","dependencies":[]}
			]}`),
			parseForCompare(t, `{"artifact":"app","version":"2","components":[
				{"coordinate":"a","license":"L","dependencies":["b","c"]},
				{"coordinate":"b","license":"NEW","dependencies":[]},
				{"coordinate":"c","license":"C","dependencies":[]}
			]}`)
	}

	before, after := parsePair()
	beforeSnapshot, afterSnapshot := *before, *after

	first, err := Compare(before, after)
	if err != nil {
		t.Fatalf("compare: %v", err)
	}
	// Compare itself leaves both inputs exactly as passed in.
	if !reflect.DeepEqual(*before, beforeSnapshot) {
		t.Fatalf("Compare mutated before:\ngot  %+v\nwant %+v", *before, beforeSnapshot)
	}
	if !reflect.DeepEqual(*after, afterSnapshot) {
		t.Fatalf("Compare mutated after:\ngot  %+v\nwant %+v", *after, afterSnapshot)
	}

	// Mutate the inputs after the call: result backing arrays must not be
	// shared with them.
	before.Components[0].Dependencies[0] = "TAMPERED"
	before.Components[1].License = "TAMPERED"
	before.Components = append(before.Components,
		model.Component{Coordinate: "extra", License: "X", Dependencies: []string{}})
	after.Components[0].Dependencies = append(after.Components[0].Dependencies, "TAMPERED")

	if len(first.Changed) != 2 ||
		first.Changed[0].Coordinate != "a" || first.Changed[1].Coordinate != "b" {
		t.Fatalf("changed = %+v, want a (edge added) and b (license)", first.Changed)
	}
	changedA, changedB := first.Changed[0], first.Changed[1]
	if changedA.Before.License != "L" || changedA.After.License != "L" ||
		!reflect.DeepEqual(changedA.Before.Dependencies, []string{"b"}) ||
		!reflect.DeepEqual(changedA.After.Dependencies, []string{"b", "c"}) {
		t.Fatalf("changed a sides wrong: %+v", changedA)
	}
	if changedB.Before.License != "OLD" || changedB.After.License != "NEW" {
		t.Fatalf("changed b sides reached input mutations: %+v", changedB)
	}
	if len(first.Removed) != 0 {
		t.Fatalf("removed = %+v, want empty (b changed, c added)", first.Removed)
	}
	if first.Added[0].Coordinate != "c" {
		t.Fatalf("added result wrong: %+v", first.Added)
	}

	// Mutate the returned result, then run the same comparison on fresh
	// inputs: the second result must not see the first result's mutations.
	first.Added[0].License = "TAMPERED"
	first.Added[0].Dependencies = append(first.Added[0].Dependencies, "TAMPERED")
	first.Changed[0].Before.Coordinate = "TAMPERED"
	secondBefore, secondAfter := parsePair()
	second, err := Compare(secondBefore, secondAfter)
	if err != nil {
		t.Fatalf("second compare: %v", err)
	}
	if !reflect.DeepEqual(second.Added, []model.Component{
		{Coordinate: "c", License: "C", Dependencies: []string{}},
	}) {
		t.Fatalf("second result affected by mutating first: %+v", second.Added)
	}
}

// TestCompareRenameIsRemovePlusAdd: the same component under a new
// coordinate is one removed plus one added, never a change.
func TestCompareRenameIsRemovePlusAdd(t *testing.T) {
	before := parseForCompare(t, `{"artifact":"app","version":"1","components":[
		{"coordinate":"old-name","license":"MIT","dependencies":[]}
	]}`)
	after := parseForCompare(t, `{"artifact":"app","version":"2","components":[
		{"coordinate":"new-name","license":"MIT","dependencies":[]}
	]}`)

	got, err := Compare(before, after)
	if err != nil {
		t.Fatalf("compare: %v", err)
	}
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

// TestCompareOnlyDirectRelationsAndNoPropagation: a license change on a
// dependency target and a transitive edge change deeper in the graph must
// not mark the referencing components as changed.
func TestCompareOnlyDirectRelationsAndNoPropagation(t *testing.T) {
	before := parseForCompare(t, `{"artifact":"app","version":"1","components":[
		{"coordinate":"a","license":"L","dependencies":["b"]},
		{"coordinate":"b","license":"L","dependencies":["c"]},
		{"coordinate":"c","license":"OLD","dependencies":[]}
	]}`)
	after := parseForCompare(t, `{"artifact":"app","version":"2","components":[
		{"coordinate":"a","license":"L","dependencies":["b"]},
		{"coordinate":"b","license":"L","dependencies":["c"]},
		{"coordinate":"c","license":"NEW","dependencies":["d"]},
		{"coordinate":"d","license":"L","dependencies":[]}
	]}`)

	got, err := Compare(before, after)
	if err != nil {
		t.Fatalf("compare: %v", err)
	}
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

// TestCompareCyclesFollowSameRules makes sure allowed non-self cycles use
// the same direct-edge rule and round-trip complete inside changed entries.
func TestCompareCyclesFollowSameRules(t *testing.T) {
	before := parseForCompare(t, `{"artifact":"cyc","version":"1","components":[
		{"coordinate":"a","license":"L","dependencies":["b"]},
		{"coordinate":"b","license":"L","dependencies":["a"]}
	]}`)
	after := parseForCompare(t, `{"artifact":"cyc","version":"2","components":[
		{"coordinate":"a","license":"OTHER","dependencies":["b"]},
		{"coordinate":"b","license":"L","dependencies":["a"]}
	]}`)

	got, err := Compare(before, after)
	if err != nil {
		t.Fatalf("compare: %v", err)
	}
	if len(got.Changed) != 1 || got.Changed[0].Coordinate != "a" {
		t.Fatalf("changed = %+v, want only a", got.Changed)
	}
	if got.Changed[0].Before.License != "L" || got.Changed[0].After.License != "OTHER" {
		t.Fatalf("a sides = %+v", got.Changed[0])
	}
	if !reflect.DeepEqual(got.Changed[0].After.Dependencies, []string{"b"}) {
		t.Fatalf("cycle edge missing from after: %+v", got.Changed[0].After)
	}
}

// TestCompareSortsAddedAndRemovedAcrossMultipleComponents makes sure both
// presence arrays are coordinate-sorted, not input-ordered.
func TestCompareSortsAddedAndRemovedAcrossMultipleComponents(t *testing.T) {
	before := parseForCompare(t, `{"artifact":"app","version":"1","components":[
		{"coordinate":"z","license":"L","dependencies":[]},
		{"coordinate":"m","license":"L","dependencies":[]},
		{"coordinate":"a","license":"L","dependencies":[]}
	]}`)
	after := parseForCompare(t, `{"artifact":"app","version":"2","components":[
		{"coordinate":"y","license":"L","dependencies":[]},
		{"coordinate":"b","license":"L","dependencies":[]},
		{"coordinate":"n","license":"L","dependencies":[]}
	]}`)

	got, err := Compare(before, after)
	if err != nil {
		t.Fatalf("compare: %v", err)
	}
	gotAdded := []string{}
	for _, c := range got.Added {
		gotAdded = append(gotAdded, c.Coordinate)
	}
	gotRemoved := []string{}
	for _, c := range got.Removed {
		gotRemoved = append(gotRemoved, c.Coordinate)
	}
	if !reflect.DeepEqual(gotAdded, []string{"b", "n", "y"}) {
		t.Fatalf("added order = %v, want [b n y]", gotAdded)
	}
	if !reflect.DeepEqual(gotRemoved, []string{"a", "m", "z"}) {
		t.Fatalf("removed order = %v, want [a m z]", gotRemoved)
	}
	if len(got.Changed) != 0 {
		t.Fatalf("changed = %+v, want empty", got.Changed)
	}
}
