package store

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/xjeey8iust/sen-sbom-inventory/internal/model"
)

// comp is a terse constructor for components without dependencies.
func comp(coordinate, license string) model.Component {
	return model.Component{Coordinate: coordinate, License: license, Dependencies: []string{}}
}

// diffOrFail runs Diff and fails the test on error.
func diffOrFail(t *testing.T, st *Store, artifact, fromVersion, toVersion string) *model.DiffResult {
	t.Helper()
	result, err := st.Diff(context.Background(), artifact, fromVersion, toVersion)
	if err != nil {
		t.Fatalf("diff %s %s->%s: %v", artifact, fromVersion, toVersion, err)
	}
	return result
}

func assertCoordinates(t *testing.T, name string, got []model.Component, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("%s len = %d, want %d (%v): %+v", name, len(got), len(want), want, got)
	}
	for i, coordinate := range want {
		if got[i].Coordinate != coordinate {
			t.Fatalf("%s[%d] coordinate = %q, want %q (full order %v)", name, i, got[i].Coordinate, coordinate, want)
		}
	}
}

// TestDiffComputesAddedRemovedChanged covers the central rule against stored
// manifests: added = newer-only, removed = older-only, a shared coordinate is
// changed only on license or direct dependency set difference, and every
// emitted component is the full stored component. Reversing the direction
// swaps the two sides, proving versions are plain labels with no ordering
// inference.
func TestDiffComputesAddedRemovedChanged(t *testing.T) {
	st, _ := openCountingStore(t)

	registerManifest(t, st, "app", "1", []model.Component{
		{Coordinate: "a", License: "L1", Dependencies: []string{"b", "c"}},
		comp("b", "L2"),
		comp("c", "L3"),
		comp("d", "L4"),
	})
	registerManifest(t, st, "app", "2", []model.Component{
		{Coordinate: "a", License: "L1", Dependencies: []string{"b"}},
		comp("b", "L2-new"),
		comp("c", "L3"),
		{Coordinate: "e", License: "L5", Dependencies: []string{"a"}},
	})

	result := diffOrFail(t, st, "app", "1", "2")
	if result.Artifact != "app" || result.FromVersion != "1" || result.ToVersion != "2" {
		t.Fatalf("identifiers = %q/%q/%q", result.Artifact, result.FromVersion, result.ToVersion)
	}

	assertCoordinates(t, "added", result.Added, []string{"e"})
	assertCoordinates(t, "removed", result.Removed, []string{"d"})

	changed := result.Changed
	if len(changed) != 2 || changed[0].Coordinate != "a" || changed[1].Coordinate != "b" {
		t.Fatalf("changed = %+v, want coordinates [a b]", changed)
	}

	// "a" changed only in its direct dependency set; license stayed.
	gotA := changed[0]
	if gotA.Before.License != "L1" || gotA.After.License != "L1" {
		t.Fatalf("a licenses = %q/%q, want L1/L1", gotA.Before.License, gotA.After.License)
	}
	if !sameStrings(gotA.Before.Dependencies, []string{"b", "c"}) ||
		!sameStrings(gotA.After.Dependencies, []string{"b"}) {
		t.Fatalf("a deps = %v -> %v, want [b c] -> [b]", gotA.Before.Dependencies, gotA.After.Dependencies)
	}

	// "b" changed only in its license; direct dependency set stayed empty.
	gotB := changed[1]
	if gotB.Before.License != "L2" || gotB.After.License != "L2-new" {
		t.Fatalf("b licenses = %q/%q, want L2/L2-new", gotB.Before.License, gotB.After.License)
	}
	if len(gotB.Before.Dependencies) != 0 || len(gotB.After.Dependencies) != 0 {
		t.Fatalf("b deps = %v/%v, want empty/empty", gotB.Before.Dependencies, gotB.After.Dependencies)
	}

	// Added components are complete components, dependencies included; removed
	// carries the full older component.
	if added := result.Added[0]; added.License != "L5" || !sameStrings(added.Dependencies, []string{"a"}) {
		t.Fatalf("added e is not the full component: %+v", added)
	}
	if removed := result.Removed[0]; removed.License != "L4" || removed.Dependencies == nil || len(removed.Dependencies) != 0 {
		t.Fatalf("removed d is not the full older component: %+v", removed)
	}

	// Direction reversed: added/removed swap and before/after flip.
	back := diffOrFail(t, st, "app", "2", "1")
	assertCoordinates(t, "reversed added", back.Added, []string{"d"})
	assertCoordinates(t, "reversed removed", back.Removed, []string{"e"})
	if len(back.Changed) != 2 || back.Changed[0].Coordinate != "a" {
		t.Fatalf("reversed changed = %+v, want [a b]", back.Changed)
	}
	before := back.Changed[0].Before
	after := back.Changed[0].After
	if !sameStrings(before.Dependencies, []string{"b"}) || !sameStrings(after.Dependencies, []string{"b", "c"}) {
		t.Fatalf("reversed a sides not swapped: %v -> %v", before.Dependencies, after.Dependencies)
	}
}

// TestDiffUnchangedCoordinateIsNotEmitted pins the negative case, including
// the rule that a referenced component's license change never propagates to
// components pointing at it: only "b" changes; "a" keeps the same direct edge
// a->b and must stay out of the result even transitively.
func TestDiffUnchangedAndNoTransitivePropagation(t *testing.T) {
	st, _ := openCountingStore(t)
	registerManifest(t, st, "app", "1", []model.Component{
		{Coordinate: "a", License: "L1", Dependencies: []string{"b"}},
		comp("b", "L2"),
		comp("c", "L3"),
	})
	registerManifest(t, st, "app", "2", []model.Component{
		{Coordinate: "a", License: "L1", Dependencies: []string{"b"}},
		comp("b", "L2-changed"),
		comp("c", "L3"),
	})

	result := diffOrFail(t, st, "app", "1", "2")
	assertCoordinates(t, "added", result.Added, nil)
	assertCoordinates(t, "removed", result.Removed, nil)
	if len(result.Changed) != 1 || result.Changed[0].Coordinate != "b" {
		t.Fatalf("changed = %+v, want only [b]", result.Changed)
	}
}

// TestDiffRenameIsRemoveAndAdd: a coordinate is the identity within a
// manifest, so a rename can never appear as changed.
func TestDiffRenameIsRemoveAndAdd(t *testing.T) {
	st, _ := openCountingStore(t)
	registerManifest(t, st, "app", "1", []model.Component{
		comp("old-name", "L"),
	})
	registerManifest(t, st, "app", "2", []model.Component{
		comp("new-name", "L"),
	})

	result := diffOrFail(t, st, "app", "1", "2")
	assertCoordinates(t, "added", result.Added, []string{"new-name"})
	assertCoordinates(t, "removed", result.Removed, []string{"old-name"})
	assertCoordinates(t, "changed coordinates", changedCoordinates(result.Changed), nil)
}

func changedCoordinates(changed []model.ChangedComponent) []model.Component {
	out := make([]model.Component, len(changed))
	for i, c := range changed {
		out[i] = c.Before
	}
	return out
}

// TestDiffEmptyManifests covers every empty/non-empty combination under the
// same rules as populated manifests.
func TestDiffEmptyManifests(t *testing.T) {
	st, _ := openCountingStore(t)
	registerManifest(t, st, "app", "empty1", []model.Component{})
	registerManifest(t, st, "app", "empty2", []model.Component{})
	registerManifest(t, st, "app", "nonempty", []model.Component{comp("x", "L")})

	emptyToFull := diffOrFail(t, st, "app", "empty1", "nonempty")
	assertCoordinates(t, "added", emptyToFull.Added, []string{"x"})
	assertCoordinates(t, "removed", emptyToFull.Removed, nil)
	assertCoordinates(t, "changed", changedCoordinates(emptyToFull.Changed), nil)

	fullToEmpty := diffOrFail(t, st, "app", "nonempty", "empty1")
	assertCoordinates(t, "added", fullToEmpty.Added, nil)
	assertCoordinates(t, "removed", fullToEmpty.Removed, []string{"x"})

	bothEmpty := diffOrFail(t, st, "app", "empty1", "empty2")
	assertCoordinates(t, "added", bothEmpty.Added, nil)
	assertCoordinates(t, "removed", bothEmpty.Removed, nil)
	assertCoordinates(t, "changed", changedCoordinates(bothEmpty.Changed), nil)
}

// TestDiffSameVersionComparesItself: the only legitimate same-name comparison
// is a manifest with itself, which reports three empty arrays (never nil) when
// the manifest exists.
func TestDiffSameVersionComparesItself(t *testing.T) {
	st, _ := openCountingStore(t)
	registerManifest(t, st, "app", "1", []model.Component{
		{Coordinate: "a", License: "L", Dependencies: []string{"b"}},
		comp("b", "L"),
	})

	result := diffOrFail(t, st, "app", "1", "1")
	if result.Added == nil || result.Removed == nil || result.Changed == nil {
		t.Fatalf("difference slices must be non-nil: %+v", result)
	}
	if len(result.Added) != 0 || len(result.Removed) != 0 || len(result.Changed) != 0 {
		t.Fatalf("self comparison produced differences: %+v", result)
	}
}

// TestDiffAllowsCyclesOnBothSides compares manifests containing legal
// non-self cycles: edges compare as direct relations only and a removed cycle
// edge shows up as a dependency change on the owning component.
func TestDiffAllowsCyclesOnBothSides(t *testing.T) {
	st, _ := openCountingStore(t)
	registerManifest(t, st, "cyc", "1", []model.Component{
		{Coordinate: "a", License: "A", Dependencies: []string{"b"}},
		{Coordinate: "b", License: "B", Dependencies: []string{"a"}},
	})
	registerManifest(t, st, "cyc", "2", []model.Component{
		{Coordinate: "a", License: "A", Dependencies: []string{"b"}},
		comp("b", "B"),
	})

	result := diffOrFail(t, st, "cyc", "1", "2")
	assertCoordinates(t, "added", result.Added, nil)
	assertCoordinates(t, "removed", result.Removed, nil)
	if len(result.Changed) != 1 || result.Changed[0].Coordinate != "b" {
		t.Fatalf("changed = %+v, want only [b]", result.Changed)
	}
	got := result.Changed[0]
	if !sameStrings(got.Before.Dependencies, []string{"a"}) || len(got.After.Dependencies) != 0 {
		t.Fatalf("b edge = %v -> %v, want [a] -> []", got.Before.Dependencies, got.After.Dependencies)
	}

	// Same cycle on both sides (another registered version with identical
	// content under a different version) yields no differences.
	registerManifest(t, st, "cyc", "3", []model.Component{
		{Coordinate: "a", License: "A", Dependencies: []string{"b"}},
		{Coordinate: "b", License: "B", Dependencies: []string{"a"}},
	})
	again := diffOrFail(t, st, "cyc", "1", "3")
	if len(again.Added)+len(again.Removed)+len(again.Changed) != 0 {
		t.Fatalf("identical cyclic manifests differ: %+v", again)
	}
}

// TestDiffOrdersArraysByCoordinate verifies all three arrays leave in
// coordinate ascending order regardless of stored/registration order.
func TestDiffOrdersArraysByCoordinate(t *testing.T) {
	st, _ := openCountingStore(t)
	registerManifest(t, st, "app", "1", []model.Component{
		comp("d1", "L"), comp("d2", "L"), comp("keep", "L"),
	})
	registerManifest(t, st, "app", "2", []model.Component{
		comp("a2", "L"), comp("a1", "L"), comp("a3", "L"), comp("keep", "L"),
	})

	result := diffOrFail(t, st, "app", "1", "2")
	assertCoordinates(t, "added", result.Added, []string{"a1", "a2", "a3"})
	assertCoordinates(t, "removed", result.Removed, []string{"d1", "d2"})
	if len(result.Changed) != 0 {
		t.Fatalf("changed = %+v, want empty", result.Changed)
	}
}

// TestCompareIgnoresDependencyOrder checks the comparison rule directly:
// direct dependencies are compared as sets, so array order at comparison time
// cannot produce a false change (registration already stores them sorted, but
// the rule itself must be order-independent).
func TestCompareIgnoresDependencyOrder(t *testing.T) {
	older := &model.SBOM{Components: []model.Component{
		{Coordinate: "a", License: "L", Dependencies: []string{"b", "c"}},
	}}
	newer := &model.SBOM{Components: []model.Component{
		{Coordinate: "a", License: "L", Dependencies: []string{"c", "b"}},
	}}
	result := computeDiff("app", "1", "2", older, newer)
	if len(result.Changed) != 0 || len(result.Added) != 0 || len(result.Removed) != 0 {
		t.Fatalf("reordered-only dependencies produced a diff: %+v", result)
	}

	// A genuine set difference still registers even when one list is a
	// permutation prefix of the other.
	newer.Components[0].Dependencies = []string{"b"}
	result = computeDiff("app", "1", "2", older, newer)
	if len(result.Changed) != 1 || result.Changed[0].Coordinate != "a" {
		t.Fatalf("missing dependency-set change: %+v", result)
	}
}

// TestDiffReturnsNotFound covers every absence shape, including both versions
// missing (still one error), a version missing while comparing with itself,
// and a casing/artifact mismatch.
func TestDiffReturnsNotFound(t *testing.T) {
	st, _ := openCountingStore(t)
	registerManifest(t, st, "app", "1", []model.Component{comp("a", "L")})
	registerManifest(t, st, "App", "1", []model.Component{comp("a", "L")})

	cases := []struct {
		name        string
		artifact    string
		fromVersion string
		toVersion   string
	}{
		{"to version missing", "app", "1", "2"},
		{"from version missing", "app", "2", "1"},
		{"both versions missing", "app", "8", "9"},
		{"self comparison on missing version", "app", "9", "9"},
		{"unknown artifact", "ghost", "1", "1"},
		{"cased artifact is a different artifact", "APP", "1", "1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := st.Diff(context.Background(), tc.artifact, tc.fromVersion, tc.toVersion)
			if !errors.Is(err, model.ErrNotFound) {
				t.Fatalf("error = %v, want model.ErrNotFound", err)
			}
			if result != nil {
				t.Fatalf("result = %+v, want nil", result)
			}
		})
	}

	// The cased counterpart that does exist still compares successfully.
	if _, err := st.Diff(context.Background(), "App", "1", "1"); err != nil {
		t.Fatalf("existing cased artifact diff failed: %v", err)
	}
}

// TestDiffReadFailuresReturnUnavailable forces a failure at each read step of
// a diff. Every failure surfaces model.ErrStorageUnavailable with no partial
// result: the two resolve queries, then the component and dependency loaders.
func TestDiffReadFailuresReturnUnavailable(t *testing.T) {
	for _, kind := range []string{"sboms", "components", "dependencies"} {
		t.Run(kind, func(t *testing.T) {
			st, counted := openCountingStore(t)
			registerManifest(t, st, "app", "1", []model.Component{
				{Coordinate: "a", License: "A", Dependencies: []string{"b"}},
				comp("b", "B"),
			})
			registerManifest(t, st, "app", "2", []model.Component{
				comp("a", "A"),
				comp("b", "B"),
			})
			counted.FailNextRead(kind)

			result, err := st.Diff(context.Background(), "app", "1", "2")
			if err == nil {
				t.Fatalf("expected failure on %s read", kind)
			}
			if !errors.Is(err, model.ErrStorageUnavailable) {
				t.Fatalf("error = %v, want model.ErrStorageUnavailable", err)
			}
			if result != nil {
				t.Fatalf("result = %+v, want nil on failed read", result)
			}
		})
	}
}

// TestDiffReadsBothManifestsFromOneSnapshotBudget counts the statements a
// successful diff issues: two identity lookups plus, per manifest, the header
// read and the two shared detail loaders — eight SELECTs regardless of
// manifest size — proving both manifests are reconstructed through the same
// loader rule inside one transaction.
func TestDiffReadsBothManifestsFromOneSnapshotBudget(t *testing.T) {
	st, counted := openCountingStore(t)
	registerManifest(t, st, "app", "1", []model.Component{
		{Coordinate: "a", License: "A", Dependencies: []string{"b"}},
		comp("b", "B"),
	})
	registerManifest(t, st, "app", "2", []model.Component{
		comp("a", "A"),
		comp("b", "B"),
	})
	registerManifest(t, st, "other", "1", []model.Component{
		comp("a", "SECRET"),
	})
	counted.Reset()

	result, err := st.Diff(context.Background(), "app", "1", "2")
	if err != nil {
		t.Fatalf("diff: %v", err)
	}
	counters := counted.Snapshot()
	if counters.Selects != 8 {
		t.Fatalf("diff issued %d SELECTs, want exactly 8", counters.Selects)
	}
	// Two resolve lookups and one header load per manifest.
	if counters.RowsByKind["sboms"] != 4 {
		t.Fatalf("sboms rows = %d, want 4: %+v", counters.RowsByKind["sboms"], counters.RowsByKind)
	}
	if counters.RowsByKind["components"] != 4 || counters.RowsByKind["dependencies"] != 1 {
		t.Fatalf("detail rows wrong: %+v", counters.RowsByKind)
	}
	if result == nil {
		t.Fatalf("nil result")
	}
}

// TestDiffSnapshotStaysCompleteUnderConcurrentWriters reads a fixed pair of
// versions while a writer commits other versions. Every diff must observe
// both manifests complete and return exactly the same result, since both
// reconstructions share one committed snapshot.
func TestDiffSnapshotStaysCompleteUnderConcurrentWriters(t *testing.T) {
	st, _ := openCountingStore(t)
	ctx := context.Background()
	registerManifest(t, st, "app", "1", []model.Component{
		comp("a", "A"),
	})
	registerManifest(t, st, "app", "2", []model.Component{
		comp("a", "A"),
		comp("b", "B"),
	})

	var wg sync.WaitGroup
	stop := make(chan struct{})
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			version := fmt.Sprintf("writer-%d", i)
			_, _, _ = st.Register(ctx, &model.SBOM{
				Artifact: "app", Version: version,
				Components: []model.Component{
					{Coordinate: "a", License: "A", Dependencies: []string{"b"}},
					comp("b", "B"),
				},
			})
		}
	}()

	for i := 0; i < 50; i++ {
		result, err := st.Diff(ctx, "app", "1", "2")
		if err != nil {
			t.Fatalf("diff during writes: %v", err)
		}
		if result.Artifact != "app" || result.FromVersion != "1" || result.ToVersion != "2" {
			t.Fatalf("identifiers mutated: %+v", result)
		}
		if len(result.Added) != 1 || result.Added[0].Coordinate != "b" ||
			result.Added[0].License != "B" || len(result.Added[0].Dependencies) != 0 {
			t.Fatalf("unstable/partial added: %+v", result.Added)
		}
		if len(result.Removed) != 0 || len(result.Changed) != 0 {
			t.Fatalf("unexpected removed/changed: %+v / %+v", result.Removed, result.Changed)
		}
	}
	close(stop)
	wg.Wait()
}
