package store

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/xjeey8iust/sen-sbom-inventory/internal/model"
)

func componentsByName(sbom *model.SBOM) map[string]model.Component {
	m := make(map[string]model.Component, len(sbom.Components))
	for _, c := range sbom.Components {
		m[c.Coordinate] = c
	}
	return m
}

// TestDiffPartitionsComponentsByPresenceAndChange exercises the store read
// itself: both manifests come back complete and ordered, a self-comparison
// returns the same record twice, and missing versions (either one or both)
// surface model.ErrNotFound.
func TestDiffPartitionsComponentsByPresenceAndChange(t *testing.T) {
	st, _ := openCountingStore(t)
	ctx := context.Background()

	// Old version:
	//   gone   -> present only in old
	//   shared -> changes license in new
	//   edge   -> changes direct dependency set in new
	//   stable -> identical in both
	registerManifest(t, st, "app", "1", []model.Component{
		{Coordinate: "gone", License: "G", Dependencies: []string{}},
		{Coordinate: "shared", License: "OLD", Dependencies: []string{}},
		{Coordinate: "edge", License: "E", Dependencies: []string{"stable"}},
		{Coordinate: "stable", License: "S", Dependencies: []string{}},
	})
	// New version drops "gone", adds "born", changes "shared" license and
	// "edge" edges, keeps "stable".
	registerManifest(t, st, "app", "2", []model.Component{
		{Coordinate: "born", License: "B", Dependencies: []string{}},
		{Coordinate: "shared", License: "NEW", Dependencies: []string{}},
		{Coordinate: "edge", License: "E", Dependencies: []string{"born", "stable"}},
		{Coordinate: "stable", License: "S", Dependencies: []string{}},
	})

	from, to, err := st.Diff(ctx, "app", "1", "2")
	if err != nil {
		t.Fatalf("diff: %v", err)
	}
	if from.Version != "1" || to.Version != "2" || from.Artifact != "app" || to.Artifact != "app" {
		t.Fatalf("identities = %s@%s vs %s@%s", from.Artifact, from.Version, to.Artifact, to.Version)
	}
	if len(from.Components) != 4 || len(to.Components) != 4 {
		t.Fatalf("manifests incomplete: %d vs %d components", len(from.Components), len(to.Components))
	}
	// Components stay coordinate-ascending and empty deps stay non-nil.
	if from.Components[0].Coordinate != "edge" {
		t.Fatalf("from not coordinate sorted: %+v", from.Components)
	}
	if to.Components[0].Dependencies == nil {
		t.Fatalf("empty dependencies reconstructed as nil")
	}

	oldByName := componentsByName(from)
	newByName := componentsByName(to)
	if c := oldByName["gone"]; c.License != "G" || len(c.Dependencies) != 0 {
		t.Fatalf("gone component wrong: %+v", c)
	}
	if c := newByName["born"]; c.License != "B" || len(c.Dependencies) != 0 {
		t.Fatalf("born component wrong: %+v", c)
	}
	if c := newByName["edge"]; len(c.Dependencies) != 2 ||
		c.Dependencies[0] != "born" || c.Dependencies[1] != "stable" {
		t.Fatalf("edge dependencies not sorted/complete: %+v", c)
	}
}

// TestDiffSelfLoadsOneManifestAndIsIdentity proves same-version comparison
// reads the manifest only once and hands the same record back for both slots.
func TestDiffSelfLoadsOneManifestAndIsIdentity(t *testing.T) {
	st, counted := openCountingStore(t)
	registerManifest(t, st, "app", "1", []model.Component{
		{Coordinate: "a", License: "A", Dependencies: []string{"b"}},
		{Coordinate: "b", License: "B", Dependencies: []string{}},
	})
	counted.Reset()

	from, to, err := st.Diff(context.Background(), "app", "1", "1")
	if err != nil {
		t.Fatalf("self diff: %v", err)
	}
	if from.ID != to.ID {
		t.Fatalf("self diff loaded two records: ids %d and %d", from.ID, to.ID)
	}
	if len(from.Components) != 2 || len(to.Components) != 2 {
		t.Fatalf("self diff manifests incomplete")
	}
	if !equalContent(from, to) {
		t.Fatalf("self diff content differs")
	}
	// One sboms read, one batched components read, one batched dependencies
	// read — the equal version is never queried twice.
	counters := counted.Snapshot()
	if counters.Selects != 3 {
		t.Fatalf("self diff issued %d SELECTs, want 3: %+v", counters.Selects, counters.RowsByKind)
	}
	if counters.RowsByKind["sboms"] != 1 {
		t.Fatalf("self diff read %d sbom rows, want 1", counters.RowsByKind["sboms"])
	}
}

// TestDiffEmptyManifestsLoadFine verifies the empty-array reconstruction on
// the diff path.
func TestDiffEmptyManifestsLoadFine(t *testing.T) {
	st, _ := openCountingStore(t)
	registerManifest(t, st, "app", "1", []model.Component{})
	registerManifest(t, st, "app", "2", []model.Component{
		{Coordinate: "a", License: "A", Dependencies: []string{}},
	})

	from, to, err := st.Diff(context.Background(), "app", "1", "2")
	if err != nil {
		t.Fatalf("diff: %v", err)
	}
	if from.Components == nil || len(from.Components) != 0 {
		t.Fatalf("old empty components = %v, want non-nil empty", from.Components)
	}
	if len(to.Components) != 1 || to.Components[0].Dependencies == nil {
		t.Fatalf("new manifest reconstructed wrong: %+v", to.Components)
	}
}

// TestDiffMissingVersionsReturnsNotFound covers unknown artifact, missing
// from-version, missing to-version, and both missing: every case is exactly
// one model.ErrNotFound, even when both rows are absent.
func TestDiffMissingVersionsReturnsNotFound(t *testing.T) {
	st, _ := openCountingStore(t)
	registerManifest(t, st, "app", "1", []model.Component{})

	cases := []struct {
		name        string
		artifact    string
		fromVersion string
		toVersion   string
	}{
		{"both versions missing", "app", "8", "9"},
		{"from version missing", "app", "9", "1"},
		{"to version missing", "app", "1", "9"},
		{"unknown artifact", "ghost", "1", "1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			from, to, err := st.Diff(context.Background(), tc.artifact, tc.fromVersion, tc.toVersion)
			if !errors.Is(err, model.ErrNotFound) {
				t.Fatalf("error = %v, want ErrNotFound", err)
			}
			if from != nil || to != nil {
				t.Fatalf("partial manifests returned on not-found: %+v %+v", from, to)
			}
		})
	}
}

// TestDiffUsesOneSnapshotReadEach checks the end-to-end read budget for two
// different versions: a single sboms scan, one batched components read and
// one batched dependencies read.
func TestDiffUsesOneSnapshotReadEach(t *testing.T) {
	st, counted := openCountingStore(t)
	registerManifest(t, st, "app", "1", []model.Component{
		{Coordinate: "a", License: "A", Dependencies: []string{"b"}},
		{Coordinate: "b", License: "B", Dependencies: []string{}},
	})
	registerManifest(t, st, "app", "2", []model.Component{
		{Coordinate: "a", License: "A2", Dependencies: []string{}},
	})
	// Another artifact sharing coordinates must never enter the snapshot read.
	registerManifest(t, st, "other", "1", []model.Component{
		{Coordinate: "a", License: "SECRET", Dependencies: []string{}},
	})
	counted.Reset()

	from, to, err := st.Diff(context.Background(), "app", "1", "2")
	if err != nil {
		t.Fatalf("diff: %v", err)
	}
	counters := counted.Snapshot()
	if counters.Selects != 3 {
		t.Fatalf("issued %d SELECTs, want 3", counters.Selects)
	}
	if counters.RowsByKind["sboms"] != 2 ||
		counters.RowsByKind["components"] != 3 ||
		counters.RowsByKind["dependencies"] != 1 {
		t.Fatalf("detail reads escaped the two manifests: %+v", counters.RowsByKind)
	}
	for _, sbom := range []*model.SBOM{from, to} {
		for _, c := range sbom.Components {
			if c.License == "SECRET" {
				t.Fatalf("other artifact's component leaked into diff: %+v", c)
			}
		}
	}
}

// TestDiffReadFailuresReturnUnavailable forces a failure at each of the three
// read steps; every failure is model.ErrStorageUnavailable with no partial
// result. A forced fault on the existence scan must also surface as a storage
// failure rather than a not-found.
func TestDiffReadFailuresReturnUnavailable(t *testing.T) {
	for _, kind := range []string{"sboms", "components", "dependencies"} {
		t.Run(kind, func(t *testing.T) {
			st, counted := openCountingStore(t)
			registerManifest(t, st, "app", "1", []model.Component{
				{Coordinate: "a", License: "A", Dependencies: []string{"b"}},
				{Coordinate: "b", License: "B", Dependencies: []string{}},
			})
			registerManifest(t, st, "app", "2", []model.Component{
				{Coordinate: "a", License: "A2", Dependencies: []string{}},
			})
			counted.FailNextRead(kind)

			from, to, err := st.Diff(context.Background(), "app", "1", "2")
			if !errors.Is(err, model.ErrStorageUnavailable) {
				t.Fatalf("error = %v, want ErrStorageUnavailable", err)
			}
			if from != nil || to != nil {
				t.Fatalf("partial manifests on failed read: %+v %+v", from, to)
			}
		})
	}
}

// TestDiffSnapshotStaysConsistentUnderConcurrentWriters compares two fixed
// versions while a writer registers other versions: both compared manifests
// must always come back complete and share one committed snapshot.
func TestDiffSnapshotStaysConsistentUnderConcurrentWriters(t *testing.T) {
	st, _ := openCountingStore(t)
	ctx := context.Background()
	registerManifest(t, st, "app", "base-1", []model.Component{
		{Coordinate: "a", License: "A", Dependencies: []string{"b"}},
		{Coordinate: "b", License: "B", Dependencies: []string{}},
	})
	registerManifest(t, st, "app", "base-2", []model.Component{
		{Coordinate: "a", License: "A", Dependencies: []string{}},
		{Coordinate: "b", License: "B", Dependencies: []string{"a"}},
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
				Artifact:   "app",
				Version:    version,
				Components: twoComponents([]string{"b"}),
			})
		}
	}()

	for i := 0; i < 50; i++ {
		from, to, err := st.Diff(ctx, "app", "base-1", "base-2")
		if err != nil {
			t.Fatalf("diff during writes: %v", err)
		}
		if len(from.Components) != 2 || len(to.Components) != 2 {
			t.Fatalf("incomplete manifests from snapshot: %+v %+v", from, to)
		}
		fromDeps := componentsByName(from)
		toDeps := componentsByName(to)
		if len(fromDeps["a"].Dependencies) != 1 || fromDeps["a"].Dependencies[0] != "b" {
			t.Fatalf("old manifest edges wrong: %+v", fromDeps["a"])
		}
		if len(toDeps["b"].Dependencies) != 1 || toDeps["b"].Dependencies[0] != "a" {
			t.Fatalf("new manifest edges wrong: %+v", toDeps["b"])
		}
	}
	close(stop)
	wg.Wait()
}
