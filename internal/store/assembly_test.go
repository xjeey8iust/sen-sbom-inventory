package store

import (
	"context"
	"errors"
	"testing"

	"github.com/xjeey8iust/sen-sbom-inventory/internal/model"
)

// TestReadPathsShareManifestAssembly proves the three read paths — Register's
// idempotency read-back, List's paged read and Diff's version read — assemble
// the same manifest from storage: master record, empty collections, coordinate
// ordering, license/dependency attribution per version and artifact, and a
// legal dependency cycle all come back identically on every path.
func TestReadPathsShareManifestAssembly(t *testing.T) {
	st, _ := openCountingStore(t)
	ctx := context.Background()

	// Two versions of one artifact share every coordinate but differ in
	// licenses and dependency edges (including a cycle in v2); a second
	// artifact reuses the same coordinates again. Whatever one path
	// reconstructs, the other two must reconstruct exactly the same.
	v1 := []model.Component{
		{Coordinate: "lib", License: "Apache-2.0", Dependencies: []string{"util"}},
		{Coordinate: "util", License: "BSD-3-Clause", Dependencies: []string{}},
	}
	v2 := []model.Component{
		{Coordinate: "lib", License: "GPL-3.0", Dependencies: []string{"util"}},
		{Coordinate: "util", License: "MIT", Dependencies: []string{"lib"}},
	}
	first1 := registerManifest(t, st, "app", "1", v1)
	first2 := registerManifest(t, st, "app", "2", v2)
	registerManifest(t, st, "vendor", "1", []model.Component{
		{Coordinate: "lib", License: "PROPRIETARY", Dependencies: []string{}},
		{Coordinate: "util", License: "PROPRIETARY", Dependencies: []string{}},
	})
	// An empty manifest must come back with a non-nil empty component list on
	// every path too.
	emptyFirst := registerManifest(t, st, "app", "empty", []model.Component{})

	// Path 1: replayed registrations read the stored manifest back.
	replay1, created, err := st.Register(ctx, &model.SBOM{Artifact: "app", Version: "1", Components: v1})
	if err != nil || created {
		t.Fatalf("replay v1: err=%v created=%v", err, created)
	}
	replay2, created, err := st.Register(ctx, &model.SBOM{Artifact: "app", Version: "2", Components: v2})
	if err != nil || created {
		t.Fatalf("replay v2: err=%v created=%v", err, created)
	}
	replayEmpty, created, err := st.Register(ctx, &model.SBOM{Artifact: "app", Version: "empty", Components: []model.Component{}})
	if err != nil || created {
		t.Fatalf("replay empty: err=%v created=%v", err, created)
	}

	// Path 2: the paged read.
	items, total, err := st.List(ctx, "app", 1, 20)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if total != 3 || len(items) != 3 {
		t.Fatalf("total/items = %d/%d, want 3/3", total, len(items))
	}
	listed := map[string]*model.SBOM{}
	for _, item := range items {
		listed[item.Version] = item
	}

	// Path 3: the comparison read, both as the from-side and as the to-side.
	from1, to2, err := st.Diff(ctx, "app", "1", "2")
	if err != nil {
		t.Fatalf("diff 1->2: %v", err)
	}
	from2, to1, err := st.Diff(ctx, "app", "2", "1")
	if err != nil {
		t.Fatalf("diff 2->1: %v", err)
	}
	emptyFrom, emptyTo, err := st.Diff(ctx, "app", "empty", "empty")
	if err != nil {
		t.Fatalf("diff empty: %v", err)
	}

	// Every path must agree with the record returned by the first registration.
	for _, got := range []*model.SBOM{replay1, listed["1"], from1, to1} {
		assertSameManifest(t, first1, got)
	}
	for _, got := range []*model.SBOM{replay2, listed["2"], from2, to2} {
		assertSameManifest(t, first2, got)
	}
	for _, got := range []*model.SBOM{replayEmpty, listed["empty"], emptyFrom, emptyTo} {
		assertSameManifest(t, emptyFirst, got)
		if got.Components == nil {
			t.Fatalf("empty manifest reconstructed with nil components on some path")
		}
	}

	// The shared coordinates stayed scoped per manifest on every path: no
	// license or dependency edge crossed versions or artifacts.
	for version, want := range map[string][]model.Component{"1": v1, "2": v2} {
		for _, got := range []*model.SBOM{listed[version]} {
			byCoord := componentsByName(got)
			for _, w := range want {
				c := byCoord[w.Coordinate]
				if c.License != w.License || !sameStrings(c.Dependencies, w.Dependencies) {
					t.Fatalf("version %s component %s = %+v, want %+v", version, w.Coordinate, c, w)
				}
			}
		}
	}
	// The v2 cycle survived intact on the diff path.
	if deps := componentsByName(to2)["util"].Dependencies; len(deps) != 1 || deps[0] != "lib" {
		t.Fatalf("cycle edge util-> = %v, want [lib]", deps)
	}
}

// TestReadPathFailuresYieldEmptyResults forces a failure at each shared read
// step and checks all three paths fail the same way: model.ErrStorageUnavailable,
// with List returning a nil page and zero total, Diff returning nil on both
// sides and Register returning no record.
func TestReadPathFailuresYieldEmptyResults(t *testing.T) {
	for _, kind := range []string{"sboms", "components", "dependencies"} {
		t.Run(kind, func(t *testing.T) {
			st, counted := openCountingStore(t)
			ctx := context.Background()
			registerManifest(t, st, "app", "1", twoComponents([]string{"b"}))
			registerManifest(t, st, "app", "2", twoComponents(nil))

			counted.FailNextRead(kind)
			items, total, err := st.List(ctx, "app", 1, 20)
			if !errors.Is(err, model.ErrStorageUnavailable) {
				t.Fatalf("list error = %v, want model.ErrStorageUnavailable", err)
			}
			if items != nil || total != 0 {
				t.Fatalf("failed list = items %v total %d, want nil/0", items, total)
			}

			counted.FailNextRead(kind)
			from, to, err := st.Diff(ctx, "app", "1", "2")
			if !errors.Is(err, model.ErrStorageUnavailable) {
				t.Fatalf("diff error = %v, want model.ErrStorageUnavailable", err)
			}
			if from != nil || to != nil {
				t.Fatalf("failed diff = %+v %+v, want nil/nil", from, to)
			}

			counted.FailNextRead(kind)
			replayed, created, err := st.Register(ctx, &model.SBOM{
				Artifact: "app", Version: "1", Components: twoComponents([]string{"b"}),
			})
			if !errors.Is(err, model.ErrStorageUnavailable) {
				t.Fatalf("register error = %v, want model.ErrStorageUnavailable", err)
			}
			if replayed != nil || created {
				t.Fatalf("failed register = %+v created=%v, want nil/false", replayed, created)
			}
		})
	}
}

// TestEmptyPageAndMissingVersionStayConsistent re-checks the boundary reads
// against the shared assembly: an out-of-range page and an unknown artifact
// return a non-nil empty page with the snapshot's total, and a diff against a
// missing version is one model.ErrNotFound with no detail read.
func TestEmptyPageAndMissingVersionStayConsistent(t *testing.T) {
	st, counted := openCountingStore(t)
	ctx := context.Background()
	registerManifest(t, st, "app", "1", twoComponents([]string{"b"}))
	counted.Reset()

	for _, tc := range []struct {
		artifact string
		page     int
	}{
		{"app", 2},
		{"ghost", 1},
	} {
		items, total, err := st.List(ctx, tc.artifact, tc.page, 10)
		if err != nil {
			t.Fatalf("list %s page %d: %v", tc.artifact, tc.page, err)
		}
		if items == nil || len(items) != 0 {
			t.Fatalf("empty page items = %v, want non-nil empty slice", items)
		}
		wantTotal := 0
		if tc.artifact == "app" {
			wantTotal = 1
		}
		if total != wantTotal {
			t.Fatalf("total = %d, want %d", total, wantTotal)
		}
	}
	counters := counted.Snapshot()
	if counters.RowsByKind["components"] != 0 || counters.RowsByKind["dependencies"] != 0 {
		t.Fatalf("empty pages read detail rows: %+v", counters.RowsByKind)
	}

	counted.Reset()
	from, to, err := st.Diff(ctx, "app", "1", "missing")
	if !errors.Is(err, model.ErrNotFound) {
		t.Fatalf("diff error = %v, want model.ErrNotFound", err)
	}
	if from != nil || to != nil {
		t.Fatalf("not-found diff = %+v %+v, want nil/nil", from, to)
	}
	counters = counted.Snapshot()
	if counters.RowsByKind["components"] != 0 || counters.RowsByKind["dependencies"] != 0 {
		t.Fatalf("missing version read detail rows: %+v", counters.RowsByKind)
	}
}
