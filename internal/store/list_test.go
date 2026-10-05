package store

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"

	"github.com/xjeey8iust/sen-sbom-inventory/internal/model"
	"github.com/xjeey8iust/sen-sbom-inventory/internal/storetest"
)

func openCountingStore(t *testing.T) (*Store, *storetest.Driver) {
	t.Helper()
	counted := storetest.Register()
	st, err := OpenWithDriver(filepath.Join(t.TempDir(), "counted.db"), storetest.DriverName)
	if err != nil {
		t.Fatalf("open counting store: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	return st, counted
}

func registerManifest(t *testing.T, st *Store, artifact, version string, comps []model.Component) *model.SBOM {
	t.Helper()
	got, created, err := st.Register(context.Background(), &model.SBOM{
		Artifact: artifact, Version: version, Components: comps,
	})
	if err != nil {
		t.Fatalf("register %s@%s: %v", artifact, version, err)
	}
	if !created {
		t.Fatalf("register %s@%s: not created", artifact, version)
	}
	return got
}

func twoComponents(aDeps []string) []model.Component {
	return []model.Component{
		{Coordinate: "a", License: "L-a", Dependencies: aDeps},
		{Coordinate: "b", License: "L-b", Dependencies: []string{}},
	}
}

// TestListUsesAtMostFourSelects proves the query budget against the real
// driver: one manifest or a full hundred both take exactly four SELECTs
// (count, page rows, one batched components read, one batched dependencies
// read), and the two detail reads never return rows for anything outside the
// current page and requested artifact.
func TestListUsesAtMostFourSelects(t *testing.T) {
	ctx := context.Background()

	t.Run("one manifest", func(t *testing.T) {
		st, counted := openCountingStore(t)
		registerManifest(t, st, "app", "1", []model.Component{
			{Coordinate: "a", License: "A", Dependencies: []string{"b", "c"}},
			{Coordinate: "b", License: "B", Dependencies: []string{"c"}},
			{Coordinate: "c", License: "C", Dependencies: []string{}},
		})
		counted.Reset()

		items, total, err := st.List(ctx, "app", 1, 20)
		if err != nil {
			t.Fatalf("list: %v", err)
		}
		counters := counted.Snapshot()
		if counters.Selects != 4 {
			t.Fatalf("non-empty page ran %d SELECTs, want exactly 4", counters.Selects)
		}
		if total != 1 || len(items) != 1 {
			t.Fatalf("total/items = %d/%d, want 1/1", total, len(items))
		}
		if counters.RowsByKind["count"] != 1 || counters.RowsByKind["sboms"] != 1 ||
			counters.RowsByKind["components"] != 3 || counters.RowsByKind["dependencies"] != 3 {
			t.Fatalf("unexpected row reads: %+v", counters.RowsByKind)
		}
	})

	t.Run("hundred manifests", func(t *testing.T) {
		st, counted := openCountingStore(t)
		const n = 100
		for i := 0; i < n; i++ {
			version := string(rune('0'+i/10)) + string(rune('0'+i%10))
			registerManifest(t, st, "app", version, twoComponents([]string{"b"}))
		}
		// Another artifact sharing the same coordinates: its detail rows must
		// never be read as part of an "app" page.
		registerManifest(t, st, "other", "1", []model.Component{
			{Coordinate: "a", License: "SECRET", Dependencies: []string{"b"}},
			{Coordinate: "b", License: "SECRET", Dependencies: []string{"a"}},
		})
		counted.Reset()

		items, total, err := st.List(ctx, "app", 1, 100)
		if err != nil {
			t.Fatalf("list: %v", err)
		}
		counters := counted.Snapshot()
		if counters.Selects != 4 {
			t.Fatalf("100-item page ran %d SELECTs, want exactly 4", counters.Selects)
		}
		if total != n || len(items) != n {
			t.Fatalf("total/items = %d/%d, want %d/%d", total, len(items), n, n)
		}
		if counters.RowsByKind["sboms"] != n ||
			counters.RowsByKind["components"] != 2*n ||
			counters.RowsByKind["dependencies"] != n {
			t.Fatalf("detail reads escaped the page or artifact: %+v", counters.RowsByKind)
		}
		for _, item := range items {
			if item.Artifact != "app" {
				t.Fatalf("foreign manifest on page: %q", item.Artifact)
			}
			for _, c := range item.Components {
				if c.License == "SECRET" {
					t.Fatalf("component from another artifact leaked onto the page: %+v", c)
				}
			}
		}
	})

	t.Run("middle page", func(t *testing.T) {
		st, counted := openCountingStore(t)
		for i := 0; i < 5; i++ {
			registerManifest(t, st, "app", string(rune('0'+i)), twoComponents([]string{"b"}))
		}
		counted.Reset()

		items, total, err := st.List(ctx, "app", 2, 2)
		if err != nil {
			t.Fatalf("list: %v", err)
		}
		counters := counted.Snapshot()
		if counters.Selects != 4 {
			t.Fatalf("middle page ran %d SELECTs, want 4", counters.Selects)
		}
		if total != 5 || len(items) != 2 {
			t.Fatalf("total/items = %d/%d, want 5/2", total, len(items))
		}
		// Only the two manifests on this page may have their details read.
		if counters.RowsByKind["sboms"] != 2 ||
			counters.RowsByKind["components"] != 4 ||
			counters.RowsByKind["dependencies"] != 2 {
			t.Fatalf("detail reads escaped the current page: %+v", counters.RowsByKind)
		}
	})

	t.Run("empty page skips detail reads", func(t *testing.T) {
		for _, tc := range []struct {
			name     string
			artifact string
			page     int
			wantTot  int
		}{
			{"unknown artifact", "ghost", 1, 0},
			{"past last page", "app", 4, 3},
		} {
			t.Run(tc.name, func(t *testing.T) {
				st, counted := openCountingStore(t)
				for _, v := range []string{"1", "2", "3"} {
					registerManifest(t, st, "app", v, twoComponents(nil))
				}
				counted.Reset()

				items, total, err := st.List(ctx, tc.artifact, tc.page, 2)
				if err != nil {
					t.Fatalf("list: %v", err)
				}
				counters := counted.Snapshot()
				if counters.Selects > 4 {
					t.Fatalf("SELECT count = %d, want at most 4", counters.Selects)
				}
				// Count plus page scan only; IN-list detail queries must not run.
				if counters.Selects != 2 ||
					counters.RowsByKind["components"] != 0 ||
					counters.RowsByKind["dependencies"] != 0 {
					t.Fatalf("empty page ran %d selects with rows %+v, want 2 selects and no detail rows",
						counters.Selects, counters.RowsByKind)
				}
				if items == nil || len(items) != 0 {
					t.Fatalf("items = %v, want non-nil empty slice", items)
				}
				if total != tc.wantTot {
					t.Fatalf("total = %d, want %d", total, tc.wantTot)
				}
			})
		}
	})
}

// TestListReconstructsManifests verifies ID ordering, empty-array output,
// coordinate ordering and that a legal dependency cycle round-trips completely.
func TestListReconstructsManifests(t *testing.T) {
	st, _ := openCountingStore(t)
	ctx := context.Background()

	// Empty manifest: no components at all.
	registerManifest(t, st, "app", "empty", []model.Component{})
	// Components without dependencies: dependencies must come back as an empty
	// array, not null.
	registerManifest(t, st, "app", "plain", []model.Component{
		{Coordinate: "z", License: "Z", Dependencies: []string{}},
		{Coordinate: "a", License: "A", Dependencies: []string{}},
	})
	// Legal dependency cycle a<->b must round-trip completely.
	registerManifest(t, st, "app", "cycle", []model.Component{
		{Coordinate: "a", License: "A", Dependencies: []string{"b"}},
		{Coordinate: "b", License: "B", Dependencies: []string{"a"}},
	})

	items, total, err := st.List(ctx, "app", 1, 20)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if total != 3 || len(items) != 3 {
		t.Fatalf("total/items = %d/%d", total, len(items))
	}

	empty := items[0]
	if empty.Version != "empty" || empty.Components == nil || len(empty.Components) != 0 {
		t.Fatalf("empty manifest = %+v, want non-nil empty components", empty)
	}

	plain := items[1]
	if plain.Version != "plain" {
		t.Fatalf("items not ordered by id: %s", plain.Version)
	}
	if plain.Components[0].Coordinate != "a" || plain.Components[1].Coordinate != "z" {
		t.Fatalf("components not ordered by coordinate: %+v", plain.Components)
	}
	for _, c := range plain.Components {
		if c.Dependencies == nil || len(c.Dependencies) != 0 {
			t.Fatalf("empty dependencies of %s = %v, want non-nil empty slice", c.Coordinate, c.Dependencies)
		}
	}

	cycle := items[2]
	deps := map[string][]string{}
	for _, c := range cycle.Components {
		deps[c.Coordinate] = c.Dependencies
	}
	if got := deps["a"]; len(got) != 1 || got[0] != "b" {
		t.Fatalf("cycle edge a-> = %v, want [b]", got)
	}
	if got := deps["b"]; len(got) != 1 || got[0] != "a" {
		t.Fatalf("cycle edge b-> = %v, want [a]", got)
	}
}

// TestListKeepsSameCoordinatesScopedPerVersion registers multiple versions
// (and another artifact) that share component coordinates but differ in
// licenses and dependency edges, then asserts every license and dependency
// stays with its own manifest.
func TestListKeepsSameCoordinatesScopedPerVersion(t *testing.T) {
	st, _ := openCountingStore(t)
	ctx := context.Background()

	registerManifest(t, st, "app", "1", []model.Component{
		{Coordinate: "lib", License: "Apache-2.0", Dependencies: []string{"util"}},
		{Coordinate: "util", License: "BSD-3-Clause", Dependencies: []string{}},
	})
	registerManifest(t, st, "app", "2", []model.Component{
		{Coordinate: "lib", License: "GPL-3.0", Dependencies: []string{}},
		{Coordinate: "util", License: "MIT", Dependencies: []string{"lib"}},
	})
	registerManifest(t, st, "app", "3", []model.Component{
		{Coordinate: "lib", License: "ISC", Dependencies: []string{"util"}},
		{Coordinate: "util", License: "Unlicense", Dependencies: []string{"lib"}},
	})
	registerManifest(t, st, "vendor", "1", []model.Component{
		{Coordinate: "lib", License: "PROPRIETARY", Dependencies: []string{}},
		{Coordinate: "util", License: "PROPRIETARY", Dependencies: []string{}},
	})

	items, total, err := st.List(ctx, "app", 1, 100)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if total != 3 || len(items) != 3 {
		t.Fatalf("total/items = %d/%d, want 3/3", total, len(items))
	}

	want := []struct {
		version     string
		libLicense  string
		libDeps     []string
		utilLicense string
		utilDeps    []string
	}{
		{"1", "Apache-2.0", []string{"util"}, "BSD-3-Clause", []string{}},
		{"2", "GPL-3.0", []string{}, "MIT", []string{"lib"}},
		{"3", "ISC", []string{"util"}, "Unlicense", []string{"lib"}},
	}
	for i, w := range want {
		got := items[i]
		if got.Version != w.version {
			t.Fatalf("item %d version = %q, want %q", i, got.Version, w.version)
		}
		byCoord := map[string]model.Component{}
		for _, c := range got.Components {
			byCoord[c.Coordinate] = c
		}
		lib, util := byCoord["lib"], byCoord["util"]
		if lib.License != w.libLicense || !sameStrings(lib.Dependencies, w.libDeps) {
			t.Fatalf("version %s lib = %+v, want license %q deps %v", w.version, lib, w.libLicense, w.libDeps)
		}
		if util.License != w.utilLicense || !sameStrings(util.Dependencies, w.utilDeps) {
			t.Fatalf("version %s util = %+v, want license %q deps %v", w.version, util, w.utilLicense, w.utilDeps)
		}
	}
}

func sameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestListReadFailuresReturnUnavailable forces a failure at each of the four
// read steps. Every failure must surface model.ErrStorageUnavailable with no
// partial items.
func TestListReadFailuresReturnUnavailable(t *testing.T) {
	for _, kind := range []string{"count", "sboms", "components", "dependencies"} {
		t.Run(kind, func(t *testing.T) {
			st, counted := openCountingStore(t)
			registerManifest(t, st, "app", "1", twoComponents([]string{"b"}))
			counted.FailNextRead(kind)

			items, _, err := st.List(context.Background(), "app", 1, 20)
			if err == nil {
				t.Fatalf("expected failure on %s read", kind)
			}
			if !errors.Is(err, model.ErrStorageUnavailable) {
				t.Fatalf("error = %v, want model.ErrStorageUnavailable", err)
			}
			if items != nil {
				t.Fatalf("items = %v, want nil on failed read", items)
			}
		})
	}
}

// TestListSnapshotStaysConsistentUnderConcurrentWriters registers manifests
// while pages are read. Every returned manifest must be complete (never a
// half-written registration) and the page must never contradict its total.
func TestListSnapshotStaysConsistentUnderConcurrentWriters(t *testing.T) {
	st, _ := openCountingStore(t)
	ctx := context.Background()
	for i := 0; i < 5; i++ {
		registerManifest(t, st, "app", string(rune('a'+i)), twoComponents([]string{"b"}))
	}

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
			version := "writer-" +
				string(rune('a'+i%26)) +
				string(rune('a'+(i/26)%26)) +
				string(rune('a'+(i/676)%26))
			_, _, _ = st.Register(ctx, &model.SBOM{
				Artifact:   "app",
				Version:    version,
				Components: twoComponents([]string{"b"}),
			})
		}
	}()

	for i := 0; i < 50; i++ {
		items, total, err := st.List(ctx, "app", 1, 20)
		if err != nil {
			t.Fatalf("list during writes: %v", err)
		}
		if len(items) > 20 {
			t.Fatalf("page returned %d items, want at most 20", len(items))
		}
		if len(items) > total {
			t.Fatalf("items %d exceed total %d within one snapshot", len(items), total)
		}
		for _, item := range items {
			if item.Artifact != "app" || len(item.Components) != 2 {
				t.Fatalf("incomplete or foreign manifest visible: %+v", item)
			}
			deps := map[string][]string{}
			for _, c := range item.Components {
				deps[c.Coordinate] = c.Dependencies
			}
			if len(deps["a"]) != 1 || deps["a"][0] != "b" {
				t.Fatalf("partially written manifest visible: %+v", item)
			}
		}
	}
	close(stop)
	wg.Wait()
}
