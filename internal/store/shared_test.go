package store

import (
	"context"
	"testing"

	"github.com/xjeey8iust/sen-sbom-inventory/internal/manifest"
	"github.com/xjeey8iust/sen-sbom-inventory/internal/model"
)

// TestReadPathsShareReconstruction is the cross-path regression for the
// shared main-record rule: the same stored manifest must come back identical
// whether it is rebuilt by Register's idempotency reload (loadSBOM), List's
// paged scan or Diff's paired-version scan. Components stay coordinate-sorted
// with non-nil dependency slices (a legal self-cycle included), and two
// versions with identical content compare as fully unchanged.
func TestReadPathsShareReconstruction(t *testing.T) {
	for _, tc := range []struct {
		name  string
		comps []model.Component
	}{
		{
			name: "components with a legal dependency cycle",
			comps: []model.Component{
				{Coordinate: "a", License: "A", Dependencies: []string{"b", "c"}},
				{Coordinate: "b", License: "B", Dependencies: []string{"a"}},
				{Coordinate: "c", License: "C", Dependencies: []string{}},
			},
		},
		{
			name:  "manifest without components",
			comps: []model.Component{},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st, _ := openCountingStore(t)
			ctx := context.Background()
			registered := registerManifest(t, st, "app", "1", tc.comps)

			// Path 1: Register's existing-record reload (loadSBOM).
			replayed, created, err := st.Register(ctx, &model.SBOM{
				Artifact: "app", Version: "1", Components: tc.comps,
			})
			if err != nil || created {
				t.Fatalf("replay register: err=%v created=%v", err, created)
			}

			// Path 2: List's paged main-record scan.
			items, total, err := st.List(ctx, "app", 1, 20)
			if err != nil {
				t.Fatalf("list: %v", err)
			}
			if total != 1 || len(items) != 1 {
				t.Fatalf("total/items = %d/%d, want 1/1", total, len(items))
			}
			listed := items[0]

			// Path 3: Diff's paired-version scan. A second version carries
			// identical content, so the shared loaders must rebuild equal
			// component and dependency sets for both sides.
			registerManifest(t, st, "app", "2", tc.comps)
			from, to, err := st.Diff(ctx, "app", "1", "2")
			if err != nil {
				t.Fatalf("diff: %v", err)
			}

			got := [][]model.Component{
				registered.Components,
				replayed.Components,
				listed.Components,
				from.Components,
				to.Components,
			}
			for i := 1; i < len(got); i++ {
				assertSameComponentSet(t, got[0], got[i])
			}

			// Identical license/direct-dependency content means the
			// comparison itself reports no movement.
			diff, err := manifest.Compare(from, to)
			if err != nil {
				t.Fatalf("compare: %v", err)
			}
			if len(diff.Added) != 0 || len(diff.Removed) != 0 || len(diff.Changed) != 0 {
				t.Fatalf("identical versions differ: %+v", diff)
			}
		})
	}
}

// assertSameComponentSet compares reconstructed component slices exactly:
// every read path must preserve coordinate order, license ownership and the
// sorted non-nil dependency slice of each component.
func assertSameComponentSet(t *testing.T, want, got []model.Component) {
	t.Helper()
	if len(want) != len(got) {
		t.Fatalf("component len = %d, want %d (%+v vs %+v)", len(got), len(want), got, want)
	}
	for i := range want {
		w, g := want[i], got[i]
		if w.Coordinate != g.Coordinate || w.License != g.License {
			t.Fatalf("component %d = %+v, want %+v", i, g, w)
		}
		if g.Dependencies == nil && len(w.Dependencies) != 0 {
			t.Fatalf("component %q dependencies nil, want %v", g.Coordinate, w.Dependencies)
		}
		if !sameStrings(w.Dependencies, g.Dependencies) {
			t.Fatalf("component %q dependencies = %v, want %v", g.Coordinate, g.Dependencies, w.Dependencies)
		}
	}
}
