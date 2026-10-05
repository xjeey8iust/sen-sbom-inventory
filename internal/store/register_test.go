package store

import (
	"context"
	"errors"
	"testing"

	"github.com/xjeey8iust/sen-sbom-inventory/internal/model"
)

// TestRegisterAndListShareReconstruction proves the registration read path
// (Register's idempotency reload of the stored manifest) and the paged read
// path (List) rebuild the same manifest from storage: a replayed registration
// and a paged query must both return the stored record exactly as first
// registered, including a legal dependency cycle.
func TestRegisterAndListShareReconstruction(t *testing.T) {
	st, _ := openCountingStore(t)
	ctx := context.Background()

	components := []model.Component{
		{Coordinate: "a", License: "Apache-2.0", Dependencies: []string{"b", "c"}},
		{Coordinate: "b", License: "MIT", Dependencies: []string{"a"}},
		{Coordinate: "c", License: "BSD-3-Clause", Dependencies: []string{}},
	}
	first := registerManifest(t, st, "app", "1", components)

	// Re-registering the same normalized content makes Register reload the
	// stored manifest through the shared reconstruction loaders.
	replayed, created, err := st.Register(ctx, &model.SBOM{
		Artifact: "app", Version: "1", Components: components,
	})
	if err != nil {
		t.Fatalf("replay register: %v", err)
	}
	if created {
		t.Fatalf("replay created a new record, want the existing one")
	}

	items, total, err := st.List(ctx, "app", 1, 20)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if total != 1 || len(items) != 1 {
		t.Fatalf("total/items = %d/%d, want 1/1", total, len(items))
	}

	assertSameManifest(t, first, replayed)
	assertSameManifest(t, first, items[0])
}

func assertSameManifest(t *testing.T, want, got *model.SBOM) {
	t.Helper()
	if got.ID != want.ID || got.Artifact != want.Artifact || got.Version != want.Version {
		t.Fatalf("identity = %d/%q/%q, want %d/%q/%q",
			got.ID, got.Artifact, got.Version, want.ID, want.Artifact, want.Version)
	}
	if len(got.Components) != len(want.Components) {
		t.Fatalf("components len = %d, want %d", len(got.Components), len(want.Components))
	}
	for i := range want.Components {
		w, g := want.Components[i], got.Components[i]
		if w.Coordinate != g.Coordinate || w.License != g.License ||
			!sameStrings(w.Dependencies, g.Dependencies) {
			t.Fatalf("component %d = %+v, want %+v", i, g, w)
		}
	}
}

// TestRegisterReadFailureReturnsUnavailable forces a failure at each read step
// of Register's idempotency reload. Every failure must surface as
// model.ErrStorageUnavailable and leave the stored record untouched.
func TestRegisterReadFailureReturnsUnavailable(t *testing.T) {
	for _, kind := range []string{"sboms", "components", "dependencies"} {
		t.Run(kind, func(t *testing.T) {
			st, counted := openCountingStore(t)
			registerManifest(t, st, "app", "1", twoComponents([]string{"b"}))
			counted.FailNextRead(kind)

			_, _, err := st.Register(context.Background(), &model.SBOM{
				Artifact: "app", Version: "1", Components: twoComponents([]string{"b"}),
			})
			if err == nil {
				t.Fatalf("expected failure on %s read", kind)
			}
			if !errors.Is(err, model.ErrStorageUnavailable) {
				t.Fatalf("error = %v, want model.ErrStorageUnavailable", err)
			}

			// The failed replay must not have modified the stored manifest.
			counted.Reset()
			items, total, err := st.List(context.Background(), "app", 1, 20)
			if err != nil {
				t.Fatalf("list after failed register: %v", err)
			}
			if total != 1 || len(items) != 1 {
				t.Fatalf("total/items after failed register = %d/%d, want 1/1", total, len(items))
			}
			want := &model.SBOM{
				ID: items[0].ID, Artifact: "app", Version: "1",
				Components: twoComponents([]string{"b"}),
			}
			assertSameManifest(t, want, items[0])
		})
	}
}

// TestRegisterWriteFailureReturnsUnavailable forces a failure on each detail
// insert (components, then dependencies). Every failure must surface as
// model.ErrStorageUnavailable, leave no partial records behind, and keep the
// pre-existing manifests intact; once the fault clears, registrations and
// queries must complete normally again.
func TestRegisterWriteFailureReturnsUnavailable(t *testing.T) {
	for _, kind := range []string{"components", "dependencies"} {
		t.Run(kind, func(t *testing.T) {
			st, counted := openCountingStore(t)
			ctx := context.Background()
			kept := registerManifest(t, st, "app", "keep", twoComponents([]string{"b"}))

			detail := []model.Component{
				{Coordinate: "a", License: "L-a", Dependencies: []string{"b"}},
				{Coordinate: "b", License: "L-b", Dependencies: []string{}},
			}
			counted.FailNextWrite(kind)
			_, _, err := st.Register(ctx, &model.SBOM{
				Artifact: "app", Version: "1", Components: detail,
			})
			if err == nil {
				t.Fatalf("expected failure on %s write", kind)
			}
			if !errors.Is(err, model.ErrStorageUnavailable) {
				t.Fatalf("error = %v, want model.ErrStorageUnavailable", err)
			}

			// Fault cleared: the failed registration must not be queryable and
			// the pre-existing manifest must be complete.
			counted.Reset()
			items, total, err := st.List(ctx, "app", 1, 20)
			if err != nil {
				t.Fatalf("list after failed register: %v", err)
			}
			if total != 1 || len(items) != 1 {
				t.Fatalf("total/items after failed register = %d/%d, want 1/1", total, len(items))
			}
			assertSameManifest(t, kept, items[0])

			// Retrying the failed registration now succeeds as a new record.
			got, created, err := st.Register(ctx, &model.SBOM{
				Artifact: "app", Version: "1", Components: detail,
			})
			if err != nil {
				t.Fatalf("register after fault cleared: %v", err)
			}
			if !created {
				t.Fatalf("register after fault cleared: not created")
			}
			assertSameManifest(t, got, &model.SBOM{
				ID: got.ID, Artifact: "app", Version: "1", Components: detail,
			})
		})
	}
}
