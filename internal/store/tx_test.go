package store

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/xjeey8iust/sen-sbom-inventory/internal/model"
)

// twoComponentsWithDep is the canonical manifest used by the lifecycle tests:
// two components and one dependency edge, so both detail tables hold rows.
func twoComponentsWithDep() []model.Component {
	return twoComponents([]string{"b"})
}

// TestRegisterDetailWriteFailureRollsBack forces each detail-write step
// (component insert and dependency insert) to fail once. The failed
// registration must surface model.ErrStorageUnavailable, leave no partial
// record, and once the fault is gone the same registration must complete and
// read back whole — proving the rollback ran, the connection was returned and
// the unified lifecycle recovers.
func TestRegisterDetailWriteFailureRollsBack(t *testing.T) {
	for _, kind := range []string{"components", "dependencies"} {
		t.Run(kind, func(t *testing.T) {
			st, counted := openCountingStore(t)
			ctx := context.Background()

			// A pre-existing, unrelated manifest that must survive the failure.
			registerManifest(t, st, "other", "1", []model.Component{
				{Coordinate: "keep", License: "K", Dependencies: []string{}},
			})
			counted.Reset()

			counted.FailNextWrite(kind)
			sbom, created, err := st.Register(ctx, &model.SBOM{
				Artifact: "app", Version: "1", Components: twoComponentsWithDep(),
			})
			if err == nil {
				t.Fatalf("expected %s write failure", kind)
			}
			if !errors.Is(err, model.ErrStorageUnavailable) {
				t.Fatalf("error = %v, want model.ErrStorageUnavailable", err)
			}
			if sbom != nil || created {
				t.Fatalf("failed register returned sbom=%v created=%v", sbom, created)
			}

			// The fault was one-shot; reset counters, then prove no partial
			// record is visible under the failed key.
			counted.Reset()
			items, total, err := st.List(ctx, "app", 1, 20)
			if err != nil {
				t.Fatalf("list after failed register: %v", err)
			}
			if total != 0 || len(items) != 0 {
				t.Fatalf("partial registration visible: total=%d items=%d", total, len(items))
			}

			// The unrelated manifest is untouched.
			others, otherTotal, err := st.List(ctx, "other", 1, 20)
			if err != nil {
				t.Fatalf("list other: %v", err)
			}
			if otherTotal != 1 || len(others) != 1 || len(others[0].Components) != 1 {
				t.Fatalf("unrelated manifest changed: total=%d items=%d", otherTotal, len(others))
			}

			// Fault cleared: the same registration now completes normally.
			got, created, err := st.Register(ctx, &model.SBOM{
				Artifact: "app", Version: "1", Components: twoComponentsWithDep(),
			})
			if err != nil {
				t.Fatalf("register after recovery: %v", err)
			}
			if !created {
				t.Fatalf("register after recovery was not created")
			}

			// The recovered manifest reads back complete from one snapshot.
			items, total, err = st.List(ctx, "app", 1, 20)
			if err != nil {
				t.Fatalf("list after recovery: %v", err)
			}
			if total != 1 || len(items) != 1 {
				t.Fatalf("total/items after recovery = %d/%d, want 1/1", total, len(items))
			}
			assertSameManifest(t, got, items[0])
			if len(items[0].Components) != 2 {
				t.Fatalf("recovered manifest incomplete: %+v", items[0])
			}
			deps := map[string][]string{}
			for _, c := range items[0].Components {
				deps[c.Coordinate] = c.Dependencies
			}
			if len(deps["a"]) != 1 || deps["a"][0] != "b" {
				t.Fatalf("recovered dependency edge missing: %+v", deps)
			}
		})
	}
}

// TestRollbackFailureKeepsOriginalError forces a detail-write failure and a
// ROLLBACK failure together. The cleanup error must be swallowed: the caller
// still sees the original storage error, the transaction is actually undone
// (no partial record) and the connection stays usable afterwards.
func TestRollbackFailureKeepsOriginalError(t *testing.T) {
	st, counted := openCountingStore(t)
	ctx := context.Background()
	registerManifest(t, st, "app", "1", twoComponentsWithDep())

	counted.FailNextWrite("components")
	counted.FailNextRollback()

	_, _, err := st.Register(ctx, &model.SBOM{
		Artifact: "app", Version: "2", Components: twoComponentsWithDep(),
	})
	if !errors.Is(err, model.ErrStorageUnavailable) {
		t.Fatalf("error = %v, want model.ErrStorageUnavailable", err)
	}
	if !strings.Contains(err.Error(), "forced write failure") {
		t.Fatalf("error lost the original write cause: %v", err)
	}
	if strings.Contains(err.Error(), "forced rollback failure") {
		t.Fatalf("rollback cleanup error overwrote the storage error: %v", err)
	}

	// The failed registration is invisible; the original manifest is intact.
	items, total, err := st.List(ctx, "app", 1, 20)
	if err != nil {
		t.Fatalf("list after cleanup failure: %v", err)
	}
	if total != 1 || len(items) != 1 {
		t.Fatalf("total/items = %d/%d, want 1/1", total, len(items))
	}
	assertSameManifest(t, &model.SBOM{
		ID: items[0].ID, Artifact: "app", Version: "1",
		Components: twoComponentsWithDep(),
	}, items[0])

	// The connection was actually returned in a clean state and can serve the
	// retried registration.
	registerManifest(t, st, "app", "2", twoComponentsWithDep())
}

// TestConflictReturnSurvivesRollbackFailure exercises the early business exit:
// a conflicting registration ends in ROLLBACK, and even when that cleanup
// reports failure the caller must still receive model.ErrConflict, with the
// original record unchanged.
func TestConflictReturnSurvivesRollbackFailure(t *testing.T) {
	st, counted := openCountingStore(t)
	ctx := context.Background()
	registerManifest(t, st, "app", "1", twoComponentsWithDep())

	counted.FailNextRollback()
	_, _, err := st.Register(ctx, &model.SBOM{
		Artifact: "app", Version: "1",
		Components: []model.Component{
			{Coordinate: "a", License: "CHANGED", Dependencies: []string{"b"}},
			{Coordinate: "b", License: "L-b", Dependencies: []string{}},
		},
	})
	if !errors.Is(err, model.ErrConflict) {
		t.Fatalf("error = %v, want model.ErrConflict", err)
	}
	if strings.Contains(err.Error(), "forced rollback failure") {
		t.Fatalf("cleanup error replaced the business error: %v", err)
	}

	// An identical replay still returns the original record afterwards, so the
	// connection stayed usable and the record is unchanged.
	replayed, created, err := st.Register(ctx, &model.SBOM{
		Artifact: "app", Version: "1", Components: twoComponentsWithDep(),
	})
	if err != nil || created {
		t.Fatalf("replay after failed cleanup: err=%v created=%v", err, created)
	}
	items, total, err := st.List(ctx, "app", 1, 20)
	if err != nil || total != 1 || len(items) != 1 {
		t.Fatalf("record changed after conflict cleanup: err=%v total=%d items=%d", err, total, len(items))
	}
	assertSameManifest(t, replayed, items[0])
}
