package store

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"testing"
)

func openTestStore(t *testing.T) *Store {
	t.Helper()
	st, err := Open(filepath.Join(t.TempDir(), "store.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func sampleComponents() []Component {
	return []Component{
		{Coordinate: "pkg-b", License: "MIT", Dependencies: []string{"pkg-a"}},
		{Coordinate: "pkg-a", License: "Apache-2.0", Dependencies: []string{}},
	}
}

func TestRegisterSBOMInsertsAndRelationsPersist(t *testing.T) {
	st := openTestStore(t)
	ctx := context.Background()

	outcome, err := st.RegisterSBOM(ctx, "artifact-x", "1.0", sampleComponents())
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if !outcome.Created || outcome.SBOM.ID < 1 {
		t.Fatalf("outcome = %+v, want created with positive id", outcome)
	}

	got, _, err := st.ListSBOMs(ctx, "artifact-x", 1, 20)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("items = %d, want 1", len(got))
	}
	want := []Component{
		{Coordinate: "pkg-a", License: "Apache-2.0", Dependencies: []string{}},
		{Coordinate: "pkg-b", License: "MIT", Dependencies: []string{"pkg-a"}},
	}
	if !reflect.DeepEqual(got[0].Components, want) {
		t.Fatalf("components = %+v, want %+v", got[0].Components, want)
	}
}

func TestRegisterSBOMIsIdempotentRegardlessOfOrder(t *testing.T) {
	st := openTestStore(t)
	ctx := context.Background()

	first, err := st.RegisterSBOM(ctx, "artifact-x", "1.0", []Component{
		{Coordinate: "a", License: "MIT", Dependencies: []string{"b"}},
		{Coordinate: "b", License: "MIT", Dependencies: nil},
	})
	if err != nil {
		t.Fatalf("first register: %v", err)
	}

	// Components and dependencies submitted in different order.
	second, err := st.RegisterSBOM(ctx, "artifact-x", "1.0", []Component{
		{Coordinate: "b", License: "MIT", Dependencies: []string{}},
		{Coordinate: "a", License: "MIT", Dependencies: []string{"b"}},
	})
	if err != nil {
		t.Fatalf("second register: %v", err)
	}
	if second.Created {
		t.Fatalf("second register reported Created = true")
	}
	if second.SBOM.ID != first.SBOM.ID {
		t.Fatalf("id changed: %d != %d", second.SBOM.ID, first.SBOM.ID)
	}
}

func TestRegisterSBOMConflictCases(t *testing.T) {
	ctx := context.Background()
	cases := map[string][]Component{
		"component set differs": {
			{Coordinate: "a", License: "MIT", Dependencies: []string{}},
		},
		"license differs": {
			{Coordinate: "a", License: "GPL-3.0", Dependencies: []string{}},
			{Coordinate: "b", License: "MIT", Dependencies: []string{}},
		},
		"dependency relation differs": {
			{Coordinate: "a", License: "MIT", Dependencies: []string{"b"}},
			{Coordinate: "b", License: "MIT", Dependencies: []string{}},
		},
	}
	for name, changed := range cases {
		t.Run(name, func(t *testing.T) {
			st := openTestStore(t)
			original := []Component{
				{Coordinate: "a", License: "MIT", Dependencies: []string{}},
				{Coordinate: "b", License: "MIT", Dependencies: []string{}},
			}
			if _, err := st.RegisterSBOM(ctx, "artifact-x", "1.0", original); err != nil {
				t.Fatalf("seed: %v", err)
			}
			if _, err := st.RegisterSBOM(ctx, "artifact-x", "1.0", changed); !errors.Is(err, ErrConflict) {
				t.Fatalf("err = %v, want ErrConflict", err)
			}

			// The original record stays untouched.
			items, total, err := st.ListSBOMs(ctx, "artifact-x", 1, 20)
			if err != nil {
				t.Fatalf("list: %v", err)
			}
			if total != 1 || len(items) != 1 {
				t.Fatalf("total/items = %d/%d, want 1/1", total, len(items))
			}
			if got := items[0].Components; !reflect.DeepEqual(got, original) {
				t.Fatalf("stored components = %+v, want original %+v", got, original)
			}
		})
	}
}

func TestRegisterSBOMAllowsDependencyCycles(t *testing.T) {
	st := openTestStore(t)
	ctx := context.Background()

	cyclic := []Component{
		{Coordinate: "a", License: "MIT", Dependencies: []string{"b"}},
		{Coordinate: "b", License: "MIT", Dependencies: []string{"a"}},
	}
	outcome, err := st.RegisterSBOM(ctx, "artifact-x", "1.0", cyclic)
	if err != nil {
		t.Fatalf("register cyclic: %v", err)
	}
	if !outcome.Created {
		t.Fatalf("cyclic manifest was not created")
	}
}

func TestRegisterSBOMSurvivesReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "store.db")
	ctx := context.Background()

	st, err := Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if _, err := st.RegisterSBOM(ctx, "artifact-x", "1.0", sampleComponents()); err != nil {
		t.Fatalf("register: %v", err)
	}
	if err := st.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	reopened, err := Open(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer reopened.Close()

	outcome, err := reopened.RegisterSBOM(ctx, "artifact-x", "1.0", []Component{
		{Coordinate: "pkg-a", License: "Apache-2.0", Dependencies: nil},
		{Coordinate: "pkg-b", License: "MIT", Dependencies: []string{"pkg-a"}},
	})
	if err != nil {
		t.Fatalf("re-register after reopen: %v", err)
	}
	if outcome.Created || outcome.SBOM.ID != 1 {
		t.Fatalf("outcome = %+v, want existing record id 1", outcome)
	}

	items, total, err := reopened.ListSBOMs(ctx, "artifact-x", 1, 20)
	if err != nil {
		t.Fatalf("list after reopen: %v", err)
	}
	if total != 1 || len(items) != 1 || items[0].Artifact != "artifact-x" || items[0].Version != "1.0" {
		t.Fatalf("unexpected persisted data: total=%d items=%+v", total, items)
	}
}

func TestListSBOMsPaginatesByArtifact(t *testing.T) {
	st := openTestStore(t)
	ctx := context.Background()

	empty := []Component{}
	for i := 0; i < 3; i++ {
		if _, err := st.RegisterSBOM(ctx, "lib-paged", versions[i], empty); err != nil {
			t.Fatalf("seed %d: %v", i, err)
		}
	}
	if _, err := st.RegisterSBOM(ctx, "other-lib", "1.0", empty); err != nil {
		t.Fatalf("seed other: %v", err)
	}

	items, total, err := st.ListSBOMs(ctx, "lib-paged", 1, 2)
	if err != nil {
		t.Fatalf("page 1: %v", err)
	}
	if total != 3 || len(items) != 2 {
		t.Fatalf("page 1 total/items = %d/%d, want 3/2", total, len(items))
	}
	if items[0].ID >= items[1].ID {
		t.Fatalf("page not ordered by id ascending: %d, %d", items[0].ID, items[1].ID)
	}

	items, total, err = st.ListSBOMs(ctx, "lib-paged", 2, 2)
	if err != nil {
		t.Fatalf("page 2: %v", err)
	}
	if total != 3 || len(items) != 1 {
		t.Fatalf("page 2 total/items = %d/%d, want 3/1", total, len(items))
	}

	// Unknown artifact and a page past the end both yield an empty page.
	items, total, err = st.ListSBOMs(ctx, "unknown", 1, 20)
	if err != nil {
		t.Fatalf("unknown artifact: %v", err)
	}
	if total != 0 || len(items) != 0 {
		t.Fatalf("unknown artifact total/items = %d/%d, want 0/0", total, len(items))
	}
	items, _, err = st.ListSBOMs(ctx, "lib-paged", 9, 2)
	if err != nil {
		t.Fatalf("past last page: %v", err)
	}
	if len(items) != 0 {
		t.Fatalf("past-last-page items = %d, want 0", len(items))
	}
}

var versions = []string{"1.0", "2.0", "3.0"}
