package manifest

import (
	"fmt"
	"sort"

	"github.com/xjeey8iust/sen-sbom-inventory/internal/model"
)

// ComponentChange describes one coordinate present in both manifests whose
// license or direct dependency set changed. Before and After are the two
// complete components, from the old and the new manifest respectively.
type ComponentChange struct {
	Coordinate string          `json:"coordinate"`
	Before     model.Component `json:"before"`
	After      model.Component `json:"after"`
}

// Diff is the complete comparison result of two manifests of one artifact. It
// serializes directly as the GET /sboms/diff success body: the three diff
// arrays are always arrays (empty, never null) and sorted by coordinate, and
// every component's dependency list is sorted ascending by coordinate string.
// The manifest ID never appears here and never takes part in the comparison;
// the two versions are carried as identifiers only.
type Diff struct {
	Artifact    string            `json:"artifact"`
	FromVersion string            `json:"fromVersion"`
	ToVersion   string            `json:"toVersion"`
	Added       []model.Component `json:"added"`
	Removed     []model.Component `json:"removed"`
	Changed     []ComponentChange `json:"changed"`
}

// Compare diffs two manifests of one artifact — a *model.SBOM as produced by
// ParseRegistration or reconstructed by the store, including copies whose
// component and dependency arrays were merely reordered. It owns neither HTTP
// nor storage, so the GET /sboms/diff handler and plain Go callers share one
// rule set:
//
//   - a coordinate only in after is added; a coordinate only in before is
//     removed (a rename is therefore one removed plus one added, never a
//     change);
//   - a coordinate in both is changed only when its license or its set of
//     direct dependency coordinates differs. Direct edges are compared as
//     sets: transitive edges are not expanded, and a license change on a
//     dependency target does not propagate to the components referencing it;
//   - unchanged components are omitted. Comparing a manifest with itself (or
//     with an identical copy) yields three empty arrays; swapping the inputs
//     swaps added with removed and flips every changed entry's before/after.
//
// The artifact and the two versions in the result are copied from the inputs;
// the store-assigned ID is ignored. A nil manifest or two manifests of
// different artifacts are rejected with a nil result and an error that
// errors.Is recognizes as model.ErrInvalidInput.
//
// Compare never modifies its inputs, and the result shares no memory with
// them: mutating either input afterwards cannot change a returned Diff, and
// mutating a Diff cannot affect the inputs or any other call's result.
func Compare(before, after *model.SBOM) (*Diff, error) {
	if before == nil || after == nil {
		return nil, fmt.Errorf("compare manifests: %w", model.ErrInvalidInput)
	}
	if before.Artifact != after.Artifact {
		return nil, fmt.Errorf("compare manifests of artifacts %q and %q: %w",
			before.Artifact, after.Artifact, model.ErrInvalidInput)
	}

	oldByCoordinate := indexComponents(before.Components)
	newByCoordinate := indexComponents(after.Components)

	diff := &Diff{
		Artifact:    before.Artifact,
		FromVersion: before.Version,
		ToVersion:   after.Version,
		Added:       []model.Component{},
		Removed:     []model.Component{},
		Changed:     []ComponentChange{},
	}

	for coordinate, comp := range newByCoordinate {
		if _, exists := oldByCoordinate[coordinate]; !exists {
			diff.Added = append(diff.Added, copyComponent(comp))
		}
	}
	for coordinate, comp := range oldByCoordinate {
		if _, exists := newByCoordinate[coordinate]; !exists {
			diff.Removed = append(diff.Removed, copyComponent(comp))
		}
	}
	for coordinate, newComp := range newByCoordinate {
		oldComp, exists := oldByCoordinate[coordinate]
		if !exists {
			continue
		}
		if oldComp.License != newComp.License || !sameDependencySet(oldComp.Dependencies, newComp.Dependencies) {
			diff.Changed = append(diff.Changed, ComponentChange{
				Coordinate: coordinate,
				Before:     copyComponent(oldComp),
				After:      copyComponent(newComp),
			})
		}
	}

	sort.Slice(diff.Added, func(i, j int) bool { return diff.Added[i].Coordinate < diff.Added[j].Coordinate })
	sort.Slice(diff.Removed, func(i, j int) bool { return diff.Removed[i].Coordinate < diff.Removed[j].Coordinate })
	sort.Slice(diff.Changed, func(i, j int) bool { return diff.Changed[i].Coordinate < diff.Changed[j].Coordinate })
	return diff, nil
}

func indexComponents(components []model.Component) map[string]model.Component {
	byCoordinate := make(map[string]model.Component, len(components))
	for _, comp := range components {
		byCoordinate[comp.Coordinate] = comp
	}
	return byCoordinate
}

// copyComponent returns a deep copy with the dependency list sorted ascending
// and never nil, so the result is normalized regardless of the input's array
// order and stays independent of the input's memory.
func copyComponent(comp model.Component) model.Component {
	deps := make([]string, len(comp.Dependencies))
	copy(deps, comp.Dependencies)
	sort.Strings(deps)
	return model.Component{
		Coordinate:   comp.Coordinate,
		License:      comp.License,
		Dependencies: deps,
	}
}

// sameDependencySet compares direct dependency coordinates as sets, so two
// manifests whose dependency arrays list the same targets in different orders
// count as unchanged.
func sameDependencySet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	set := make(map[string]struct{}, len(a))
	for _, dep := range a {
		set[dep] = struct{}{}
	}
	for _, dep := range b {
		if _, ok := set[dep]; !ok {
			return false
		}
	}
	return true
}
