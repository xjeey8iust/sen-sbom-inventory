package manifest

import (
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

// Diff is the result of comparing two manifests of one artifact. The three
// diff arrays are always arrays (empty, never null) and sorted by coordinate.
// Artifact and Version are labels taken from the inputs, not database
// identity: the manifests' IDs never enter the result or the comparison.
type Diff struct {
	Artifact    string            `json:"artifact"`
	FromVersion string            `json:"fromVersion"`
	ToVersion   string            `json:"toVersion"`
	Added       []model.Component `json:"added"`
	Removed     []model.Component `json:"removed"`
	Changed     []ComponentChange `json:"changed"`
}

// Compare compares two validated manifests — outputs of ParseRegistration or
// full manifests reconstructed from storage — without HTTP or storage. The
// before manifest supplies the removed side and the Artifact/FromVersion
// labels; the after manifest supplies the added side and the ToVersion label.
//
// Components are indexed by coordinate, so the comparison never depends on
// the order arrays happened to carry:
//
//   - a coordinate only in after is added;
//   - a coordinate only in before is removed (a rename is therefore one
//     removed plus one added, never a change);
//   - a coordinate in both is changed only when its license or its set of
//     direct dependency coordinates differs. Direct edges are compared as
//     sets: transitive edges are not expanded, and a license change on a
//     dependency target does not propagate to the components referencing it.
//
// The inputs are never modified, and the components and dependencies held
// by the result are independent copies, so later changes to either manifest
// cannot reach an already returned Diff.
//
// A nil manifest on either side, or two manifests whose artifacts differ,
// are caller errors: Compare returns nil and an error that errors.Is
// recognizes as model.ErrInvalidInput.
func Compare(before, after *model.SBOM) (*Diff, error) {
	if before == nil || after == nil || before.Artifact != after.Artifact {
		return nil, model.ErrInvalidInput
	}

	oldByCoordinate := indexComponents(before.Components)
	newByCoordinate := indexComponents(after.Components)

	result := &Diff{
		Artifact:    before.Artifact,
		FromVersion: before.Version,
		ToVersion:   after.Version,
		Added:       []model.Component{},
		Removed:     []model.Component{},
		Changed:     []ComponentChange{},
	}

	// Copy every component placed in the result: components and their
	// dependency slices are owned by the caller, so the result must not
	// share storage with either input.
	for coordinate, comp := range newByCoordinate {
		if _, exists := oldByCoordinate[coordinate]; !exists {
			result.Added = append(result.Added, cloneComponent(comp))
		}
	}
	for coordinate, comp := range oldByCoordinate {
		if _, exists := newByCoordinate[coordinate]; !exists {
			result.Removed = append(result.Removed, cloneComponent(comp))
		}
	}
	for coordinate, newComp := range newByCoordinate {
		oldComp, exists := oldByCoordinate[coordinate]
		if !exists {
			continue
		}
		if oldComp.License != newComp.License || !sameDependencySet(oldComp.Dependencies, newComp.Dependencies) {
			result.Changed = append(result.Changed, ComponentChange{
				Coordinate: coordinate,
				Before:     cloneComponent(oldComp),
				After:      cloneComponent(newComp),
			})
		}
	}

	sort.Slice(result.Added, func(i, j int) bool { return result.Added[i].Coordinate < result.Added[j].Coordinate })
	sort.Slice(result.Removed, func(i, j int) bool { return result.Removed[i].Coordinate < result.Removed[j].Coordinate })
	sort.Slice(result.Changed, func(i, j int) bool { return result.Changed[i].Coordinate < result.Changed[j].Coordinate })
	return result, nil
}

func indexComponents(components []model.Component) map[string]model.Component {
	byCoordinate := make(map[string]model.Component, len(components))
	for _, comp := range components {
		byCoordinate[comp.Coordinate] = comp
	}
	return byCoordinate
}

// cloneComponent returns a component with its own, coordinate-sorted
// dependency slice. The coordinates themselves are immutable strings, so
// the slice is the only shared storage to break; sorting it makes the
// result canonical even when an input only had its array order adjusted.
func cloneComponent(comp model.Component) model.Component {
	deps := append([]string{}, comp.Dependencies...)
	sort.Strings(deps)
	comp.Dependencies = deps
	return comp
}

// sameDependencySet compares direct dependency coordinates as sets, so two
// manifests whose dependency arrays list the same targets in different orders
// count as unchanged. Parsed manifests already sort and de-duplicate these
// arrays; comparing as sets makes the order-independence contract explicit.
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
