package api

import (
	"net/http"
	"sort"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/xjeey8iust/sen-sbom-inventory/internal/model"
)

// diff handles GET /sboms/diff. Versions are identifiers only — the endpoint
// never infers which one is newer, so the request names an explicit old
// (fromVersion) and new (toVersion) manifest of one artifact.
func (h *sbomHandlers) diff(c *gin.Context) {
	artifact := strings.TrimSpace(c.Query("artifact"))
	fromVersion := strings.TrimSpace(c.Query("fromVersion"))
	toVersion := strings.TrimSpace(c.Query("toVersion"))
	// Missing and blank-after-trimming collapse to the same rejection.
	if artifact == "" || fromVersion == "" || toVersion == "" {
		writeAPIError(c, http.StatusBadRequest, invalidInputCode, invalidInputMessage)
		return
	}

	before, after, err := h.store.Diff(c.Request.Context(), artifact, fromVersion, toVersion)
	if err != nil {
		writeStoreError(c, err)
		return
	}
	c.JSON(http.StatusOK, buildDiff(artifact, fromVersion, toVersion, before, after))
}

// componentChange describes one coordinate present in both manifests whose
// license or direct dependency set changed. Before and After are the two
// complete components, from the old and the new manifest respectively.
type componentChange struct {
	Coordinate string          `json:"coordinate"`
	Before     model.Component `json:"before"`
	After      model.Component `json:"after"`
}

// diffResponse is the complete success body. The three diff arrays are always
// arrays (empty, never null) and sorted by coordinate.
type diffResponse struct {
	Artifact    string            `json:"artifact"`
	FromVersion string            `json:"fromVersion"`
	ToVersion   string            `json:"toVersion"`
	Added       []model.Component `json:"added"`
	Removed     []model.Component `json:"removed"`
	Changed     []componentChange `json:"changed"`
}

// buildDiff compares two reconstructed manifests. Components are indexed by
// coordinate, so the comparison never depends on the order arrays happened to
// have at registration time:
//
//   - a coordinate only in the new manifest is added;
//   - a coordinate only in the old manifest is removed (a rename is therefore
//     one removed plus one added, never a change);
//   - a coordinate in both is changed only when its license or its set of
//     direct dependency coordinates differs. Direct edges are compared as
//     sets: transitive edges are not expanded, and a license change on a
//     dependency target does not propagate to the components referencing it.
func buildDiff(artifact, fromVersion, toVersion string, before, after *model.SBOM) diffResponse {
	oldByCoordinate := indexComponents(before.Components)
	newByCoordinate := indexComponents(after.Components)

	resp := diffResponse{
		Artifact:    artifact,
		FromVersion: fromVersion,
		ToVersion:   toVersion,
		Added:       []model.Component{},
		Removed:     []model.Component{},
		Changed:     []componentChange{},
	}

	for coordinate, comp := range newByCoordinate {
		if _, exists := oldByCoordinate[coordinate]; !exists {
			resp.Added = append(resp.Added, comp)
		}
	}
	for coordinate, comp := range oldByCoordinate {
		if _, exists := newByCoordinate[coordinate]; !exists {
			resp.Removed = append(resp.Removed, comp)
		}
	}
	for coordinate, newComp := range newByCoordinate {
		oldComp, exists := oldByCoordinate[coordinate]
		if !exists {
			continue
		}
		if oldComp.License != newComp.License || !sameDependencySet(oldComp.Dependencies, newComp.Dependencies) {
			resp.Changed = append(resp.Changed, componentChange{
				Coordinate: coordinate,
				Before:     oldComp,
				After:      newComp,
			})
		}
	}

	sort.Slice(resp.Added, func(i, j int) bool { return resp.Added[i].Coordinate < resp.Added[j].Coordinate })
	sort.Slice(resp.Removed, func(i, j int) bool { return resp.Removed[i].Coordinate < resp.Removed[j].Coordinate })
	sort.Slice(resp.Changed, func(i, j int) bool { return resp.Changed[i].Coordinate < resp.Changed[j].Coordinate })
	return resp
}

func indexComponents(components []model.Component) map[string]model.Component {
	byCoordinate := make(map[string]model.Component, len(components))
	for _, comp := range components {
		byCoordinate[comp.Coordinate] = comp
	}
	return byCoordinate
}

// sameDependencySet compares direct dependency coordinates as sets, so two
// manifests whose dependency arrays list the same targets in different orders
// count as unchanged. Registration already sorts and de-duplicates these
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
