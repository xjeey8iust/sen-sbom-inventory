package api

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"sort"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/xjeey8iust/sen-sbom-inventory/internal/store"
)

// maxSBOMBody caps how much manifest JSON a single request may carry.
const maxSBOMBody = 8 << 20

const (
	codeInvalidInput   = "InvalidSbomInputError"
	codeConflict       = "SbomConflictError"
	codeStorageUnavail = "storage_unavailable"

	msgInvalidInput       = "the SBOM payload is not valid"
	msgConflict           = "the submitted SBOM conflicts with the registered manifest"
	msgStorageUnavailable = "database is not available"
)

// componentJSON is the published shape of one component.
type componentJSON struct {
	Coordinate   string   `json:"coordinate"`
	License      string   `json:"license"`
	Dependencies []string `json:"dependencies"`
}

// sbomJSON is the published shape of one complete manifest.
type sbomJSON struct {
	ID         int64           `json:"id"`
	Artifact   string          `json:"artifact"`
	Version    string          `json:"version"`
	Components []componentJSON `json:"components"`
}

func toSBOMJSON(s *store.SBOM) sbomJSON {
	components := make([]componentJSON, 0, len(s.Components))
	for _, comp := range s.Components {
		dependencies := comp.Dependencies
		if dependencies == nil {
			dependencies = []string{}
		}
		components = append(components, componentJSON{
			Coordinate:   comp.Coordinate,
			License:      comp.License,
			Dependencies: dependencies,
		})
	}
	return sbomJSON{
		ID:         s.ID,
		Artifact:   s.Artifact,
		Version:    s.Version,
		Components: components,
	}
}

func respondError(c *gin.Context, status int, code, message string) {
	c.JSON(status, gin.H{"error": gin.H{"code": code, "message": message}})
}

// registerSBOM handles POST /sboms.
func registerSBOM(st *store.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		artifact, version, components, ok := parseSBOMInput(c.Request.Body)
		if !ok {
			respondError(c, http.StatusBadRequest, codeInvalidInput, msgInvalidInput)
			return
		}

		outcome, err := st.RegisterSBOM(c.Request.Context(), artifact, version, components)
		if err != nil {
			if errors.Is(err, store.ErrConflict) {
				respondError(c, http.StatusConflict, codeConflict, msgConflict)
				return
			}
			respondError(c, http.StatusServiceUnavailable, codeStorageUnavail, msgStorageUnavailable)
			return
		}
		// Identical re-registration answers 201 with the original record, so
		// Created does not change the status code.
		c.JSON(http.StatusCreated, toSBOMJSON(outcome.SBOM))
	}
}

// listSBOMs handles GET /sboms?artifact=...&page=...&pageSize=...
func listSBOMs(st *store.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		artifact := strings.TrimSpace(c.Query("artifact"))
		if artifact == "" {
			respondError(c, http.StatusBadRequest, codeInvalidInput, msgInvalidInput)
			return
		}
		page, ok := parsePositiveDecimal(c.Query("page"), 1)
		if !ok {
			respondError(c, http.StatusBadRequest, codeInvalidInput, msgInvalidInput)
			return
		}
		pageSize, ok := parsePositiveDecimal(c.Query("pageSize"), 20)
		if !ok || pageSize > 100 {
			respondError(c, http.StatusBadRequest, codeInvalidInput, msgInvalidInput)
			return
		}

		items, total, err := st.ListSBOMs(c.Request.Context(), artifact, page, pageSize)
		if err != nil {
			respondError(c, http.StatusServiceUnavailable, codeStorageUnavail, msgStorageUnavailable)
			return
		}

		encoded := make([]sbomJSON, 0, len(items))
		for _, item := range items {
			encoded = append(encoded, toSBOMJSON(item))
		}
		c.JSON(http.StatusOK, gin.H{
			"items":    encoded,
			"total":    total,
			"page":     page,
			"pageSize": pageSize,
		})
	}
}

// parsePositiveDecimal parses an optional positive decimal integer query
// parameter. An absent or empty value yields the given default. Leading zeros
// are accepted; signs, fractions and other characters are not.
func parsePositiveDecimal(raw string, fallback int) (int, bool) {
	if raw == "" {
		return fallback, true
	}
	value := 0
	for _, r := range raw {
		if r < '0' || r > '9' {
			return 0, false
		}
		value = value*10 + int(r-'0')
	}
	if value < 1 {
		return 0, false
	}
	return value, true
}

// parseSBOMInput validates and normalizes a manifest request body. The boolean
// result is false for every InvalidSbomInputError case: the body must be one
// JSON object; artifact, version and components must be present with the
// documented types; strings must be non-empty after trimming; coordinates and
// dependencies must be distinct; dependencies must reference components in the
// same manifest and must not self-reference. Dependency cycles between
// distinct components are allowed.
func parseSBOMInput(body io.ReadCloser) (string, string, []store.Component, bool) {
	rawBody, err := io.ReadAll(io.LimitReader(body, maxSBOMBody))
	if err != nil {
		return "", "", nil, false
	}
	trimmed := strings.TrimSpace(string(rawBody))
	if trimmed == "" || trimmed[0] != '{' {
		return "", "", nil, false
	}

	var top map[string]json.RawMessage
	if err := json.Unmarshal(rawBody, &top); err != nil {
		return "", "", nil, false
	}

	artifact, ok := decodeJSONString(top["artifact"])
	if !ok {
		return "", "", nil, false
	}
	version, ok := decodeJSONString(top["version"])
	if !ok {
		return "", "", nil, false
	}
	artifact = strings.TrimSpace(artifact)
	version = strings.TrimSpace(version)
	if artifact == "" || version == "" {
		return "", "", nil, false
	}

	rawComponents, present := top["components"]
	if !present || len(rawComponents) == 0 || rawComponents[0] != '[' {
		return "", "", nil, false
	}
	var rawComponentList []json.RawMessage
	if err := json.Unmarshal(rawComponents, &rawComponentList); err != nil {
		return "", "", nil, false
	}

	coordinates := make(map[string]struct{}, len(rawComponentList))
	components := make([]store.Component, 0, len(rawComponentList))
	for _, rawComponent := range rawComponentList {
		if len(rawComponent) == 0 || rawComponent[0] != '{' {
			return "", "", nil, false
		}
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(rawComponent, &fields); err != nil {
			return "", "", nil, false
		}
		coordinate, ok := decodeJSONString(fields["coordinate"])
		if !ok {
			return "", "", nil, false
		}
		license, ok := decodeJSONString(fields["license"])
		if !ok {
			return "", "", nil, false
		}
		rawDependencies, present := fields["dependencies"]
		if !present || len(rawDependencies) == 0 || rawDependencies[0] != '[' {
			return "", "", nil, false
		}
		var rawDependencyList []json.RawMessage
		if err := json.Unmarshal(rawDependencies, &rawDependencyList); err != nil {
			return "", "", nil, false
		}

		coordinate = strings.TrimSpace(coordinate)
		license = strings.TrimSpace(license)
		if coordinate == "" || license == "" {
			return "", "", nil, false
		}
		if _, dup := coordinates[coordinate]; dup {
			return "", "", nil, false
		}
		coordinates[coordinate] = struct{}{}

		dependencies := make([]string, 0, len(rawDependencyList))
		seenDependencies := make(map[string]struct{}, len(rawDependencyList))
		for _, rawDependency := range rawDependencyList {
			dependency, ok := decodeJSONString(rawDependency)
			if !ok {
				return "", "", nil, false
			}
			dependency = strings.TrimSpace(dependency)
			if dependency == "" {
				return "", "", nil, false
			}
			if dependency == coordinate {
				return "", "", nil, false
			}
			if _, dup := seenDependencies[dependency]; dup {
				return "", "", nil, false
			}
			seenDependencies[dependency] = struct{}{}
			dependencies = append(dependencies, dependency)
		}

		components = append(components, store.Component{
			Coordinate:   coordinate,
			License:      license,
			Dependencies: dependencies,
		})
	}

	for i := range components {
		for _, dependency := range components[i].Dependencies {
			if _, exists := coordinates[dependency]; !exists {
				return "", "", nil, false
			}
		}
	}

	sort.Slice(components, func(i, j int) bool {
		return components[i].Coordinate < components[j].Coordinate
	})
	for i := range components {
		sort.Strings(components[i].Dependencies)
	}
	return artifact, version, components, true
}

// decodeJSONString accepts a raw JSON value only when it is a JSON string,
// rejecting null, numbers, booleans, arrays and objects.
func decodeJSONString(raw json.RawMessage) (string, bool) {
	if len(raw) == 0 || raw[0] != '"' {
		return "", false
	}
	var value string
	if err := json.Unmarshal(raw, &value); err != nil {
		return "", false
	}
	return value, true
}
