package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/xjeey8iust/sen-sbom-inventory/internal/model"
)

// errMalformed is returned by the request decoders for every shape the API
// contract rejects. The single error keeps SQL, paths and internals out of the
// client-visible message.
var errMalformed = errors.New("malformed SBOM request")

// componentInput is one request component after shape validation; strings are
// already trimmed and dependencies are de-duplicated.
type componentInput struct {
	coordinate string
	license    string
	deps       []string
}

// componentsInput is the typed, validated view of the request's components
// array. Its UnmarshalJSON enforces the array/object/string types strictly so
// that a null, a scalar or a wrongly typed element cannot sneak in through Go's
// lenient zero values, and detects duplicate coordinates while every JSON
// element is still visible (plain struct decoding would silently keep the last
// of two duplicates).
type componentsInput []componentInput

type rawComponent struct {
	Coordinate   *string   `json:"coordinate"`
	License      *string   `json:"license"`
	Dependencies *[]string `json:"dependencies"`
}

func (c *componentsInput) UnmarshalJSON(data []byte) error {
	// A JSON null is not the array the contract requires; distinguish it from
	// an actually empty array.
	if bytes.Equal(bytes.TrimSpace(data), []byte("null")) {
		return errMalformed
	}
	var raw []*rawComponent
	if err := json.Unmarshal(data, &raw); err != nil {
		// Type errors (components not an array, element not an object, a
		// dependency entry not a string, ...) all collapse to the same
		// client-fixable rejection.
		return errMalformed
	}

	coordinates := make(map[string]struct{}, len(raw))
	parsed := make(componentsInput, 0, len(raw))
	for _, item := range raw {
		if item == nil || item.Coordinate == nil || item.License == nil || item.Dependencies == nil {
			return errMalformed
		}
		coordinate := strings.TrimSpace(*item.Coordinate)
		license := strings.TrimSpace(*item.License)
		if coordinate == "" || license == "" {
			return errMalformed
		}
		if _, exists := coordinates[coordinate]; exists {
			return errMalformed
		}
		coordinates[coordinate] = struct{}{}

		deps := make([]string, 0, len(*item.Dependencies))
		seen := make(map[string]struct{}, len(*item.Dependencies))
		for _, dep := range *item.Dependencies {
			dep = strings.TrimSpace(dep)
			if dep == "" {
				return errMalformed
			}
			if dep == coordinate {
				return errMalformed
			}
			if _, exists := seen[dep]; exists {
				return errMalformed
			}
			seen[dep] = struct{}{}
			deps = append(deps, dep)
		}
		parsed = append(parsed, componentInput{
			coordinate: coordinate,
			license:    license,
			deps:       deps,
		})
	}
	*c = parsed
	return nil
}

type registerRequest struct {
	Artifact   string          `json:"artifact"`
	Version    string          `json:"version"`
	Components componentsInput `json:"components"`
}

func (h *sbomHandlers) register(c *gin.Context) {
	body, err := io.ReadAll(c.Request.Body)
	if err != nil {
		writeAPIError(c, http.StatusBadRequest, invalidInputCode, invalidInputMessage)
		return
	}

	var req registerRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeAPIError(c, http.StatusBadRequest, invalidInputCode, invalidInputMessage)
		return
	}
	// The body must resolve to exactly one JSON value: "{} {}" and
	// "{} garbage" are rejected instead of silently keeping the first object.
	if hasTrailingValue(body) {
		writeAPIError(c, http.StatusBadRequest, invalidInputCode, invalidInputMessage)
		return
	}

	req.Artifact = strings.TrimSpace(req.Artifact)
	req.Version = strings.TrimSpace(req.Version)
	if req.Artifact == "" || req.Version == "" || req.Components == nil {
		writeAPIError(c, http.StatusBadRequest, invalidInputCode, invalidInputMessage)
		return
	}

	coordinates := make(map[string]struct{}, len(req.Components))
	for _, comp := range req.Components {
		coordinates[comp.coordinate] = struct{}{}
	}
	components := make([]model.Component, len(req.Components))
	for i, comp := range req.Components {
		for _, dep := range comp.deps {
			if _, ok := coordinates[dep]; !ok {
				writeAPIError(c, http.StatusBadRequest, invalidInputCode, invalidInputMessage)
				return
			}
		}
		sort.Strings(comp.deps)
		components[i] = model.Component{
			Coordinate:   comp.coordinate,
			License:      comp.license,
			Dependencies: comp.deps,
		}
	}
	sort.Slice(components, func(i, j int) bool { return components[i].Coordinate < components[j].Coordinate })

	sbom, _, err := h.store.Register(c.Request.Context(), &model.SBOM{
		Artifact:   req.Artifact,
		Version:    req.Version,
		Components: components,
	})
	if err != nil {
		writeStoreError(c, err)
		return
	}
	c.JSON(http.StatusCreated, sbom)
}

// hasTrailingValue reports whether anything but whitespace follows the first
// top-level JSON value in body. json.Unmarshal ignores such trailing bytes, so
// they have to be detected explicitly.
func hasTrailingValue(body []byte) bool {
	dec := json.NewDecoder(bytes.NewReader(body))
	var first json.RawMessage
	if err := dec.Decode(&first); err != nil {
		return false // The first decode already failed; the caller rejects it.
	}
	var next json.RawMessage
	return dec.Decode(&next) == nil
}

type listResponse struct {
	Items    []*model.SBOM `json:"items"`
	Total    int           `json:"total"`
	Page     int           `json:"page"`
	PageSize int           `json:"pageSize"`
}

func (h *sbomHandlers) list(c *gin.Context) {
	artifact := strings.TrimSpace(c.Query("artifact"))
	if artifact == "" {
		writeAPIError(c, http.StatusBadRequest, invalidInputCode, invalidInputMessage)
		return
	}
	page, err := positiveQuery(c, "page", 1)
	if err != nil {
		writeAPIError(c, http.StatusBadRequest, invalidInputCode, invalidInputMessage)
		return
	}
	pageSize, err := positiveQuery(c, "pageSize", 20)
	if err != nil || pageSize > 100 {
		writeAPIError(c, http.StatusBadRequest, invalidInputCode, invalidInputMessage)
		return
	}

	items, total, err := h.store.List(c.Request.Context(), artifact, page, pageSize)
	if err != nil {
		writeStoreError(c, err)
		return
	}
	c.JSON(http.StatusOK, listResponse{Items: items, Total: total, Page: page, PageSize: pageSize})
}

// diff compares two registered versions of one artifact. The store returns
// the complete wire shape; only normalized identifiers and the three
// difference arrays ever leave the service.
func (h *sbomHandlers) diff(c *gin.Context) {
	artifact := strings.TrimSpace(c.Query("artifact"))
	fromVersion := strings.TrimSpace(c.Query("fromVersion"))
	toVersion := strings.TrimSpace(c.Query("toVersion"))
	if artifact == "" || fromVersion == "" || toVersion == "" {
		writeAPIError(c, http.StatusBadRequest, invalidInputCode, invalidDiffMessage)
		return
	}

	result, err := h.store.Diff(c.Request.Context(), artifact, fromVersion, toVersion)
	if err != nil {
		writeStoreError(c, err)
		return
	}
	c.JSON(http.StatusOK, result)
}

// positiveQuery parses an optional query parameter that, when present, must be
// a decimal positive integer (digits only, no sign, no spaces).
func positiveQuery(c *gin.Context, name string, fallback int) (int, error) {
	raw, present := c.GetQuery(name)
	if !present {
		return fallback, nil
	}
	if raw == "" || len(raw) > 10 {
		return 0, errMalformed
	}
	for i := 0; i < len(raw); i++ {
		if raw[i] < '0' || raw[i] > '9' {
			return 0, errMalformed
		}
	}
	value, err := strconv.Atoi(raw)
	if err != nil || value <= 0 {
		return 0, errMalformed
	}
	return value, nil
}

const (
	invalidInputCode    = "InvalidSbomInputError"
	conflictCode        = "SbomConflictError"
	notFoundCode        = "SbomNotFoundError"
	storageCode         = "storage_unavailable"
	invalidInputMessage = "request is not a valid SBOM manifest"
	invalidDiffMessage  = "request is not a valid SBOM diff query"
	notFoundMessage     = "no registered SBOM exists for this artifact and version"
	conflictMessage     = "an SBOM with different content already exists for this artifact and version"
	storageMessage      = "database is not available"
)

func writeAPIError(c *gin.Context, status int, code, message string) {
	c.JSON(status, gin.H{"error": gin.H{"code": code, "message": message}})
}

// writeStoreError maps the store's sentinel errors to the contracted status
// codes. Every other storage failure is reported generically as 503.
func writeStoreError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, model.ErrConflict):
		writeAPIError(c, http.StatusConflict, conflictCode, conflictMessage)
	case errors.Is(err, model.ErrNotFound):
		writeAPIError(c, http.StatusNotFound, notFoundCode, notFoundMessage)
	case errors.Is(err, model.ErrStorageUnavailable):
		writeAPIError(c, http.StatusServiceUnavailable, storageCode, storageMessage)
	default:
		writeAPIError(c, http.StatusServiceUnavailable, storageCode, storageMessage)
	}
}
