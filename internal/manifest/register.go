// Package manifest turns raw SBOM registration payloads into validated,
// normalized model.SBOM values. It owns neither HTTP nor storage: parsing
// depends only on the bytes handed in, never reads or writes the inventory
// store, so the POST /sboms handler and plain Go callers share one rule set.
package manifest

import (
	"bytes"
	"encoding/json"
	"sort"
	"strings"

	"github.com/xjeey8iust/sen-sbom-inventory/internal/model"
)

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
		return model.ErrInvalidInput
	}
	var raw []*rawComponent
	if err := json.Unmarshal(data, &raw); err != nil {
		// Type errors (components not an array, element not an object, a
		// dependency entry not a string, ...) all collapse to the same
		// caller-fixable rejection.
		return model.ErrInvalidInput
	}

	coordinates := make(map[string]struct{}, len(raw))
	parsed := make(componentsInput, 0, len(raw))
	for _, item := range raw {
		if item == nil || item.Coordinate == nil || item.License == nil || item.Dependencies == nil {
			return model.ErrInvalidInput
		}
		coordinate := strings.TrimSpace(*item.Coordinate)
		license := strings.TrimSpace(*item.License)
		if coordinate == "" || license == "" {
			return model.ErrInvalidInput
		}
		if _, exists := coordinates[coordinate]; exists {
			return model.ErrInvalidInput
		}
		coordinates[coordinate] = struct{}{}

		deps := make([]string, 0, len(*item.Dependencies))
		seen := make(map[string]struct{}, len(*item.Dependencies))
		for _, dep := range *item.Dependencies {
			dep = strings.TrimSpace(dep)
			if dep == "" {
				return model.ErrInvalidInput
			}
			if dep == coordinate {
				return model.ErrInvalidInput
			}
			if _, exists := seen[dep]; exists {
				return model.ErrInvalidInput
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

// registerInput is the strict top-level shape. Artifact and Version are
// pointers so that a missing or null field is distinguishable from an
// (also rejected) blank-after-trimming string; Components carries the custom
// strict decoder and stays nil when the field is absent.
type registerInput struct {
	Artifact   *string         `json:"artifact"`
	Version    *string         `json:"version"`
	Components componentsInput `json:"components"`
}

// ParseRegistration parses, validates and normalizes one registration payload
// — the exact input POST /sboms accepts:
//
//   - the body must be exactly one JSON object (arrays, scalars, null, a
//     second value or trailing garbage are rejected; unknown fields are
//     ignored);
//   - artifact, version and components are required, with string / string-array
//     types; every business string has its leading and trailing whitespace
//     removed, but casing and inner formatting are preserved;
//   - components and dependency arrays may be empty; an empty array stays an
//     empty array, never null;
//   - coordinates must be unique after trimming; a component's dependency
//     targets must be non-empty, unique, not the component itself and must name
//     a coordinate present in the same manifest. Dependencies may point at
//     components listed later, and non-self cycles are allowed;
//   - licenses and coordinate formats are not otherwise inspected.
//
// On success the returned *model.SBOM is normalized (components and each
// component's dependencies sorted ascending by coordinate string) and carries
// the zero ID: it has not been registered anywhere. Duplicates are rejected
// rather than merged.
//
// Every rejection returns an error that errors.Is recognizes as
// model.ErrInvalidInput, together with a nil manifest. raw is never modified,
// no storage is accessed, and repeated calls never share state or results.
func ParseRegistration(raw []byte) (*model.SBOM, error) {
	var req registerInput
	if err := json.Unmarshal(raw, &req); err != nil {
		return nil, model.ErrInvalidInput
	}
	// The body must resolve to exactly one JSON value: "{} {}" and
	// "{} garbage" are rejected instead of silently keeping the first object.
	if hasTrailingValue(raw) {
		return nil, model.ErrInvalidInput
	}
	if req.Artifact == nil || req.Version == nil || req.Components == nil {
		return nil, model.ErrInvalidInput
	}

	artifact := strings.TrimSpace(*req.Artifact)
	version := strings.TrimSpace(*req.Version)
	if artifact == "" || version == "" {
		return nil, model.ErrInvalidInput
	}

	coordinates := make(map[string]struct{}, len(req.Components))
	for _, comp := range req.Components {
		coordinates[comp.coordinate] = struct{}{}
	}

	components := make([]model.Component, len(req.Components))
	for i, comp := range req.Components {
		for _, dep := range comp.deps {
			if _, ok := coordinates[dep]; !ok {
				return nil, model.ErrInvalidInput
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

	return &model.SBOM{
		Artifact:   artifact,
		Version:    version,
		Components: components,
	}, nil
}

// hasTrailingValue reports whether anything but whitespace follows the first
// top-level JSON value in body. A single json.Unmarshal already rejects such
// trailing bytes today; the explicit decoder check keeps the one-value
// contract independent of that detail.
func hasTrailingValue(body []byte) bool {
	dec := json.NewDecoder(bytes.NewReader(body))
	var first json.RawMessage
	if err := dec.Decode(&first); err != nil {
		return false // The first decode already failed; the caller rejects it.
	}
	var next json.RawMessage
	return dec.Decode(&next) == nil
}
