package model

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// ParseSBOM is the transport-independent entry point for the registration
// input rules. It parses, validates and normalizes one raw SBOM registration
// payload — the same JSON object POST /sboms accepts — without involving HTTP
// or the database, so any Go code can apply the registration rules directly:
//
//	sbom, err := model.ParseSBOM(body)
//	switch {
//	case err == nil:
//		// sbom is normalized and satisfies every Store.Register precondition.
//	case errors.Is(err, model.ErrInvalidInput):
//		// The caller can fix the payload; sbom is nil.
//	}
//
// Input: the raw JSON bytes of one registration object with the required
// string fields "artifact" and "version" and the required array "components"
// of {"coordinate", "license", "dependencies"} objects. Unknown fields are
// ignored. The bytes are only read, never modified, and the function performs
// no storage access; results of separate calls share nothing, so callers may
// keep or mutate a returned manifest without affecting later calls.
//
// On success the returned manifest is normalized and its ID is zero (the
// store assigns IDs at registration):
//   - every business string (artifact, version, coordinates, licenses,
//     dependency targets) is trimmed of leading/trailing whitespace; case and
//     inner formatting are preserved — no license or coordinate format is
//     validated beyond non-emptiness;
//   - components are sorted ascending by coordinate and each component's
//     dependencies are sorted ascending; duplicates are rejected, never
//     merged;
//   - empty components/dependencies arrays stay empty arrays (never nil).
//
// On failure the return is nil plus an error for which
// errors.Is(err, ErrInvalidInput) is true. Rejected shapes include: invalid
// JSON, a top-level value that is not an object, a second value or garbage
// after the object, required fields missing/null/wrongly typed, required
// strings blank after trimming, duplicate coordinates after normalization, a
// duplicated dependency within one component, a self-dependency, and a
// dependency target that is not a component of the same manifest. A
// dependency may reference a component listed later in the input, and
// dependency cycles that do not pass through a self-edge are valid.
func ParseSBOM(data []byte) (*SBOM, error) {
	var in manifestInput
	if err := json.Unmarshal(data, &in); err != nil {
		return nil, invalidInput("body is not a single JSON object")
	}
	// The body must resolve to exactly one JSON value: "{} {}" and
	// "{} garbage" are rejected instead of silently keeping the first object.
	if hasTrailingValue(data) {
		return nil, invalidInput("unexpected content after the JSON object")
	}

	artifact := strings.TrimSpace(in.Artifact)
	version := strings.TrimSpace(in.Version)
	if artifact == "" || version == "" || in.Components == nil {
		return nil, invalidInput("artifact, version and components are required")
	}

	coordinates := make(map[string]struct{}, len(in.Components))
	for _, comp := range in.Components {
		coordinates[comp.coordinate] = struct{}{}
	}
	components := make([]Component, len(in.Components))
	for i, comp := range in.Components {
		for _, dep := range comp.deps {
			if _, ok := coordinates[dep]; !ok {
				return nil, invalidInput("dependency target is not a component of this manifest")
			}
		}
		sort.Strings(comp.deps)
		components[i] = Component{
			Coordinate:   comp.coordinate,
			License:      comp.license,
			Dependencies: comp.deps,
		}
	}
	sort.Slice(components, func(i, j int) bool { return components[i].Coordinate < components[j].Coordinate })

	return &SBOM{Artifact: artifact, Version: version, Components: components}, nil
}

// invalidInput marks a rejected payload so callers can recognize it with
// errors.Is(err, ErrInvalidInput); the reason stays in the Go error chain and
// never reaches the HTTP response.
func invalidInput(reason string) error {
	return fmt.Errorf("%w: %s", ErrInvalidInput, reason)
}

// manifestInput is the typed view of the registration payload's top level.
// Artifact and Version stay plain strings: a missing or null value decodes to
// the empty string and is rejected by the blank-after-trimming check, exactly
// like an explicitly empty value.
type manifestInput struct {
	Artifact   string          `json:"artifact"`
	Version    string          `json:"version"`
	Components componentsInput `json:"components"`
}

// componentInput is one payload component after shape validation; strings are
// already trimmed and dependencies are de-duplicated.
type componentInput struct {
	coordinate string
	license    string
	deps       []string
}

// componentsInput is the typed, validated view of the payload's components
// array. Its UnmarshalJSON enforces the array/object/string types strictly so
// that a null, a scalar or a wrongly typed element cannot sneak in through
// Go's lenient zero values, and detects duplicate coordinates while every
// JSON element is still visible (plain struct decoding would silently keep
// the last of two duplicates).
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
		return invalidInput("components must be an array")
	}
	var raw []*rawComponent
	if err := json.Unmarshal(data, &raw); err != nil {
		// Type errors (components not an array, element not an object, a
		// dependency entry not a string, ...) all collapse to the same
		// caller-fixable rejection.
		return invalidInput("components must be an array of objects")
	}

	coordinates := make(map[string]struct{}, len(raw))
	parsed := make(componentsInput, 0, len(raw))
	for _, item := range raw {
		if item == nil || item.Coordinate == nil || item.License == nil || item.Dependencies == nil {
			return invalidInput("component requires coordinate, license and dependencies")
		}
		coordinate := strings.TrimSpace(*item.Coordinate)
		license := strings.TrimSpace(*item.License)
		if coordinate == "" || license == "" {
			return invalidInput("component coordinate and license must be non-empty")
		}
		if _, exists := coordinates[coordinate]; exists {
			return invalidInput("duplicate component coordinate")
		}
		coordinates[coordinate] = struct{}{}

		deps := make([]string, 0, len(*item.Dependencies))
		seen := make(map[string]struct{}, len(*item.Dependencies))
		for _, dep := range *item.Dependencies {
			dep = strings.TrimSpace(dep)
			if dep == "" {
				return invalidInput("dependency target must be non-empty")
			}
			if dep == coordinate {
				return invalidInput("component must not depend on itself")
			}
			if _, exists := seen[dep]; exists {
				return invalidInput("duplicate dependency within one component")
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

// hasTrailingValue reports whether anything but whitespace follows the first
// top-level JSON value in body. json.Unmarshal ignores such trailing bytes,
// so they have to be detected explicitly.
func hasTrailingValue(body []byte) bool {
	dec := json.NewDecoder(bytes.NewReader(body))
	var first json.RawMessage
	if err := dec.Decode(&first); err != nil {
		return false // The first decode already failed; the caller rejects it.
	}
	var next json.RawMessage
	return dec.Decode(&next) == nil
}
