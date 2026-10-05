// Package model defines the SBOM inventory domain types and the errors shared
// between the HTTP layer and the storage layer.
package model

import "errors"

// Component is one entry of a bill of materials. Coordinate is unique within
// a single SBOM; Dependencies refer to coordinates of other components in the
// same SBOM.
type Component struct {
	Coordinate   string   `json:"coordinate"`
	License      string   `json:"license"`
	Dependencies []string `json:"dependencies"`
}

// SBOM is the persisted manifest. ID is assigned by the store; Artifact and
// Version together identify a manifest for idempotent registration.
type SBOM struct {
	ID         int64       `json:"id"`
	Artifact   string      `json:"artifact"`
	Version    string      `json:"version"`
	Components []Component `json:"components"`
}

// Sentinel errors. The HTTP layer maps each sentinel to a status code and uses
// the error type name as the business error code.
var (
	// ErrInvalidInput signals a request the caller can fix: malformed body,
	// missing fields, duplicates, dangling dependency targets, bad paging, ...
	ErrInvalidInput = errors.New("InvalidSbomInputError")
	// ErrConflict signals that an SBOM with the same artifact and version
	// already exists with different content.
	ErrConflict = errors.New("SbomConflictError")
	// ErrNotFound signals that a request named an artifact/version combination
	// no registered manifest exists for.
	ErrNotFound = errors.New("SbomNotFoundError")
	// ErrStorageUnavailable signals that the persistence layer cannot serve
	// the request.
	ErrStorageUnavailable = errors.New("storage_unavailable")
)

// ChangedComponent is one coordinate whose component exists in both compared
// manifests but differs in license or in the set of direct dependency
// coordinates; Before comes from the older manifest, After from the newer one.
type ChangedComponent struct {
	Coordinate string    `json:"coordinate"`
	Before     Component `json:"before"`
	After      Component `json:"after"`
}

// DiffResult is the comparison of two registered manifests of one artifact.
// The three difference slices are always present on the wire (empty, never
// null) and ordered by coordinate ascending.
type DiffResult struct {
	Artifact    string             `json:"artifact"`
	FromVersion string             `json:"fromVersion"`
	ToVersion   string             `json:"toVersion"`
	Added       []Component        `json:"added"`
	Removed     []Component        `json:"removed"`
	Changed     []ChangedComponent `json:"changed"`
}
