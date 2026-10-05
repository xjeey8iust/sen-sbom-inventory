// Package model defines the SBOM inventory domain types and the errors shared
// between the HTTP layer and the storage layer. ParseSBOM (parse.go) is the
// transport-independent entry point that parses, validates and normalizes a
// raw registration payload into an SBOM ready for Store.Register.
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
	// ErrNotFound signals that the requested artifact/version is not
	// registered. Diff returns it for either missing version.
	ErrNotFound = errors.New("SbomNotFoundError")
	// ErrStorageUnavailable signals that the persistence layer cannot serve
	// the request.
	ErrStorageUnavailable = errors.New("storage_unavailable")
)
