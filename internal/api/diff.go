package api

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/xjeey8iust/sen-sbom-inventory/internal/manifest"
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
	// The comparison itself is HTTP/storage-independent: the same entry plain
	// Go callers use, so the on-wire rules and the library rules can never
	// drift apart. The store guarantees both manifests belong to the requested
	// artifact, so Compare cannot reject what Diff already loaded.
	result, err := manifest.Compare(before, after)
	if err != nil {
		writeStoreError(c, err)
		return
	}
	c.JSON(http.StatusOK, result)
}

// The diff response shape is defined next to the comparison entry in the
// manifest package; these aliases keep the in-package test references
// unchanged.
type (
	diffResponse    = manifest.Diff
	componentChange = manifest.ComponentChange
)
