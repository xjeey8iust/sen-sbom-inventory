package api

import (
	"errors"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/xjeey8iust/sen-sbom-inventory/internal/manifest"
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

	// Partitioning is HTTP/storage-independent: plain Go callers compare
	// manifests through the same manifest.Compare entry, so the endpoint
	// and the library can never drift apart. The store only returns
	// non-nil manifests of the requested artifact; any other failure is
	// a defensive 400/503 with no partial diff.
	result, err := manifest.Compare(before, after)
	if err != nil {
		if errors.Is(err, model.ErrInvalidInput) {
			writeAPIError(c, http.StatusBadRequest, invalidInputCode, invalidInputMessage)
			return
		}
		writeStoreError(c, err)
		return
	}
	c.JSON(http.StatusOK, result)
}
