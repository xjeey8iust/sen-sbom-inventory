package api

import (
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/xjeey8iust/sen-sbom-inventory/internal/manifest"
	"github.com/xjeey8iust/sen-sbom-inventory/internal/model"
)

// errMalformed is returned by the request decoders for every shape the API
// contract rejects. The single error keeps SQL, paths and internals out of the
// client-visible message.
var errMalformed = errors.New("malformed SBOM request")

func (h *sbomHandlers) register(c *gin.Context) {
	body, err := io.ReadAll(c.Request.Body)
	if err != nil {
		writeAPIError(c, http.StatusBadRequest, invalidInputCode, invalidInputMessage)
		return
	}

	// Parsing, validation and normalization are HTTP/storage-independent: the
	// same entry plain Go callers use, so the on-wire rules and the library
	// rules can never drift apart. A successful parse yields an unregistered
	// manifest with the zero ID; the store assigns the ID.
	sbom, err := manifest.ParseRegistration(body)
	if err != nil {
		writeAPIError(c, http.StatusBadRequest, invalidInputCode, invalidInputMessage)
		return
	}

	sbom, _, err = h.store.Register(c.Request.Context(), sbom)
	if err != nil {
		writeStoreError(c, err)
		return
	}
	c.JSON(http.StatusCreated, sbom)
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
	conflictMessage     = "an SBOM with different content already exists for this artifact and version"
	notFoundMessage     = "no SBOM is registered for this artifact and version"
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
