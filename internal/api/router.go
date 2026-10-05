package api

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/xjeey8iust/sen-sbom-inventory/internal/store"
)

// sbomHandlers bundles the HTTP handlers with their storage dependency.
type sbomHandlers struct {
	store *store.Store
}

// NewRouter wires the public HTTP surface. Every entry keeps the error shape
// the service contract in README.md describes.
func NewRouter(st *store.Store) *gin.Engine {
	gin.SetMode(gin.ReleaseMode)
	router := gin.New()
	router.Use(gin.Recovery())

	h := &sbomHandlers{store: st}

	router.GET("/healthz", func(c *gin.Context) {
		if err := st.Ping(); err != nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": gin.H{"code": "storage_unavailable", "message": "database is not available"}})
			return
		}
		c.JSON(http.StatusOK, gin.H{"status": "ok", "database": "ok"})
	})

	router.POST("/sboms", h.register)
	router.GET("/sboms", h.list)
	router.GET("/sboms/diff", h.diff)

	router.NoRoute(func(c *gin.Context) {
		c.JSON(http.StatusNotFound, gin.H{"error": gin.H{"code": "route_not_found", "message": "no route matches this path"}})
	})
	return router
}
