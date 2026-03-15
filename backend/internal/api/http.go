package api

import (
	"net/http"

	"phishguard/backend/internal/service"
	"phishguard/backend/internal/store"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

func NewRouter(db *store.DB, worker *service.Worker, logger *zap.Logger) http.Handler {
	r := gin.New()
	r.Use(gin.Recovery())

	h := &Handlers{
		db:     db,
		worker: worker,
		logger: logger,
	}

	r.GET("/healthz", h.Healthz)

	r.GET("/api/v1/accounts", h.ListAccounts)
	r.POST("/api/v1/accounts", h.CreateAccount)

	r.GET("/api/v1/history", h.GetHistory)
	r.GET("/api/v1/stats", h.GetStats)

	r.POST("/api/v1/poll/once", h.PollOnce)

	return r
}
