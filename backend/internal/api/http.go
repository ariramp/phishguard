package api

import (
	"net/http"
	"os"
	"path/filepath"

	"phishguard/backend/internal/mail"
	"phishguard/backend/internal/mlclient"
	"phishguard/backend/internal/service"
	"phishguard/backend/internal/store"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

func NewRouter(db *store.DB, worker *service.Worker, ml mlclient.Client, logger *zap.Logger) http.Handler {
	r := gin.New()
	r.Use(gin.Recovery())

	h := &Handlers{
		db:         db,
		worker:     worker,
		ml:         ml,
		mailClient: mail.NewClient(),
		logger:     logger,
	}

	r.GET("/healthz", h.Healthz)
	r.GET("/api/v1/system/status", h.SystemStatus)

	r.GET("/api/v1/accounts", h.ListAccounts)
	r.GET("/api/v1/accounts/errors", h.ListAccountErrors)
	r.POST("/api/v1/accounts", h.CreateAccount)
	r.PATCH("/api/v1/accounts/:accountID", h.UpdateAccount)
	r.DELETE("/api/v1/accounts/:accountID", h.DeleteAccount)

	r.GET("/api/v1/history", h.GetHistory)
	r.GET("/api/v1/history/:emailID", h.GetHistoryDetails)
	r.GET("/api/v1/reports/detections.csv", h.ExportDetectionsCSV)
	r.GET("/api/v1/reports/summary", h.GetSummaryReport)
	r.GET("/api/v1/reports/summary.csv", h.ExportSummaryCSV)
	r.GET("/api/v1/stats", h.GetStats)
	r.GET("/api/v1/stats/timeseries", h.GetTimeSeriesStats)

	r.POST("/api/v1/poll/once", h.PollOnce)
	r.POST("/api/v1/rescore", h.RescoreExisting)
	r.POST("/api/v1/check/url", h.ManualCheck)

	webDir := resolveWebDir()
	r.Static("/assets", filepath.Join(webDir, "assets"))
	r.GET("/", func(c *gin.Context) {
		c.File(filepath.Join(webDir, "index.html"))
	})

	return r
}

func resolveWebDir() string {
	if cwd, err := os.Getwd(); err == nil {
		candidate := filepath.Join(cwd, "web")
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}
	return "/app/web"
}
