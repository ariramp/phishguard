package api

import (
	"net/http"
	"time"

	"phishguard/backend/internal/mail"
	"phishguard/backend/internal/service"
	"phishguard/backend/internal/store"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

type Handlers struct {
	db         *store.DB
	worker     *service.Worker
	mailClient *mail.Client
	logger     *zap.Logger
}

func (h *Handlers) Healthz(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"ok": true,
		"ts": time.Now().UTC(),
	})
}

func (h *Handlers) ListAccounts(c *gin.Context) {
	items, err := h.db.ListAccounts(c.Request.Context())
	if err != nil {
		h.logger.Error("list accounts failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"items": items})
}

func (h *Handlers) CreateAccount(c *gin.Context) {
	var req store.CreateAccountParams
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if req.IMAPPort == 0 {
		req.IMAPPort = 993
	}
	if req.SourceMailbox == "" {
		req.SourceMailbox = "INBOX"
	}
	if req.PollIntervalSeconds == 0 {
		req.PollIntervalSeconds = 900
	}
	if req.ActionOnHigh == "" {
		req.ActionOnHigh = "MOVE"
	}
	if req.TargetMailbox == "" {
		req.TargetMailbox = "Phishing"
	}

	acc, err := h.db.CreateAccount(c.Request.Context(), req)
	if err != nil {
		h.logger.Error("create account failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	maxUID, err := h.mailClient.GetCurrentMaxUID(c.Request.Context(), *acc)
	if err != nil {
		h.logger.Error("init max uid failed", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "account created, but IMAP init failed: " + err.Error(),
		})
		return
	}

	if err := h.db.UpdateAccountLastUID(c.Request.Context(), acc.ID, int64(maxUID)); err != nil {
		h.logger.Error("update initial last uid failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	acc.LastUID = int64(maxUID)

	c.JSON(http.StatusCreated, gin.H{
		"account": acc,
		"message": "account created; existing emails skipped; only new emails will be processed",
	})
}

func (h *Handlers) GetHistory(c *gin.Context) {
	items, err := h.db.GetHistory(c.Request.Context(), 100)
	if err != nil {
		h.logger.Error("get history failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"items": items,
	})
}

func (h *Handlers) GetStats(c *gin.Context) {
	stats, err := h.db.GetStats(c.Request.Context())
	if err != nil {
		h.logger.Error("get stats failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, stats)
}

func (h *Handlers) PollOnce(c *gin.Context) {
	if err := h.worker.PollOnce(c.Request.Context()); err != nil {
		h.logger.Error("poll once failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}
func (h *Handlers) GetTimeSeriesStats(c *gin.Context) {
	period := c.DefaultQuery("period", "week")

	items, err := h.db.GetTimeSeriesStats(c.Request.Context(), period)
	if err != nil {
		h.logger.Error("get timeseries stats failed", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"period": period,
		"items":  items,
	})
}
