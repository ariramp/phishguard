package api

import (
	"encoding/csv"
	"net/http"
	"strconv"
	"time"

	"phishguard/backend/internal/mail"
	"phishguard/backend/internal/mlclient"
	"phishguard/backend/internal/service"
	"phishguard/backend/internal/store"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"go.uber.org/zap"
)

type Handlers struct {
	db         *store.DB
	worker     *service.Worker
	ml         mlclient.Client
	mailClient *mail.Client
	logger     *zap.Logger
}

func (h *Handlers) Healthz(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"ok": true,
		"ts": time.Now().UTC(),
	})
}

func (h *Handlers) SystemStatus(c *gin.Context) {
	ctx := c.Request.Context()

	dbStatus := gin.H{"ok": true}
	if err := h.db.Ping(ctx); err != nil {
		dbStatus["ok"] = false
		dbStatus["error"] = err.Error()
	}

	mlStatus := gin.H{"ok": true}
	if payload, err := h.ml.Status(ctx); err != nil {
		mlStatus["ok"] = false
		mlStatus["error"] = err.Error()
	} else {
		mlStatus["details"] = payload
	}

	ok := dbStatus["ok"] == true && mlStatus["ok"] == true
	code := http.StatusOK
	if !ok {
		code = http.StatusServiceUnavailable
	}

	c.JSON(code, gin.H{
		"ok":      ok,
		"ts":      time.Now().UTC(),
		"backend": gin.H{"ok": true},
		"db":      dbStatus,
		"ml":      mlStatus,
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

func (h *Handlers) ListAccountErrors(c *gin.Context) {
	limit := 50
	if raw := c.Query("limit"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid limit"})
			return
		}
		limit = parsed
	}

	items, err := h.db.ListAccountErrors(c.Request.Context(), limit)
	if err != nil {
		h.logger.Error("list account errors failed", zap.Error(err))
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

type updateAccountReq struct {
	EmailAddress        *string `json:"email_address"`
	Enabled             *bool   `json:"enabled"`
	IMAPHost            *string `json:"imap_host"`
	IMAPPort            *int    `json:"imap_port"`
	IMAPTLS             *bool   `json:"imap_tls"`
	Username            *string `json:"username"`
	Password            *string `json:"password"`
	SourceMailbox       *string `json:"source_mailbox"`
	PollIntervalSeconds *int    `json:"poll_interval_seconds"`
	ActionOnHigh        *string `json:"action_on_high"`
	TargetMailbox       *string `json:"target_mailbox"`
	ResetLastUID        bool    `json:"reset_last_uid"`
}

func (h *Handlers) UpdateAccount(c *gin.Context) {
	accountID, err := uuid.Parse(c.Param("accountID"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid account id"})
		return
	}

	var req updateAccountReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if req.IMAPPort != nil && *req.IMAPPort == 0 {
		defaultPort := 993
		req.IMAPPort = &defaultPort
	}
	if req.PollIntervalSeconds != nil && *req.PollIntervalSeconds == 0 {
		defaultInterval := 900
		req.PollIntervalSeconds = &defaultInterval
	}
	if req.ActionOnHigh != nil && *req.ActionOnHigh == "" {
		defaultAction := "MOVE"
		req.ActionOnHigh = &defaultAction
	}
	if req.TargetMailbox != nil && *req.TargetMailbox == "" {
		defaultTarget := "Phishing"
		req.TargetMailbox = &defaultTarget
	}
	if req.SourceMailbox != nil && *req.SourceMailbox == "" {
		defaultMailbox := "INBOX"
		req.SourceMailbox = &defaultMailbox
	}

	acc, err := h.db.UpdateAccount(c.Request.Context(), accountID, store.UpdateAccountParams{
		EmailAddress:        req.EmailAddress,
		Enabled:             req.Enabled,
		IMAPHost:            req.IMAPHost,
		IMAPPort:            req.IMAPPort,
		IMAPTLS:             req.IMAPTLS,
		Username:            req.Username,
		Password:            req.Password,
		SourceMailbox:       req.SourceMailbox,
		PollIntervalSeconds: req.PollIntervalSeconds,
		ActionOnHigh:        req.ActionOnHigh,
		TargetMailbox:       req.TargetMailbox,
	})
	if err != nil {
		if err == pgx.ErrNoRows {
			c.JSON(http.StatusNotFound, gin.H{"error": "account not found"})
			return
		}
		h.logger.Error("update account failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	message := "account updated"
	if req.ResetLastUID {
		maxUID, err := h.mailClient.GetCurrentMaxUID(c.Request.Context(), *acc)
		if err != nil {
			h.logger.Error("reinit max uid failed", zap.Error(err))
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "account updated, but IMAP reinit failed: " + err.Error(),
			})
			return
		}
		if err := h.db.UpdateAccountLastUID(c.Request.Context(), acc.ID, int64(maxUID)); err != nil {
			h.logger.Error("update last uid after patch failed", zap.Error(err))
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		acc.LastUID = int64(maxUID)
		message = "account updated; last_uid reinitialized to current mailbox maximum"
	}

	c.JSON(http.StatusOK, gin.H{
		"account":  acc,
		"message":  message,
		"reset_uid": req.ResetLastUID,
	})
}

func (h *Handlers) DeleteAccount(c *gin.Context) {
	accountID, err := uuid.Parse(c.Param("accountID"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid account id"})
		return
	}

	summary, err := h.db.DeleteAccount(c.Request.Context(), accountID)
	if err != nil {
		if err == pgx.ErrNoRows {
			c.JSON(http.StatusNotFound, gin.H{"error": "account not found"})
			return
		}
		h.logger.Error("delete account failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"status":  "deleted",
		"summary": summary,
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

func (h *Handlers) GetHistoryDetails(c *gin.Context) {
	emailID, err := uuid.Parse(c.Param("emailID"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid email id"})
		return
	}

	items, err := h.db.GetHistoryDetails(c.Request.Context(), emailID)
	if err != nil {
		h.logger.Error("get history details failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"items": items})
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

type manualCheckReq struct {
	URL     string `json:"url" binding:"required"`
	Subject string `json:"subject"`
	Snippet string `json:"snippet"`
}

func (h *Handlers) ManualCheck(c *gin.Context) {
	var req manualCheckReq
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	score, risk, modelVersion, features, err := h.ml.PredictURL(
		c.Request.Context(),
		req.URL,
		req.Subject,
		req.Snippet,
	)
	if err != nil {
		h.logger.Error("manual ml predict failed", zap.Error(err))
		c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
		return
	}

	verdict := "safe"
	if risk >= 3 || score >= 0.8 {
		verdict = "phishing"
	} else if risk == 2 || score >= 0.5 {
		verdict = "suspicious"
	}

	c.JSON(http.StatusOK, gin.H{
		"url":           req.URL,
		"subject":       req.Subject,
		"snippet":       req.Snippet,
		"score":         score,
		"risk":          risk,
		"verdict":       verdict,
		"model_version": modelVersion,
		"features":      features,
	})
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

func (h *Handlers) ExportDetectionsCSV(c *gin.Context) {
	period := c.DefaultQuery("period", "week")
	limit := 1000
	if raw := c.Query("limit"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid limit"})
			return
		}
		limit = parsed
	}

	items, err := h.db.GetDetectionReport(c.Request.Context(), period, limit)
	if err != nil {
		h.logger.Error("export detections failed", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	filename := "phishguard_detections_" + period + ".csv"
	c.Header("Content-Type", "text/csv; charset=utf-8")
	c.Header("Content-Disposition", `attachment; filename="`+filename+`"`)

	writer := csv.NewWriter(c.Writer)
	defer writer.Flush()

	_ = writer.Write([]string{
		"checked_at",
		"email_address",
		"sender",
		"subject",
		"raw_url",
		"normalized_url",
		"domain",
		"score",
		"risk",
		"verdict",
		"model_version",
	})

	for _, item := range items {
		_ = writer.Write([]string{
			item.CheckedAt.Format(time.RFC3339),
			item.EmailAddress,
			item.Sender,
			item.Subject,
			item.RawURL,
			item.NormalizedURL,
			item.Domain,
			strconv.FormatFloat(float64(item.Score), 'f', 6, 32),
			strconv.FormatInt(int64(item.Risk), 10),
			item.Verdict,
			item.ModelVersion,
		})
	}
}

func (h *Handlers) GetSummaryReport(c *gin.Context) {
	period := c.DefaultQuery("period", "week")

	report, err := h.db.GetSummaryReport(c.Request.Context(), period)
	if err != nil {
		h.logger.Error("get summary report failed", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, report)
}

func (h *Handlers) ExportSummaryCSV(c *gin.Context) {
	period := c.DefaultQuery("period", "week")

	report, err := h.db.GetSummaryReport(c.Request.Context(), period)
	if err != nil {
		h.logger.Error("export summary report failed", zap.Error(err))
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	filename := "phishguard_summary_" + period + ".csv"
	c.Header("Content-Type", "text/csv; charset=utf-8")
	c.Header("Content-Disposition", `attachment; filename="`+filename+`"`)

	writer := csv.NewWriter(c.Writer)
	defer writer.Flush()

	_ = writer.Write([]string{"metric", "value"})
	_ = writer.Write([]string{"period", report.Period})
	_ = writer.Write([]string{"generated_at", report.GeneratedAt.Format(time.RFC3339)})
	_ = writer.Write([]string{"total_emails", strconv.Itoa(report.TotalEmails)})
	_ = writer.Write([]string{"total_urls", strconv.Itoa(report.TotalURLs)})
	_ = writer.Write([]string{"total_scans", strconv.Itoa(report.TotalScans)})
	_ = writer.Write([]string{"safe_count", strconv.Itoa(report.SafeCount)})
	_ = writer.Write([]string{"suspicious_count", strconv.Itoa(report.SuspiciousCount)})
	_ = writer.Write([]string{"phishing_count", strconv.Itoa(report.PhishingCount)})
	_ = writer.Write([]string{})
	_ = writer.Write([]string{"top_domains", "count"})
	for _, item := range report.TopDomains {
		_ = writer.Write([]string{item.Domain, strconv.Itoa(item.Count)})
	}
	_ = writer.Write([]string{})
	_ = writer.Write([]string{"top_accounts", "count"})
	for _, item := range report.TopAccounts {
		_ = writer.Write([]string{item.EmailAddress, strconv.Itoa(item.Count)})
	}
}
