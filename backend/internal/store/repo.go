package store

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type Account struct {
	ID                  uuid.UUID `json:"id"`
	EmailAddress        string    `json:"email_address"`
	Enabled             bool      `json:"enabled"`
	IMAPHost            string    `json:"imap_host"`
	IMAPPort            int       `json:"imap_port"`
	IMAPTLS             bool      `json:"imap_tls"`
	Username            string    `json:"username"`
	PasswordEnc         []byte    `json:"-"`
	SourceMailbox       string    `json:"source_mailbox"`
	PollIntervalSeconds int       `json:"poll_interval_seconds"`
	ActionOnHigh        string    `json:"action_on_high"`
	TargetMailbox       string    `json:"target_mailbox"`
	LastUID             int64     `json:"last_uid"`
	CreatedAt           time.Time `json:"created_at"`
	UpdatedAt           time.Time `json:"updated_at"`
}

type CreateAccountParams struct {
	EmailAddress        string `json:"email_address"`
	IMAPHost            string `json:"imap_host"`
	IMAPPort            int    `json:"imap_port"`
	IMAPTLS             bool   `json:"imap_tls"`
	Username            string `json:"username"`
	Password            string `json:"password"`
	SourceMailbox       string `json:"source_mailbox"`
	PollIntervalSeconds int    `json:"poll_interval_seconds"`
	ActionOnHigh        string `json:"action_on_high"`
	TargetMailbox       string `json:"target_mailbox"`
}

type UpdateAccountParams struct {
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
}

type DeleteAccountSummary struct {
	AccountID     uuid.UUID `json:"account_id"`
	EmailAddress  string    `json:"email_address"`
	EmailsCount   int       `json:"emails_count"`
	URLsCount     int       `json:"urls_count"`
	ScansCount    int       `json:"scans_count"`
	DeletedAt     time.Time `json:"deleted_at"`
}

type AccountErrorRecord struct {
	AccountID    *uuid.UUID     `json:"account_id,omitempty"`
	EmailAddress string         `json:"email_address"`
	Stage        string         `json:"stage"`
	ErrorMessage string         `json:"error_message"`
	Details      map[string]any `json:"details"`
	CreatedAt    time.Time      `json:"created_at"`
}

type EmailRecord struct {
	ID         uuid.UUID
	AccountID  uuid.UUID
	MessageID  string
	Subject    string
	Sender     string
	ReceivedAt *time.Time
	BodyText   string
	BodyHTML   string
	CreatedAt  time.Time
}

type URLRecord struct {
	ID            uuid.UUID
	EmailID       uuid.UUID
	RawURL        string
	NormalizedURL string
	Domain        string
	CreatedAt     time.Time
}

type ScanResultRecord struct {
	ID           uuid.UUID
	URLID        uuid.UUID
	ModelVersion string
	Score        float32
	Risk         int16
	Features     map[string]any
	Verdict      string
	CreatedAt    time.Time
}

type RescoreCandidate struct {
	URLID          uuid.UUID
	NormalizedURL  string
	EmailSubject   string
	EmailBodyText  string
	EmailBodyHTML  string
}

func (d *DB) CreateAccount(ctx context.Context, p CreateAccountParams) (*Account, error) {
	q := `
		INSERT INTO accounts (
			email_address, enabled, imap_host, imap_port, imap_tls, username, password_enc,
			source_mailbox, poll_interval_seconds, action_on_high, target_mailbox
		)
		VALUES ($1,TRUE,$2,$3,$4,$5,$6,$7,$8,$9,$10)
		RETURNING id, email_address, enabled, imap_host, imap_port, imap_tls, username, password_enc,
		          source_mailbox, poll_interval_seconds, action_on_high, target_mailbox, last_uid, created_at, updated_at
	`

	var a Account
	err := d.Pool.QueryRow(
		ctx,
		q,
		p.EmailAddress,
		p.IMAPHost,
		p.IMAPPort,
		p.IMAPTLS,
		p.Username,
		[]byte(p.Password),
		p.SourceMailbox,
		p.PollIntervalSeconds,
		p.ActionOnHigh,
		p.TargetMailbox,
	).Scan(
		&a.ID,
		&a.EmailAddress,
		&a.Enabled,
		&a.IMAPHost,
		&a.IMAPPort,
		&a.IMAPTLS,
		&a.Username,
		&a.PasswordEnc,
		&a.SourceMailbox,
		&a.PollIntervalSeconds,
		&a.ActionOnHigh,
		&a.TargetMailbox,
		&a.LastUID,
		&a.CreatedAt,
		&a.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}

	return &a, nil
}

func (d *DB) ListAccounts(ctx context.Context) ([]Account, error) {
	q := `
		SELECT id, email_address, enabled, imap_host, imap_port, imap_tls, username, password_enc,
		       source_mailbox, poll_interval_seconds, action_on_high, target_mailbox, last_uid, created_at, updated_at
		FROM accounts
		ORDER BY created_at DESC
	`

	rows, err := d.Pool.Query(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var items []Account
	for rows.Next() {
		var a Account
		if err := rows.Scan(
			&a.ID,
			&a.EmailAddress,
			&a.Enabled,
			&a.IMAPHost,
			&a.IMAPPort,
			&a.IMAPTLS,
			&a.Username,
			&a.PasswordEnc,
			&a.SourceMailbox,
			&a.PollIntervalSeconds,
			&a.ActionOnHigh,
			&a.TargetMailbox,
			&a.LastUID,
			&a.CreatedAt,
			&a.UpdatedAt,
		); err != nil {
			return nil, err
		}
		items = append(items, a)
	}

	return items, rows.Err()
}

func (d *DB) GetAccountByID(ctx context.Context, accountID uuid.UUID) (*Account, error) {
	q := `
		SELECT id, email_address, enabled, imap_host, imap_port, imap_tls, username, password_enc,
		       source_mailbox, poll_interval_seconds, action_on_high, target_mailbox, last_uid, created_at, updated_at
		FROM accounts
		WHERE id = $1
	`

	var a Account
	err := d.Pool.QueryRow(ctx, q, accountID).Scan(
		&a.ID,
		&a.EmailAddress,
		&a.Enabled,
		&a.IMAPHost,
		&a.IMAPPort,
		&a.IMAPTLS,
		&a.Username,
		&a.PasswordEnc,
		&a.SourceMailbox,
		&a.PollIntervalSeconds,
		&a.ActionOnHigh,
		&a.TargetMailbox,
		&a.LastUID,
		&a.CreatedAt,
		&a.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}

	return &a, nil
}

func (d *DB) UpdateAccount(ctx context.Context, accountID uuid.UUID, p UpdateAccountParams) (*Account, error) {
	current, err := d.GetAccountByID(ctx, accountID)
	if err != nil {
		return nil, err
	}

	emailAddress := current.EmailAddress
	if p.EmailAddress != nil {
		emailAddress = *p.EmailAddress
	}

	enabled := current.Enabled
	if p.Enabled != nil {
		enabled = *p.Enabled
	}

	imapHost := current.IMAPHost
	if p.IMAPHost != nil {
		imapHost = *p.IMAPHost
	}

	imapPort := current.IMAPPort
	if p.IMAPPort != nil {
		imapPort = *p.IMAPPort
	}

	imapTLS := current.IMAPTLS
	if p.IMAPTLS != nil {
		imapTLS = *p.IMAPTLS
	}

	username := current.Username
	if p.Username != nil {
		username = *p.Username
	}

	passwordEnc := current.PasswordEnc
	if p.Password != nil && *p.Password != "" {
		passwordEnc = []byte(*p.Password)
	}

	sourceMailbox := current.SourceMailbox
	if p.SourceMailbox != nil {
		sourceMailbox = *p.SourceMailbox
	}

	pollIntervalSeconds := current.PollIntervalSeconds
	if p.PollIntervalSeconds != nil {
		pollIntervalSeconds = *p.PollIntervalSeconds
	}

	actionOnHigh := current.ActionOnHigh
	if p.ActionOnHigh != nil {
		actionOnHigh = *p.ActionOnHigh
	}

	targetMailbox := current.TargetMailbox
	if p.TargetMailbox != nil {
		targetMailbox = *p.TargetMailbox
	}

	q := `
		UPDATE accounts
		SET email_address = $2,
		    enabled = $3,
		    imap_host = $4,
		    imap_port = $5,
		    imap_tls = $6,
		    username = $7,
		    password_enc = $8,
		    source_mailbox = $9,
		    poll_interval_seconds = $10,
		    action_on_high = $11,
		    target_mailbox = $12,
		    updated_at = now()
		WHERE id = $1
		RETURNING id, email_address, enabled, imap_host, imap_port, imap_tls, username, password_enc,
		          source_mailbox, poll_interval_seconds, action_on_high, target_mailbox, last_uid, created_at, updated_at
	`

	var a Account
	err = d.Pool.QueryRow(
		ctx,
		q,
		accountID,
		emailAddress,
		enabled,
		imapHost,
		imapPort,
		imapTLS,
		username,
		passwordEnc,
		sourceMailbox,
		pollIntervalSeconds,
		actionOnHigh,
		targetMailbox,
	).Scan(
		&a.ID,
		&a.EmailAddress,
		&a.Enabled,
		&a.IMAPHost,
		&a.IMAPPort,
		&a.IMAPTLS,
		&a.Username,
		&a.PasswordEnc,
		&a.SourceMailbox,
		&a.PollIntervalSeconds,
		&a.ActionOnHigh,
		&a.TargetMailbox,
		&a.LastUID,
		&a.CreatedAt,
		&a.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}

	return &a, nil
}

func (d *DB) DeleteAccount(ctx context.Context, accountID uuid.UUID) (*DeleteAccountSummary, error) {
	tx, err := d.Pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	summary := &DeleteAccountSummary{AccountID: accountID}

	err = tx.QueryRow(ctx, `
		SELECT email_address
		FROM accounts
		WHERE id = $1
	`, accountID).Scan(&summary.EmailAddress)
	if err != nil {
		return nil, err
	}

	err = tx.QueryRow(ctx, `
		SELECT
			COUNT(DISTINCT e.id) AS emails_count,
			COUNT(DISTINCT u.id) AS urls_count,
			COUNT(DISTINCT s.id) AS scans_count
		FROM emails e
		LEFT JOIN extracted_urls u ON u.email_id = e.id
		LEFT JOIN scan_results s ON s.url_id = u.id
		WHERE e.account_id = $1
	`, accountID).Scan(&summary.EmailsCount, &summary.URLsCount, &summary.ScansCount)
	if err != nil {
		return nil, err
	}

	tag, err := tx.Exec(ctx, `
		DELETE FROM accounts
		WHERE id = $1
	`, accountID)
	if err != nil {
		return nil, err
	}
	if tag.RowsAffected() == 0 {
		return nil, pgx.ErrNoRows
	}

	summary.DeletedAt = time.Now().UTC()

	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}

	return summary, nil
}

func (d *DB) UpdateAccountLastUID(ctx context.Context, accountID uuid.UUID, lastUID int64) error {
	_, err := d.Pool.Exec(ctx, `
		UPDATE accounts
		SET last_uid = $2, updated_at = now()
		WHERE id = $1
	`, accountID, lastUID)
	return err
}

func (d *DB) InsertEmail(ctx context.Context, e EmailRecord) (*EmailRecord, error) {
	q := `
		INSERT INTO emails (account_id, message_id, subject, sender, received_at, body_text, body_html)
		VALUES ($1,$2,$3,$4,$5,$6,$7)
		ON CONFLICT (account_id, message_id) DO NOTHING
		RETURNING id, created_at
	`

	var out EmailRecord = e
	err := d.Pool.QueryRow(
		ctx, q,
		e.AccountID, e.MessageID, e.Subject, e.Sender, e.ReceivedAt, e.BodyText, e.BodyHTML,
	).Scan(&out.ID, &out.CreatedAt)

	if err != nil {
		// если запись уже есть, просто вернём nil,nil
		if strings.Contains(err.Error(), "no rows in result set") {
			return nil, nil
		}
		return nil, err
	}

	return &out, nil
}

func (d *DB) InsertURL(ctx context.Context, u URLRecord) (*URLRecord, error) {
	q := `
		INSERT INTO extracted_urls (email_id, raw_url, normalized_url, domain)
		VALUES ($1,$2,$3,$4)
		ON CONFLICT (email_id, normalized_url) DO NOTHING
		RETURNING id, created_at
	`

	var out URLRecord = u
	err := d.Pool.QueryRow(
		ctx, q,
		u.EmailID, u.RawURL, u.NormalizedURL, u.Domain,
	).Scan(&out.ID, &out.CreatedAt)

	if err != nil {
		if strings.Contains(err.Error(), "no rows in result set") {
			return nil, nil
		}
		return nil, err
	}

	return &out, nil
}

func (d *DB) InsertScanResult(ctx context.Context, s ScanResultRecord) (*ScanResultRecord, error) {
	q := `
		INSERT INTO scan_results (url_id, model_version, score, risk, features, verdict)
		VALUES ($1,$2,$3,$4,$5,$6)
		RETURNING id, created_at
	`

	rawFeatures, err := json.Marshal(s.Features)
	if err != nil {
		return nil, err
	}

	var out ScanResultRecord = s
	err = d.Pool.QueryRow(
		ctx, q,
		s.URLID, s.ModelVersion, s.Score, s.Risk, rawFeatures, s.Verdict,
	).Scan(&out.ID, &out.CreatedAt)
	if err != nil {
		return nil, err
	}

	return &out, nil
}

func (d *DB) GetRescoreCandidates(ctx context.Context, limit int) ([]RescoreCandidate, error) {
	if limit <= 0 || limit > 10000 {
		limit = 1000
	}

	rows, err := d.Pool.Query(ctx, `
		SELECT
			u.id,
			u.normalized_url,
			e.subject,
			e.body_text,
			e.body_html
		FROM extracted_urls u
		JOIN emails e ON e.id = u.email_id
		ORDER BY e.created_at DESC, u.created_at DESC
		LIMIT $1
	`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var items []RescoreCandidate
	for rows.Next() {
		var item RescoreCandidate
		if err := rows.Scan(
			&item.URLID,
			&item.NormalizedURL,
			&item.EmailSubject,
			&item.EmailBodyText,
			&item.EmailBodyHTML,
		); err != nil {
			return nil, err
		}
		items = append(items, item)
	}

	return items, rows.Err()
}

func (d *DB) InsertAccountError(ctx context.Context, rec AccountErrorRecord) error {
	rawDetails, err := json.Marshal(rec.Details)
	if err != nil {
		return err
	}

	_, err = d.Pool.Exec(ctx, `
		INSERT INTO account_errors (account_id, email_address, stage, error_message, details)
		VALUES ($1, $2, $3, $4, $5)
	`, rec.AccountID, rec.EmailAddress, rec.Stage, rec.ErrorMessage, rawDetails)
	return err
}

func (d *DB) ListAccountErrors(ctx context.Context, limit int) ([]AccountErrorRecord, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}

	rows, err := d.Pool.Query(ctx, `
		SELECT account_id, email_address, stage, error_message, details, created_at
		FROM account_errors
		ORDER BY created_at DESC
		LIMIT $1
	`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var items []AccountErrorRecord
	for rows.Next() {
		var item AccountErrorRecord
		var accountID *uuid.UUID
		var detailsRaw []byte
		if err := rows.Scan(
			&accountID,
			&item.EmailAddress,
			&item.Stage,
			&item.ErrorMessage,
			&detailsRaw,
			&item.CreatedAt,
		); err != nil {
			return nil, err
		}
		if accountID != nil {
			item.AccountID = accountID
		}
		if len(detailsRaw) > 0 {
			_ = json.Unmarshal(detailsRaw, &item.Details)
		}
		if item.Details == nil {
			item.Details = map[string]any{}
		}
		items = append(items, item)
	}

	return items, rows.Err()
}

type HistoryItem struct {
	EmailID      uuid.UUID `json:"email_id"`
	EmailAddress string    `json:"email_address"`
	Subject      string    `json:"subject"`
	Sender       string    `json:"sender"`
	MessageID    string    `json:"message_id"`
	URLCount     int       `json:"url_count"`
	TopDomain    string    `json:"top_domain"`
	ModelVersion string    `json:"model_version"`
	MaxScore     float32   `json:"max_score"`
	MaxRisk      int16     `json:"max_risk"`
	Verdict      string    `json:"verdict"`
	CheckedAt    time.Time `json:"checked_at"`
}

type Stats struct {
	TotalAccounts int `json:"total_accounts"`
	TotalEmails   int `json:"total_emails"`
	TotalURLs     int `json:"total_urls"`
	TotalScans    int `json:"total_scans"`

	SafeCount       int `json:"safe_count"`
	SuspiciousCount int `json:"suspicious_count"`
	PhishingCount   int `json:"phishing_count"`
}

func (d *DB) GetHistory(ctx context.Context, limit int) ([]HistoryItem, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}

	q := `
		WITH latest_scans AS (
			SELECT DISTINCT ON (s.url_id)
				s.url_id,
				s.model_version,
				s.score,
				s.risk,
				s.verdict,
				s.created_at
			FROM scan_results s
			ORDER BY s.url_id, s.created_at DESC
		)
		SELECT
			email_id,
			email_address,
			subject,
			sender,
			message_id,
			url_count,
			top_domain,
			model_version,
			max_score,
			max_risk,
			verdict,
			checked_at
		FROM (
			SELECT
				e.id AS email_id,
				a.email_address,
				e.subject,
				e.sender,
				e.message_id,
				COUNT(DISTINCT u.id) AS url_count,
				(ARRAY_AGG(u.domain ORDER BY ls.risk DESC, ls.score DESC, u.domain))[1] AS top_domain,
				(ARRAY_AGG(ls.model_version ORDER BY ls.created_at DESC))[1] AS model_version,
				MAX(ls.score) AS max_score,
				MAX(ls.risk) AS max_risk,
				CASE
					WHEN BOOL_OR(ls.verdict = 'phishing') THEN 'phishing'
					WHEN BOOL_OR(ls.verdict = 'suspicious') THEN 'suspicious'
					ELSE 'safe'
				END AS verdict,
				MAX(ls.created_at) AS checked_at
			FROM latest_scans ls
			JOIN extracted_urls u ON u.id = ls.url_id
			JOIN emails e ON e.id = u.email_id
			JOIN accounts a ON a.id = e.account_id
			GROUP BY a.email_address, e.id, e.message_id, e.subject, e.sender
		) AS grouped
		ORDER BY checked_at DESC
		LIMIT $1
	`

	rows, err := d.Pool.Query(ctx, q, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var items []HistoryItem
	for rows.Next() {
		var item HistoryItem
		if err := rows.Scan(
			&item.EmailID,
			&item.EmailAddress,
			&item.Subject,
			&item.Sender,
			&item.MessageID,
			&item.URLCount,
			&item.TopDomain,
			&item.ModelVersion,
			&item.MaxScore,
			&item.MaxRisk,
			&item.Verdict,
			&item.CheckedAt,
		); err != nil {
			return nil, err
		}
		items = append(items, item)
	}

	return items, rows.Err()
}

type HistoryDetailItem struct {
	RawURL        string    `json:"raw_url"`
	NormalizedURL string    `json:"normalized_url"`
	Domain        string    `json:"domain"`
	ModelVersion  string    `json:"model_version"`
	Score         float32   `json:"score"`
	Risk          int16     `json:"risk"`
	Verdict       string    `json:"verdict"`
	CheckedAt     time.Time `json:"checked_at"`
}

func (d *DB) GetHistoryDetails(ctx context.Context, emailID uuid.UUID) ([]HistoryDetailItem, error) {
	q := `
		WITH latest_scans AS (
			SELECT DISTINCT ON (s.url_id)
				s.url_id,
				s.model_version,
				s.score,
				s.risk,
				s.verdict,
				s.created_at
			FROM scan_results s
			ORDER BY s.url_id, s.created_at DESC
		)
		SELECT
			u.raw_url,
			u.normalized_url,
			u.domain,
			ls.model_version,
			ls.score,
			ls.risk,
			ls.verdict,
			ls.created_at
		FROM latest_scans ls
		JOIN extracted_urls u ON u.id = ls.url_id
		WHERE u.email_id = $1
		ORDER BY ls.created_at DESC, ls.risk DESC, ls.score DESC
	`

	rows, err := d.Pool.Query(ctx, q, emailID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var items []HistoryDetailItem
	for rows.Next() {
		var item HistoryDetailItem
		if err := rows.Scan(
			&item.RawURL,
			&item.NormalizedURL,
			&item.Domain,
			&item.ModelVersion,
			&item.Score,
			&item.Risk,
			&item.Verdict,
			&item.CheckedAt,
		); err != nil {
			return nil, err
		}
		items = append(items, item)
	}

	return items, rows.Err()
}

func (d *DB) GetStats(ctx context.Context) (*Stats, error) {
	stats := &Stats{}

	if err := d.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM accounts`).Scan(&stats.TotalAccounts); err != nil {
		return nil, err
	}
	if err := d.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM emails`).Scan(&stats.TotalEmails); err != nil {
		return nil, err
	}
	if err := d.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM extracted_urls`).Scan(&stats.TotalURLs); err != nil {
		return nil, err
	}
	if err := d.Pool.QueryRow(ctx, `
		WITH latest_scans AS (
			SELECT DISTINCT ON (s.url_id) s.url_id, s.verdict
			FROM scan_results s
			ORDER BY s.url_id, s.created_at DESC
		)
		SELECT
			COUNT(*) AS total_scans,
			COUNT(*) FILTER (WHERE verdict = 'safe') AS safe_count,
			COUNT(*) FILTER (WHERE verdict = 'suspicious') AS suspicious_count,
			COUNT(*) FILTER (WHERE verdict = 'phishing') AS phishing_count
		FROM latest_scans
	`).Scan(&stats.TotalScans, &stats.SafeCount, &stats.SuspiciousCount, &stats.PhishingCount); err != nil {
		return nil, err
	}

	return stats, nil
}

type TimeSeriesItem struct {
	Bucket          time.Time `json:"bucket"`
	TotalCount      int       `json:"total_count"`
	SafeCount       int       `json:"safe_count"`
	SuspiciousCount int       `json:"suspicious_count"`
	PhishingCount   int       `json:"phishing_count"`
}

type DetectionReportRow struct {
	CheckedAt      time.Time `json:"checked_at"`
	EmailAddress   string    `json:"email_address"`
	Sender         string    `json:"sender"`
	Subject        string    `json:"subject"`
	RawURL         string    `json:"raw_url"`
	NormalizedURL  string    `json:"normalized_url"`
	Domain         string    `json:"domain"`
	Score          float32   `json:"score"`
	Risk           int16     `json:"risk"`
	Verdict        string    `json:"verdict"`
	ModelVersion   string    `json:"model_version"`
}

type SummaryReport struct {
	Period           string                `json:"period"`
	GeneratedAt      time.Time             `json:"generated_at"`
	TotalEmails      int                   `json:"total_emails"`
	TotalURLs        int                   `json:"total_urls"`
	TotalScans       int                   `json:"total_scans"`
	SafeCount        int                   `json:"safe_count"`
	SuspiciousCount  int                   `json:"suspicious_count"`
	PhishingCount    int                   `json:"phishing_count"`
	TopDomains       []SummaryDomainStat   `json:"top_domains"`
	TopAccounts      []SummaryAccountStat  `json:"top_accounts"`
}

type SummaryDomainStat struct {
	Domain string `json:"domain"`
	Count  int    `json:"count"`
}

type SummaryAccountStat struct {
	EmailAddress string `json:"email_address"`
	Count        int    `json:"count"`
}

func (d *DB) GetDetectionReport(ctx context.Context, period string, limit int) ([]DetectionReportRow, error) {
	if limit <= 0 || limit > 5000 {
		limit = 1000
	}

	var interval string
	switch period {
	case "day":
		interval = "24 hours"
	case "week":
		interval = "7 days"
	case "month":
		interval = "1 month"
	case "year":
		interval = "1 year"
	default:
		return nil, fmt.Errorf("unsupported period: %s", period)
	}

	rows, err := d.Pool.Query(ctx, `
		WITH latest_scans AS (
			SELECT DISTINCT ON (s.url_id)
				s.url_id,
				s.created_at,
				s.verdict,
				s.score,
				s.risk,
				s.model_version
			FROM scan_results s
			ORDER BY s.url_id, s.created_at DESC
		)
		SELECT
			ls.created_at,
			a.email_address,
			e.sender,
			e.subject,
			u.raw_url,
			u.normalized_url,
			u.domain,
			ls.score,
			ls.risk,
			ls.verdict,
			ls.model_version
		FROM latest_scans ls
		JOIN extracted_urls u ON u.id = ls.url_id
		JOIN emails e ON e.id = u.email_id
		JOIN accounts a ON a.id = e.account_id
		WHERE COALESCE(e.received_at, ls.created_at) >= now() - ($1::interval)
		ORDER BY ls.created_at DESC
		LIMIT $2
	`, interval, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var items []DetectionReportRow
	for rows.Next() {
		var item DetectionReportRow
		if err := rows.Scan(
			&item.CheckedAt,
			&item.EmailAddress,
			&item.Sender,
			&item.Subject,
			&item.RawURL,
			&item.NormalizedURL,
			&item.Domain,
			&item.Score,
			&item.Risk,
			&item.Verdict,
			&item.ModelVersion,
		); err != nil {
			return nil, err
		}
		items = append(items, item)
	}

	return items, rows.Err()
}

func (d *DB) GetSummaryReport(ctx context.Context, period string) (*SummaryReport, error) {
	var interval string
	switch period {
	case "day":
		interval = "24 hours"
	case "week":
		interval = "7 days"
	case "month":
		interval = "1 month"
	case "year":
		interval = "1 year"
	default:
		return nil, fmt.Errorf("unsupported period: %s", period)
	}

	report := &SummaryReport{
		Period:      period,
		GeneratedAt: time.Now().UTC(),
		TopDomains:  []SummaryDomainStat{},
		TopAccounts: []SummaryAccountStat{},
	}

	err := d.Pool.QueryRow(ctx, `
		WITH latest_scans AS (
			SELECT DISTINCT ON (s.url_id)
				s.url_id,
				s.created_at,
				s.verdict
			FROM scan_results s
			ORDER BY s.url_id, s.created_at DESC
		)
		SELECT
			COUNT(DISTINCT e.id) AS total_emails,
			COUNT(DISTINCT u.id) AS total_urls,
			COUNT(ls.url_id) AS total_scans,
			COUNT(*) FILTER (WHERE ls.verdict = 'safe') AS safe_count,
			COUNT(*) FILTER (WHERE ls.verdict = 'suspicious') AS suspicious_count,
			COUNT(*) FILTER (WHERE ls.verdict = 'phishing') AS phishing_count
		FROM latest_scans ls
		JOIN extracted_urls u ON u.id = ls.url_id
		JOIN emails e ON e.id = u.email_id
		WHERE COALESCE(e.received_at, ls.created_at) >= now() - ($1::interval)
	`, interval).Scan(
		&report.TotalEmails,
		&report.TotalURLs,
		&report.TotalScans,
		&report.SafeCount,
		&report.SuspiciousCount,
		&report.PhishingCount,
	)
	if err != nil {
		return nil, err
	}

	domainRows, err := d.Pool.Query(ctx, `
		WITH latest_scans AS (
			SELECT DISTINCT ON (s.url_id)
				s.url_id,
				s.created_at
			FROM scan_results s
			ORDER BY s.url_id, s.created_at DESC
		)
		SELECT u.domain, COUNT(*) AS cnt
		FROM latest_scans ls
		JOIN extracted_urls u ON u.id = ls.url_id
		JOIN emails e ON e.id = u.email_id
		WHERE COALESCE(e.received_at, ls.created_at) >= now() - ($1::interval)
		GROUP BY u.domain
		ORDER BY cnt DESC, u.domain
		LIMIT 10
	`, interval)
	if err != nil {
		return nil, err
	}
	defer domainRows.Close()

	for domainRows.Next() {
		var item SummaryDomainStat
		if err := domainRows.Scan(&item.Domain, &item.Count); err != nil {
			return nil, err
		}
		report.TopDomains = append(report.TopDomains, item)
	}
	if err := domainRows.Err(); err != nil {
		return nil, err
	}

	accountRows, err := d.Pool.Query(ctx, `
		WITH latest_scans AS (
			SELECT DISTINCT ON (s.url_id)
				s.url_id,
				s.created_at
			FROM scan_results s
			ORDER BY s.url_id, s.created_at DESC
		)
		SELECT a.email_address, COUNT(*) AS cnt
		FROM latest_scans ls
		JOIN extracted_urls u ON u.id = ls.url_id
		JOIN emails e ON e.id = u.email_id
		JOIN accounts a ON a.id = e.account_id
		WHERE COALESCE(e.received_at, ls.created_at) >= now() - ($1::interval)
		GROUP BY a.email_address
		ORDER BY cnt DESC, a.email_address
		LIMIT 10
	`, interval)
	if err != nil {
		return nil, err
	}
	defer accountRows.Close()

	for accountRows.Next() {
		var item SummaryAccountStat
		if err := accountRows.Scan(&item.EmailAddress, &item.Count); err != nil {
			return nil, err
		}
		report.TopAccounts = append(report.TopAccounts, item)
	}
	if err := accountRows.Err(); err != nil {
		return nil, err
	}

	return report, nil
}

func (d *DB) GetTimeSeriesStats(ctx context.Context, period string) ([]TimeSeriesItem, error) {
	var q string

	switch period {
	case "day":
		q = `
			WITH latest_scans AS (
				SELECT DISTINCT ON (s.url_id)
					s.url_id,
					s.created_at,
					s.verdict
				FROM scan_results s
				ORDER BY s.url_id, s.created_at DESC
			)
			SELECT
				date_trunc('hour', COALESCE(e.received_at, ls.created_at)) AS bucket,
				COUNT(*) AS total_count,
				COUNT(*) FILTER (WHERE ls.verdict = 'safe') AS safe_count,
				COUNT(*) FILTER (WHERE ls.verdict = 'suspicious') AS suspicious_count,
				COUNT(*) FILTER (WHERE ls.verdict = 'phishing') AS phishing_count
			FROM latest_scans ls
			JOIN extracted_urls u ON u.id = ls.url_id
			JOIN emails e ON e.id = u.email_id
			WHERE COALESCE(e.received_at, ls.created_at) >= now() - interval '24 hours'
			GROUP BY bucket
			ORDER BY bucket
		`
	case "week":
		q = `
			WITH latest_scans AS (
				SELECT DISTINCT ON (s.url_id)
					s.url_id,
					s.created_at,
					s.verdict
				FROM scan_results s
				ORDER BY s.url_id, s.created_at DESC
			)
			SELECT
				date_trunc('day', COALESCE(e.received_at, ls.created_at)) AS bucket,
				COUNT(*) AS total_count,
				COUNT(*) FILTER (WHERE ls.verdict = 'safe') AS safe_count,
				COUNT(*) FILTER (WHERE ls.verdict = 'suspicious') AS suspicious_count,
				COUNT(*) FILTER (WHERE ls.verdict = 'phishing') AS phishing_count
			FROM latest_scans ls
			JOIN extracted_urls u ON u.id = ls.url_id
			JOIN emails e ON e.id = u.email_id
			WHERE COALESCE(e.received_at, ls.created_at) >= now() - interval '7 days'
			GROUP BY bucket
			ORDER BY bucket
		`
	case "month":
		q = `
			WITH latest_scans AS (
				SELECT DISTINCT ON (s.url_id)
					s.url_id,
					s.created_at,
					s.verdict
				FROM scan_results s
				ORDER BY s.url_id, s.created_at DESC
			)
			SELECT
				date_trunc('day', COALESCE(e.received_at, ls.created_at)) AS bucket,
				COUNT(*) AS total_count,
				COUNT(*) FILTER (WHERE ls.verdict = 'safe') AS safe_count,
				COUNT(*) FILTER (WHERE ls.verdict = 'suspicious') AS suspicious_count,
				COUNT(*) FILTER (WHERE ls.verdict = 'phishing') AS phishing_count
			FROM latest_scans ls
			JOIN extracted_urls u ON u.id = ls.url_id
			JOIN emails e ON e.id = u.email_id
			WHERE COALESCE(e.received_at, ls.created_at) >= now() - interval '1 month'
			GROUP BY bucket
			ORDER BY bucket
		`
	case "year":
		q = `
			WITH latest_scans AS (
				SELECT DISTINCT ON (s.url_id)
					s.url_id,
					s.created_at,
					s.verdict
				FROM scan_results s
				ORDER BY s.url_id, s.created_at DESC
			)
			SELECT
				date_trunc('month', COALESCE(e.received_at, ls.created_at)) AS bucket,
				COUNT(*) AS total_count,
				COUNT(*) FILTER (WHERE ls.verdict = 'safe') AS safe_count,
				COUNT(*) FILTER (WHERE ls.verdict = 'suspicious') AS suspicious_count,
				COUNT(*) FILTER (WHERE ls.verdict = 'phishing') AS phishing_count
			FROM latest_scans ls
			JOIN extracted_urls u ON u.id = ls.url_id
			JOIN emails e ON e.id = u.email_id
			WHERE COALESCE(e.received_at, ls.created_at) >= now() - interval '1 year'
			GROUP BY bucket
			ORDER BY bucket
		`
	default:
		return nil, fmt.Errorf("unsupported period: %s", period)
	}

	rows, err := d.Pool.Query(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var items []TimeSeriesItem
	for rows.Next() {
		var item TimeSeriesItem
		if err := rows.Scan(
			&item.Bucket,
			&item.TotalCount,
			&item.SafeCount,
			&item.SuspiciousCount,
			&item.PhishingCount,
		); err != nil {
			return nil, err
		}
		items = append(items, item)
	}

	return items, rows.Err()
}
