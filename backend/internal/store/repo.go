package store

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

type Account struct {
	ID                  uuid.UUID `json:"id"`
	EmailAddress        string    `json:"email_address"`
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

func (d *DB) CreateAccount(ctx context.Context, p CreateAccountParams) (*Account, error) {
	q := `
		INSERT INTO accounts (
			email_address, imap_host, imap_port, imap_tls, username, password_enc,
			source_mailbox, poll_interval_seconds, action_on_high, target_mailbox
		)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
		RETURNING id, email_address, imap_host, imap_port, imap_tls, username, password_enc,
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
		SELECT id, email_address, imap_host, imap_port, imap_tls, username, password_enc,
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

type HistoryItem struct {
	EmailAddress  string    `json:"email_address"`
	Subject       string    `json:"subject"`
	Sender        string    `json:"sender"`
	RawURL        string    `json:"raw_url"`
	NormalizedURL string    `json:"normalized_url"`
	Domain        string    `json:"domain"`
	ModelVersion  string    `json:"model_version"`
	Score         float32   `json:"score"`
	Risk          int16     `json:"risk"`
	Verdict       string    `json:"verdict"`
	CheckedAt     time.Time `json:"checked_at"`
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
		SELECT
			a.email_address,
			e.subject,
			e.sender,
			u.raw_url,
			u.normalized_url,
			u.domain,
			s.model_version,
			s.score,
			s.risk,
			s.verdict,
			s.created_at
		FROM scan_results s
		JOIN extracted_urls u ON u.id = s.url_id
		JOIN emails e ON e.id = u.email_id
		JOIN accounts a ON a.id = e.account_id
		ORDER BY s.created_at DESC
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
			&item.EmailAddress,
			&item.Subject,
			&item.Sender,
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
	if err := d.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM scan_results`).Scan(&stats.TotalScans); err != nil {
		return nil, err
	}

	if err := d.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM scan_results WHERE verdict = 'safe'`).Scan(&stats.SafeCount); err != nil {
		return nil, err
	}
	if err := d.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM scan_results WHERE verdict = 'suspicious'`).Scan(&stats.SuspiciousCount); err != nil {
		return nil, err
	}
	if err := d.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM scan_results WHERE verdict = 'phishing'`).Scan(&stats.PhishingCount); err != nil {
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

func (d *DB) GetTimeSeriesStats(ctx context.Context, period string) ([]TimeSeriesItem, error) {
	var q string

	switch period {
	case "day":
		q = `
			SELECT
				date_trunc('hour', COALESCE(e.received_at, s.created_at)) AS bucket,
				COUNT(*) AS total_count,
				COUNT(*) FILTER (WHERE s.verdict = 'safe') AS safe_count,
				COUNT(*) FILTER (WHERE s.verdict = 'suspicious') AS suspicious_count,
				COUNT(*) FILTER (WHERE s.verdict = 'phishing') AS phishing_count
			FROM scan_results s
			JOIN extracted_urls u ON u.id = s.url_id
			JOIN emails e ON e.id = u.email_id
			WHERE COALESCE(e.received_at, s.created_at) >= now() - interval '24 hours'
			GROUP BY bucket
			ORDER BY bucket
		`
	case "week":
		q = `
			SELECT
				date_trunc('day', COALESCE(e.received_at, s.created_at)) AS bucket,
				COUNT(*) AS total_count,
				COUNT(*) FILTER (WHERE s.verdict = 'safe') AS safe_count,
				COUNT(*) FILTER (WHERE s.verdict = 'suspicious') AS suspicious_count,
				COUNT(*) FILTER (WHERE s.verdict = 'phishing') AS phishing_count
			FROM scan_results s
			JOIN extracted_urls u ON u.id = s.url_id
			JOIN emails e ON e.id = u.email_id
			WHERE COALESCE(e.received_at, s.created_at) >= now() - interval '7 days'
			GROUP BY bucket
			ORDER BY bucket
		`
	case "month":
		q = `
			SELECT
				date_trunc('day', COALESCE(e.received_at, s.created_at)) AS bucket,
				COUNT(*) AS total_count,
				COUNT(*) FILTER (WHERE s.verdict = 'safe') AS safe_count,
				COUNT(*) FILTER (WHERE s.verdict = 'suspicious') AS suspicious_count,
				COUNT(*) FILTER (WHERE s.verdict = 'phishing') AS phishing_count
			FROM scan_results s
			JOIN extracted_urls u ON u.id = s.url_id
			JOIN emails e ON e.id = u.email_id
			WHERE COALESCE(e.received_at, s.created_at) >= now() - interval '1 month'
			GROUP BY bucket
			ORDER BY bucket
		`
	case "year":
		q = `
			SELECT
				date_trunc('month', COALESCE(e.received_at, s.created_at)) AS bucket,
				COUNT(*) AS total_count,
				COUNT(*) FILTER (WHERE s.verdict = 'safe') AS safe_count,
				COUNT(*) FILTER (WHERE s.verdict = 'suspicious') AS suspicious_count,
				COUNT(*) FILTER (WHERE s.verdict = 'phishing') AS phishing_count
			FROM scan_results s
			JOIN extracted_urls u ON u.id = s.url_id
			JOIN emails e ON e.id = u.email_id
			WHERE COALESCE(e.received_at, s.created_at) >= now() - interval '1 year'
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
