package service

import (
	"context"
	"strings"
	"time"

	"phishguard/backend/internal/mail"
	"phishguard/backend/internal/mlclient"
	"phishguard/backend/internal/parser"
	"phishguard/backend/internal/store"

	"go.uber.org/zap"
)

type Worker struct {
	db         *store.DB
	ml         mlclient.Client
	mailClient *mail.Client
	logger     *zap.Logger
}

func NewWorker(db *store.DB, ml mlclient.Client, logger *zap.Logger) *Worker {
	return &Worker{
		db:         db,
		ml:         ml,
		mailClient: mail.NewClient(),
		logger:     logger,
	}
}

func (w *Worker) RunPollingLoop(ctx context.Context, every time.Duration) {
	ticker := time.NewTicker(every)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			w.logger.Info("poll tick")
			_ = w.PollOnce(ctx)
		}
	}
}

func (w *Worker) PollOnce(ctx context.Context) error {
	w.logger.Info("poll once started")

	accounts, err := w.db.ListAccounts(ctx)
	if err != nil {
		return err
	}

	for _, acc := range accounts {
		if !acc.Enabled {
			w.logger.Info("skip disabled account",
				zap.String("email", acc.EmailAddress),
			)
			continue
		}
		if err := w.processAccount(ctx, acc); err != nil {
			accountID := acc.ID
			if insertErr := w.db.InsertAccountError(ctx, store.AccountErrorRecord{
				AccountID:    &accountID,
				EmailAddress: acc.EmailAddress,
				Stage:        "process_account",
				ErrorMessage: err.Error(),
				Details: map[string]any{
					"imap_host":       acc.IMAPHost,
					"source_mailbox":  acc.SourceMailbox,
					"action_on_high":  acc.ActionOnHigh,
					"target_mailbox":  acc.TargetMailbox,
					"poll_interval_s": acc.PollIntervalSeconds,
				},
			}); insertErr != nil {
				w.logger.Error("insert account error failed", zap.Error(insertErr))
			}
			w.logger.Error("process account failed",
				zap.String("email", acc.EmailAddress),
				zap.Error(err),
			)
		}
	}

	return nil
}

func (w *Worker) processAccount(ctx context.Context, acc store.Account) error {
	msgs, maxUID, err := w.mailClient.FetchNewMessages(ctx, acc)
	if err != nil {
		return err
	}

	emailsInserted := 0
	urlsInserted := 0
	scansInserted := 0
	actionsApplied := 0

	for _, msg := range msgs {
		emailRec, err := w.db.InsertEmail(ctx, store.EmailRecord{
			AccountID:  acc.ID,
			MessageID:  msg.MessageID,
			Subject:    msg.Subject,
			Sender:     msg.From,
			ReceivedAt: msg.ReceivedAt,
			BodyText:   msg.TextBody,
			BodyHTML:   msg.HTMLBody,
		})
		if err != nil {
			w.logger.Error("insert email failed", zap.Error(err))
			continue
		}

		if emailRec == nil {
			continue
		}

		emailsInserted++
		highRiskDetected := false

		urls := parser.ExtractURLs(msg.TextBody, msg.HTMLBody)
		for _, rawURL := range urls {
			normalized, domain, ok := parser.NormalizeURL(rawURL)
			if !ok {
				continue
			}

			urlRec, err := w.db.InsertURL(ctx, store.URLRecord{
				EmailID:       emailRec.ID,
				RawURL:        rawURL,
				NormalizedURL: normalized,
				Domain:        domain,
			})
			if err != nil {
				w.logger.Error("insert url failed", zap.Error(err))
				continue
			}

			if urlRec == nil {
				continue
			}

			urlsInserted++

			score, risk, modelVersion, features, err := w.ml.PredictURL(
				ctx,
				normalized,
				msg.Subject,
				firstSnippet(msg.TextBody, msg.HTMLBody),
			)
			if err != nil {
				w.logger.Error("ml predict failed", zap.Error(err))
				continue
			}

			verdict := "safe"
			if risk >= 3 || score >= 0.8 {
				verdict = "phishing"
				highRiskDetected = true
			} else if risk == 2 || score >= 0.5 {
				verdict = "suspicious"
			}

			_, err = w.db.InsertScanResult(ctx, store.ScanResultRecord{
				URLID:        urlRec.ID,
				ModelVersion: modelVersion,
				Score:        score,
				Risk:         risk,
				Features:     features,
				Verdict:      verdict,
			})
			if err != nil {
				w.logger.Error("insert scan result failed", zap.Error(err))
				continue
			}

			scansInserted++
		}

		if highRiskDetected {
			if err := w.mailClient.ApplyHighRiskAction(ctx, acc, msg.UID); err != nil {
				accountID := acc.ID
				if insertErr := w.db.InsertAccountError(ctx, store.AccountErrorRecord{
					AccountID:    &accountID,
					EmailAddress: acc.EmailAddress,
					Stage:        "apply_high_risk_action",
					ErrorMessage: err.Error(),
					Details: map[string]any{
						"uid":            msg.UID,
						"message_id":     msg.MessageID,
						"subject":        msg.Subject,
						"action_on_high": acc.ActionOnHigh,
						"target_mailbox": acc.TargetMailbox,
					},
				}); insertErr != nil {
					w.logger.Error("insert account error failed", zap.Error(insertErr))
				}
				w.logger.Error("apply high-risk action failed",
					zap.String("email", acc.EmailAddress),
					zap.Uint32("uid", msg.UID),
					zap.String("action", acc.ActionOnHigh),
					zap.Error(err),
				)
			} else {
				actionsApplied++
			}
		}
	}

	if maxUID > 0 {
		if err := w.db.UpdateAccountLastUID(ctx, acc.ID, int64(maxUID)); err != nil {
			w.logger.Error("update last uid failed", zap.Error(err))
		}
	}

	w.logger.Info("account processed",
		zap.String("email", acc.EmailAddress),
		zap.Int("messages_fetched", len(msgs)),
		zap.Int("emails_inserted", emailsInserted),
		zap.Int("urls_inserted", urlsInserted),
		zap.Int("scans_inserted", scansInserted),
		zap.Int("actions_applied", actionsApplied),
		zap.Uint32("max_uid", maxUID),
	)

	return nil
}

func firstSnippet(textBody, htmlBody string) string {
	src := textBody
	if strings.TrimSpace(src) == "" {
		src = htmlBody
	}
	src = strings.TrimSpace(src)
	if len(src) > 300 {
		return src[:300]
	}
	return src
}
