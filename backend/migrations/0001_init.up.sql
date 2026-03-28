CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE TABLE IF NOT EXISTS model_versions (
  version TEXT PRIMARY KEY,
  base_model TEXT NOT NULL,
  metrics JSONB NOT NULL DEFAULT '{}'::jsonb,
  artifact_uri TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS accounts (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email_address TEXT NOT NULL,
  enabled BOOLEAN NOT NULL DEFAULT TRUE,
  imap_host TEXT NOT NULL,
  imap_port INT NOT NULL DEFAULT 993,
  imap_tls BOOLEAN NOT NULL DEFAULT TRUE,
  username TEXT NOT NULL,
  password_enc BYTEA NOT NULL,
  source_mailbox TEXT NOT NULL DEFAULT 'INBOX',
  poll_interval_seconds INT NOT NULL DEFAULT 900,
  action_on_high TEXT NOT NULL DEFAULT 'MOVE',
  target_mailbox TEXT NOT NULL DEFAULT 'Phishing',
  last_uid BIGINT NOT NULL DEFAULT 0,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS emails (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  account_id UUID NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  message_id TEXT,
  subject TEXT NOT NULL DEFAULT '',
  sender TEXT NOT NULL DEFAULT '',
  received_at TIMESTAMPTZ,
  body_text TEXT NOT NULL DEFAULT '',
  body_html TEXT NOT NULL DEFAULT '',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS extracted_urls (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email_id UUID NOT NULL REFERENCES emails(id) ON DELETE CASCADE,
  raw_url TEXT NOT NULL,
  normalized_url TEXT NOT NULL,
  domain TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS scan_results (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  url_id UUID NOT NULL REFERENCES extracted_urls(id) ON DELETE CASCADE,
  model_version TEXT NOT NULL,
  score REAL NOT NULL,
  risk SMALLINT NOT NULL,
  features JSONB NOT NULL DEFAULT '{}'::jsonb,
  verdict TEXT NOT NULL DEFAULT 'unknown',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_emails_account_id
  ON emails(account_id);

CREATE INDEX IF NOT EXISTS idx_urls_email_id
  ON extracted_urls(email_id);

CREATE INDEX IF NOT EXISTS idx_scan_results_url_id
  ON scan_results(url_id);

CREATE INDEX IF NOT EXISTS idx_scan_results_risk
  ON scan_results(risk);

CREATE UNIQUE INDEX IF NOT EXISTS uq_emails_account_message_id
  ON emails(account_id, message_id);

CREATE UNIQUE INDEX IF NOT EXISTS uq_urls_email_normalized_url
  ON extracted_urls(email_id, normalized_url);
