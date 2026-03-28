package store

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

type DB struct {
	Pool *pgxpool.Pool
}

func NewDB(databaseURL string) (*DB, error) {
	cfg, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		return nil, err
	}

	cfg.MaxConns = 10
	cfg.MinConns = 1
	cfg.MaxConnLifetime = 30 * time.Minute

	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		return nil, err
	}

	db := &DB{Pool: pool}
	if err := db.ensureRuntimeTables(context.Background()); err != nil {
		pool.Close()
		return nil, err
	}

	return db, nil
}

func (d *DB) Close() {
	d.Pool.Close()
}

func (d *DB) Ping(ctx context.Context) error {
	return d.Pool.Ping(ctx)
}

func (d *DB) ensureRuntimeTables(ctx context.Context) error {
	_, err := d.Pool.Exec(ctx, `
		ALTER TABLE accounts
		ADD COLUMN IF NOT EXISTS enabled BOOLEAN NOT NULL DEFAULT TRUE
	`)
	if err != nil {
		return err
	}

	_, err = d.Pool.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS account_errors (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			account_id UUID REFERENCES accounts(id) ON DELETE CASCADE,
			email_address TEXT NOT NULL DEFAULT '',
			stage TEXT NOT NULL,
			error_message TEXT NOT NULL,
			details JSONB NOT NULL DEFAULT '{}'::jsonb,
			created_at TIMESTAMPTZ NOT NULL DEFAULT now()
		)
	`)
	if err != nil {
		return err
	}

	_, err = d.Pool.Exec(ctx, `
		CREATE INDEX IF NOT EXISTS idx_account_errors_created_at
		ON account_errors(created_at DESC)
	`)
	if err != nil {
		return err
	}

	_, err = d.Pool.Exec(ctx, `
		CREATE INDEX IF NOT EXISTS idx_account_errors_account_id
		ON account_errors(account_id)
	`)
	return err
}
