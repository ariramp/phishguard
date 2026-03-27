package main

import (
	"context"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"phishguard/backend/internal/api"
	"phishguard/backend/internal/config"
	"phishguard/backend/internal/mlclient"
	"phishguard/backend/internal/service"
	"phishguard/backend/internal/store"

	"go.uber.org/zap"
)

func main() {
	cfg := config.MustLoad()

	logger, _ := zap.NewProduction()
	defer logger.Sync()

	db, err := store.NewDB(cfg.DatabaseURL)
	if err != nil {
		logger.Fatal("db connect failed", zap.Error(err))
	}
	defer db.Close()

	ml := mlclient.NewHTTP(cfg.MLBaseURL, cfg.MLTimeout)
	worker := service.NewWorker(db, ml, logger)
	router := api.NewRouter(db, worker, ml, logger)

	srv := &http.Server{
		Addr:              cfg.HTTPAddr,
		Handler:           router,
		ReadHeaderTimeout: 5 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go func() {
		logger.Info("http server started", zap.String("addr", cfg.HTTPAddr))
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Fatal("http server error", zap.Error(err))
		}
	}()

	go worker.RunPollingLoop(ctx, cfg.DefaultPollInterval)

	<-ctx.Done()

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = srv.Shutdown(shutdownCtx)
}
