package config

import (
	"os"
	"time"
)

type Config struct {
	HTTPAddr            string
	DatabaseURL         string
	MLBaseURL           string
	MLTimeout           time.Duration
	DefaultPollInterval time.Duration
}

func MustLoad() Config {
	return Config{
		HTTPAddr:            getenv("HTTP_ADDR", ":8080"),
		DatabaseURL:         getenv("DATABASE_URL", "postgres://localdev:localdev@localhost:5432/phishguard?sslmode=disable"),
		MLBaseURL:           getenv("ML_BASE_URL", "http://localhost:8000"),
		MLTimeout:           getDuration("ML_TIMEOUT", 2*time.Second),
		DefaultPollInterval: getDuration("POLL_INTERVAL", 15*time.Minute),
	}
}

func getenv(key, def string) string {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	return v
}

func getDuration(key string, def time.Duration) time.Duration {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return def
	}
	return d
}
