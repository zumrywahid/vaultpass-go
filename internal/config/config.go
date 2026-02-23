package config

import (
	"log/slog"
	"os"
	"time"
)

type Config struct {
	Port        string
	Env         string
	DatabaseDSN string
	JWTSecret   string
	JWTExpiry   time.Duration
}

func Load() Config {
	cfg := Config{
		Port:        getEnv("PORT", "8080"),
		Env:         getEnv("ENV", "development"),
		DatabaseDSN: getEnv("DATABASE_DSN", "root:password@tcp(127.0.0.1:3306)/vaultpass?parseTime=true"),
		JWTSecret:   getEnv("JWT_SECRET", "dev-secret-change-in-production"),
		JWTExpiry:   24 * time.Hour,
	}

	if cfg.Env == "production" && cfg.JWTSecret == "dev-secret-change-in-production" {
		slog.Error("JWT_SECRET must be set in production environment")
		os.Exit(1)
	}

	return cfg
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
