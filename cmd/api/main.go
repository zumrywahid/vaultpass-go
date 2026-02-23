package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/joho/godotenv"
	"github.com/vaultpass/vaultpass-go/internal/config"
	"github.com/vaultpass/vaultpass-go/internal/handler"
	"github.com/vaultpass/vaultpass-go/internal/middleware"
	"github.com/vaultpass/vaultpass-go/internal/repository"
	"github.com/vaultpass/vaultpass-go/internal/service"
)

func main() {
	if err := godotenv.Load(); err != nil {
		slog.Warn("no .env file found, using environment variables")
	}

	cfg := config.Load()

	genService := service.NewGeneratorService()
	genHandler := handler.NewGeneratorHandler(genService)

	r := chi.NewRouter()
	r.Use(middleware.Logger)

	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})

	r.Post("/api/v1/generate", genHandler.HandleGenerate)

	// Initialize DB and auth routes if database is available.
	db, err := repository.NewDB(cfg.DatabaseDSN)
	if err != nil {
		slog.Warn("database connection failed — auth routes disabled", "error", err)
	} else {
		userRepo := repository.NewUserRepository(db)
		authService := service.NewAuthService(userRepo, cfg.JWTSecret, cfg.JWTExpiry)
		authHandler := handler.NewAuthHandler(authService)

		vaultRepo := repository.NewVaultRepository(db)
		vaultService := service.NewVaultService(vaultRepo)
		vaultHandler := handler.NewVaultHandler(vaultService)

		r.Group(func(r chi.Router) {
			r.Use(middleware.RateLimit(5, 10))
			r.Post("/api/v1/auth/register", authHandler.HandleRegister)
			r.Post("/api/v1/auth/login", authHandler.HandleLogin)
		})

		r.Group(func(r chi.Router) {
			r.Use(middleware.JWTAuth(cfg.JWTSecret))
			r.Get("/api/v1/auth/me", authHandler.HandleMe)

			r.Get("/api/v1/vault", vaultHandler.HandleListEntries)
			r.Post("/api/v1/vault", vaultHandler.HandleCreateEntry)
			r.Put("/api/v1/vault/{entry_id}", vaultHandler.HandleUpdateEntry)
			r.Delete("/api/v1/vault/{entry_id}", vaultHandler.HandleDeleteEntry)
			r.Post("/api/v1/vault/sync", vaultHandler.HandleSync)
		})
	}

	srv := &http.Server{
		Addr:    ":" + cfg.Port,
		Handler: r,
	}

	go func() {
		slog.Info("server starting", "port", cfg.Port, "env", cfg.Env)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("server error", "error", err)
			os.Exit(1)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	slog.Info("shutting down server")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		slog.Error("server forced shutdown", "error", err)
		os.Exit(1)
	}

	slog.Info("server stopped")
}
