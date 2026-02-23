package middleware

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/vaultpass/vaultpass-go/internal/crypto"
)

type contextKey string

const userIDKey contextKey = "userID"

// JWTAuth returns middleware that validates a Bearer token from the Authorization header.
func JWTAuth(secret string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				writeJSONError(w, http.StatusUnauthorized, "missing authorization header")
				return
			}

			token, found := strings.CutPrefix(authHeader, "Bearer ")
			if !found || token == "" {
				writeJSONError(w, http.StatusUnauthorized, "invalid authorization format")
				return
			}

			claims, err := crypto.ValidateToken(token, secret)
			if err != nil {
				writeJSONError(w, http.StatusUnauthorized, "invalid or expired token")
				return
			}

			ctx := context.WithValue(r.Context(), userIDKey, claims.UserID)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// UserIDFromContext extracts the authenticated user ID from the request context.
func UserIDFromContext(ctx context.Context) (int64, bool) {
	id, ok := ctx.Value(userIDKey).(int64)
	return id, ok
}

func writeJSONError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
