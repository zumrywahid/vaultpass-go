package handler

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/vaultpass/vaultpass-go/internal/middleware"
	"github.com/vaultpass/vaultpass-go/internal/model"
	"github.com/vaultpass/vaultpass-go/internal/service"
)

// AuthHandler handles HTTP requests for authentication.
type AuthHandler struct {
	service *service.AuthService
}

// NewAuthHandler creates a new AuthHandler.
func NewAuthHandler(svc *service.AuthService) *AuthHandler {
	return &AuthHandler{service: svc}
}

// HandleRegister handles POST /api/v1/auth/register requests.
func (h *AuthHandler) HandleRegister(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1MB

	var req model.CreateUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		if err.Error() == "http: request body too large" {
			writeJSON(w, http.StatusRequestEntityTooLarge, errorResponse("request body too large"))
			return
		}
		writeJSON(w, http.StatusBadRequest, errorResponse("invalid request body"))
		return
	}

	resp, err := h.service.Register(r.Context(), req)
	if err != nil {
		switch {
		case errors.Is(err, service.ErrEmailRequired), errors.Is(err, service.ErrPasswordRequired):
			writeJSON(w, http.StatusBadRequest, errorResponse(err.Error()))
		case errors.Is(err, service.ErrEmailTaken):
			writeJSON(w, http.StatusConflict, errorResponse(err.Error()))
		default:
			writeJSON(w, http.StatusInternalServerError, errorResponse("internal server error"))
		}
		return
	}

	writeJSON(w, http.StatusCreated, resp)
}

// HandleLogin handles POST /api/v1/auth/login requests.
func (h *AuthHandler) HandleLogin(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1MB

	var req model.LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		if err.Error() == "http: request body too large" {
			writeJSON(w, http.StatusRequestEntityTooLarge, errorResponse("request body too large"))
			return
		}
		writeJSON(w, http.StatusBadRequest, errorResponse("invalid request body"))
		return
	}

	resp, err := h.service.Login(r.Context(), req)
	if err != nil {
		if errors.Is(err, service.ErrInvalidCredentials) {
			writeJSON(w, http.StatusUnauthorized, errorResponse(err.Error()))
			return
		}
		writeJSON(w, http.StatusInternalServerError, errorResponse("internal server error"))
		return
	}

	writeJSON(w, http.StatusOK, resp)
}

// HandleMe handles GET /api/v1/auth/me requests.
func (h *AuthHandler) HandleMe(w http.ResponseWriter, r *http.Request) {
	userID, ok := middleware.UserIDFromContext(r.Context())
	if !ok {
		writeJSON(w, http.StatusUnauthorized, errorResponse("unauthorized"))
		return
	}

	resp, err := h.service.GetUser(r.Context(), userID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errorResponse("internal server error"))
		return
	}

	writeJSON(w, http.StatusOK, resp)
}
