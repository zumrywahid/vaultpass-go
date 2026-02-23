package handler

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/vaultpass/vaultpass-go/internal/middleware"
	"github.com/vaultpass/vaultpass-go/internal/model"
	"github.com/vaultpass/vaultpass-go/internal/service"
)

// VaultHandler handles HTTP requests for vault entry operations.
type VaultHandler struct {
	service *service.VaultService
}

// NewVaultHandler creates a new VaultHandler.
func NewVaultHandler(svc *service.VaultService) *VaultHandler {
	return &VaultHandler{service: svc}
}

// HandleCreateEntry handles POST /api/v1/vault requests.
func (h *VaultHandler) HandleCreateEntry(w http.ResponseWriter, r *http.Request) {
	userID, ok := middleware.UserIDFromContext(r.Context())
	if !ok {
		writeJSON(w, http.StatusUnauthorized, errorResponse("unauthorized"))
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 10<<20) // 10MB

	var req model.VaultEntryRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		if err.Error() == "http: request body too large" {
			writeJSON(w, http.StatusRequestEntityTooLarge, errorResponse("request body too large"))
			return
		}
		writeJSON(w, http.StatusBadRequest, errorResponse("invalid request body"))
		return
	}

	resp, err := h.service.CreateEntry(r.Context(), userID, req)
	if err != nil {
		switch {
		case errors.Is(err, service.ErrEntryIDRequired), errors.Is(err, service.ErrEncryptedDataRequired):
			writeJSON(w, http.StatusBadRequest, errorResponse(err.Error()))
		default:
			writeJSON(w, http.StatusInternalServerError, errorResponse("internal server error"))
		}
		return
	}

	writeJSON(w, http.StatusCreated, resp)
}

// HandleListEntries handles GET /api/v1/vault requests.
func (h *VaultHandler) HandleListEntries(w http.ResponseWriter, r *http.Request) {
	userID, ok := middleware.UserIDFromContext(r.Context())
	if !ok {
		writeJSON(w, http.StatusUnauthorized, errorResponse("unauthorized"))
		return
	}

	entries, err := h.service.ListEntries(r.Context(), userID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errorResponse("internal server error"))
		return
	}

	writeJSON(w, http.StatusOK, entries)
}

// HandleUpdateEntry handles PUT /api/v1/vault/{entry_id} requests.
func (h *VaultHandler) HandleUpdateEntry(w http.ResponseWriter, r *http.Request) {
	userID, ok := middleware.UserIDFromContext(r.Context())
	if !ok {
		writeJSON(w, http.StatusUnauthorized, errorResponse("unauthorized"))
		return
	}

	entryID := chi.URLParam(r, "entry_id")
	if entryID == "" || len(entryID) > 36 {
		writeJSON(w, http.StatusBadRequest, errorResponse("invalid entry id"))
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 10<<20) // 10MB

	var req model.VaultEntryRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		if err.Error() == "http: request body too large" {
			writeJSON(w, http.StatusRequestEntityTooLarge, errorResponse("request body too large"))
			return
		}
		writeJSON(w, http.StatusBadRequest, errorResponse("invalid request body"))
		return
	}

	resp, err := h.service.UpdateEntry(r.Context(), userID, entryID, req)
	if err != nil {
		switch {
		case errors.Is(err, service.ErrEncryptedDataRequired):
			writeJSON(w, http.StatusBadRequest, errorResponse(err.Error()))
		case errors.Is(err, service.ErrEntryNotFound):
			writeJSON(w, http.StatusNotFound, errorResponse(err.Error()))
		default:
			writeJSON(w, http.StatusInternalServerError, errorResponse("internal server error"))
		}
		return
	}

	writeJSON(w, http.StatusOK, resp)
}

// HandleDeleteEntry handles DELETE /api/v1/vault/{entry_id} requests.
func (h *VaultHandler) HandleDeleteEntry(w http.ResponseWriter, r *http.Request) {
	userID, ok := middleware.UserIDFromContext(r.Context())
	if !ok {
		writeJSON(w, http.StatusUnauthorized, errorResponse("unauthorized"))
		return
	}

	entryID := chi.URLParam(r, "entry_id")
	if entryID == "" || len(entryID) > 36 {
		writeJSON(w, http.StatusBadRequest, errorResponse("invalid entry id"))
		return
	}

	err := h.service.DeleteEntry(r.Context(), userID, entryID)
	if err != nil {
		switch {
		case errors.Is(err, service.ErrEntryNotFound):
			writeJSON(w, http.StatusNotFound, errorResponse(err.Error()))
		default:
			writeJSON(w, http.StatusInternalServerError, errorResponse("internal server error"))
		}
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// HandleSync handles POST /api/v1/vault/sync requests.
func (h *VaultHandler) HandleSync(w http.ResponseWriter, r *http.Request) {
	userID, ok := middleware.UserIDFromContext(r.Context())
	if !ok {
		writeJSON(w, http.StatusUnauthorized, errorResponse("unauthorized"))
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 10<<20) // 10MB

	var req model.SyncRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		if err.Error() == "http: request body too large" {
			writeJSON(w, http.StatusRequestEntityTooLarge, errorResponse("request body too large"))
			return
		}
		writeJSON(w, http.StatusBadRequest, errorResponse("invalid request body"))
		return
	}

	if len(req.Entries) > 1000 {
		writeJSON(w, http.StatusBadRequest, errorResponse("too many entries in sync request (max 1000)"))
		return
	}

	resp, err := h.service.Sync(r.Context(), userID, req)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errorResponse("internal server error"))
		return
	}

	writeJSON(w, http.StatusOK, resp)
}
