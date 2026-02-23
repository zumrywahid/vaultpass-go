package handler

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/vaultpass/vaultpass-go/internal/crypto"
	"github.com/vaultpass/vaultpass-go/internal/model"
	"github.com/vaultpass/vaultpass-go/internal/service"
)

// GeneratorHandler handles HTTP requests for password generation.
type GeneratorHandler struct {
	service *service.GeneratorService
}

// NewGeneratorHandler creates a new GeneratorHandler.
func NewGeneratorHandler(svc *service.GeneratorService) *GeneratorHandler {
	return &GeneratorHandler{service: svc}
}

// HandleGenerate handles POST /api/v1/generate requests.
func (h *GeneratorHandler) HandleGenerate(w http.ResponseWriter, r *http.Request) {
	var req model.GenerateRequest
	if r.Body != nil {
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1MB
		defer r.Body.Close()
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			if err.Error() == "http: request body too large" {
				writeJSON(w, http.StatusRequestEntityTooLarge, errorResponse("request body too large"))
				return
			}
			writeJSON(w, http.StatusBadRequest, errorResponse("invalid request body"))
			return
		}
	}

	resp, err := h.service.Generate(req)
	if err != nil {
		if isValidationError(err) {
			writeJSON(w, http.StatusBadRequest, errorResponse(err.Error()))
			return
		}
		writeJSON(w, http.StatusInternalServerError, errorResponse("internal server error"))
		return
	}

	writeJSON(w, http.StatusOK, resp)
}

func isValidationError(err error) bool {
	return errors.Is(err, crypto.ErrLengthTooShort) ||
		errors.Is(err, crypto.ErrLengthTooLong) ||
		errors.Is(err, crypto.ErrNoCharacterTypes) ||
		errors.Is(err, crypto.ErrLengthInsufficient)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func errorResponse(msg string) map[string]string {
	return map[string]string{"error": msg}
}
