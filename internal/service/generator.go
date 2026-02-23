package service

import (
	"github.com/vaultpass/vaultpass-go/internal/crypto"
	"github.com/vaultpass/vaultpass-go/internal/model"
)

// GeneratorService handles password generation business logic.
type GeneratorService struct{}

// NewGeneratorService creates a new GeneratorService.
func NewGeneratorService() *GeneratorService {
	return &GeneratorService{}
}

// Generate produces a password based on the given request.
func (s *GeneratorService) Generate(req model.GenerateRequest) (model.GenerateResponse, error) {
	opts := crypto.GeneratorOptions{
		Length:    req.Length,
		Uppercase: boolOrDefault(req.Uppercase, true),
		Lowercase: boolOrDefault(req.Lowercase, true),
		Numbers:   boolOrDefault(req.Numbers, true),
		Symbols:   boolOrDefault(req.Symbols, true),
	}

	if opts.Length == 0 {
		opts.Length = 16
	}

	password, err := crypto.Generate(opts)
	if err != nil {
		return model.GenerateResponse{}, err
	}

	return model.GenerateResponse{
		Password: password,
		Length:   len(password),
	}, nil
}

// boolOrDefault returns the dereferenced pointer value, or the fallback if nil.
func boolOrDefault(p *bool, fallback bool) bool {
	if p == nil {
		return fallback
	}
	return *p
}
