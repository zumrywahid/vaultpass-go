package service

import (
	"testing"

	"github.com/vaultpass/vaultpass-go/internal/model"
)

func boolPtr(b bool) *bool { return &b }

func TestGenerate_Defaults(t *testing.T) {
	svc := NewGeneratorService()
	resp, err := svc.Generate(model.GenerateRequest{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Length != 16 {
		t.Errorf("expected length 16, got %d", resp.Length)
	}
	if len(resp.Password) != 16 {
		t.Errorf("expected password length 16, got %d", len(resp.Password))
	}
}

func TestGenerate_CustomOptions(t *testing.T) {
	svc := NewGeneratorService()
	resp, err := svc.Generate(model.GenerateRequest{
		Length:    32,
		Uppercase: boolPtr(true),
		Lowercase: boolPtr(true),
		Numbers:   boolPtr(false),
		Symbols:   boolPtr(false),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Length != 32 {
		t.Errorf("expected length 32, got %d", resp.Length)
	}
	for _, c := range resp.Password {
		if !((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')) {
			t.Errorf("unexpected character %q in password with only uppercase+lowercase", c)
		}
	}
}

func TestGenerate_LengthTooShort(t *testing.T) {
	svc := NewGeneratorService()
	_, err := svc.Generate(model.GenerateRequest{Length: 3})
	if err == nil {
		t.Fatal("expected error for length too short")
	}
}

func TestGenerate_LengthTooLong(t *testing.T) {
	svc := NewGeneratorService()
	_, err := svc.Generate(model.GenerateRequest{Length: 200})
	if err == nil {
		t.Fatal("expected error for length too long")
	}
}

func TestGenerate_NoCharacterTypes(t *testing.T) {
	svc := NewGeneratorService()
	_, err := svc.Generate(model.GenerateRequest{
		Length:    16,
		Uppercase: boolPtr(false),
		Lowercase: boolPtr(false),
		Numbers:   boolPtr(false),
		Symbols:   boolPtr(false),
	})
	if err == nil {
		t.Fatal("expected error when no character types selected")
	}
}
