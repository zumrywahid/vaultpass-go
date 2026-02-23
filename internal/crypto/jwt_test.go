package crypto

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestGenerateToken(t *testing.T) {
	token, err := GenerateToken(42, "test-secret", time.Hour)
	if err != nil {
		t.Fatalf("GenerateToken() unexpected error: %v", err)
	}
	if token == "" {
		t.Fatal("GenerateToken() returned empty string")
	}
}

func TestValidateTokenValid(t *testing.T) {
	secret := "test-secret"
	userID := int64(42)

	token, err := GenerateToken(userID, secret, time.Hour)
	if err != nil {
		t.Fatalf("GenerateToken() unexpected error: %v", err)
	}

	claims, err := ValidateToken(token, secret)
	if err != nil {
		t.Fatalf("ValidateToken() unexpected error: %v", err)
	}
	if claims.UserID != userID {
		t.Errorf("ValidateToken() UserID = %d, want %d", claims.UserID, userID)
	}
}

func TestValidateTokenInvalid(t *testing.T) {
	_, err := ValidateToken("not-a-valid-token", "test-secret")
	if err == nil {
		t.Error("ValidateToken() expected error for invalid token")
	}
}

func TestValidateTokenWrongSecret(t *testing.T) {
	token, err := GenerateToken(42, "correct-secret", time.Hour)
	if err != nil {
		t.Fatalf("GenerateToken() unexpected error: %v", err)
	}

	_, err = ValidateToken(token, "wrong-secret")
	if err == nil {
		t.Error("ValidateToken() expected error for wrong secret")
	}
}

func TestValidateTokenExpired(t *testing.T) {
	token, err := GenerateToken(42, "test-secret", time.Millisecond)
	if err != nil {
		t.Fatalf("GenerateToken() unexpected error: %v", err)
	}

	time.Sleep(10 * time.Millisecond)

	_, err = ValidateToken(token, "test-secret")
	if err == nil {
		t.Error("ValidateToken() expected error for expired token")
	}
}

func TestValidateTokenWrongIssuer(t *testing.T) {
	secret := "test-secret"

	// Create a token with a wrong issuer
	claims := Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "wrong-issuer",
			Audience:  jwt.ClaimStrings{"vaultpass-api"},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
		UserID: 42,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(secret))
	if err != nil {
		t.Fatalf("SignedString() unexpected error: %v", err)
	}

	_, err = ValidateToken(tokenString, secret)
	if err == nil {
		t.Error("ValidateToken() expected error for wrong issuer")
	}
}

func TestValidateTokenWrongAudience(t *testing.T) {
	secret := "test-secret"

	// Create a token with a wrong audience
	claims := Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "vaultpass",
			Audience:  jwt.ClaimStrings{"wrong-audience"},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
		UserID: 42,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(secret))
	if err != nil {
		t.Fatalf("SignedString() unexpected error: %v", err)
	}

	_, err = ValidateToken(tokenString, secret)
	if err == nil {
		t.Error("ValidateToken() expected error for wrong audience")
	}
}
