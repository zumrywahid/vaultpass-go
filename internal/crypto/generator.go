package crypto

import (
	"crypto/rand"
	"errors"
	"math/big"
)

const (
	uppercaseChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	lowercaseChars = "abcdefghijklmnopqrstuvwxyz"
	numberChars    = "0123456789"
	symbolChars    = "!@#$%^&*()_+-=[]{}|;:,.<>?"

	MinLength = 8
	MaxLength = 128
)

var (
	ErrLengthTooShort    = errors.New("password length must be at least 8")
	ErrLengthTooLong     = errors.New("password length must be at most 128")
	ErrNoCharacterTypes  = errors.New("at least one character type must be selected")
	ErrLengthInsufficient = errors.New("password length must be at least equal to the number of selected character types")
)

// GeneratorOptions configures the password generator.
type GeneratorOptions struct {
	Length    int
	Uppercase bool
	Lowercase bool
	Numbers   bool
	Symbols   bool
}

// DefaultOptions returns sensible defaults: 16 characters with all types enabled.
func DefaultOptions() GeneratorOptions {
	return GeneratorOptions{
		Length:    16,
		Uppercase: true,
		Lowercase: true,
		Numbers:   true,
		Symbols:   true,
	}
}

// Generate creates a cryptographically secure random password based on the given options.
func Generate(opts GeneratorOptions) (string, error) {
	if opts.Length < MinLength {
		return "", ErrLengthTooShort
	}
	if opts.Length > MaxLength {
		return "", ErrLengthTooLong
	}

	// Build the character pool and collect required sets.
	var pool string
	var requiredSets []string

	if opts.Uppercase {
		pool += uppercaseChars
		requiredSets = append(requiredSets, uppercaseChars)
	}
	if opts.Lowercase {
		pool += lowercaseChars
		requiredSets = append(requiredSets, lowercaseChars)
	}
	if opts.Numbers {
		pool += numberChars
		requiredSets = append(requiredSets, numberChars)
	}
	if opts.Symbols {
		pool += symbolChars
		requiredSets = append(requiredSets, symbolChars)
	}

	if len(requiredSets) == 0 {
		return "", ErrNoCharacterTypes
	}
	if opts.Length < len(requiredSets) {
		return "", ErrLengthInsufficient
	}

	result := make([]byte, opts.Length)

	// Guarantee at least one character from each selected type.
	for i, charset := range requiredSets {
		ch, err := randChar(charset)
		if err != nil {
			return "", err
		}
		result[i] = ch
	}

	// Fill the remaining positions from the full pool.
	for i := len(requiredSets); i < opts.Length; i++ {
		ch, err := randChar(pool)
		if err != nil {
			return "", err
		}
		result[i] = ch
	}

	// Securely shuffle using Fisher-Yates with crypto/rand.
	if err := secureShuffle(result); err != nil {
		return "", err
	}

	return string(result), nil
}

// randChar picks a random character from charset using crypto/rand.
func randChar(charset string) (byte, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
	if err != nil {
		return 0, err
	}
	return charset[n.Int64()], nil
}

// secureShuffle performs a Fisher-Yates shuffle using crypto/rand.
func secureShuffle(data []byte) error {
	for i := len(data) - 1; i > 0; i-- {
		j, err := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
		if err != nil {
			return err
		}
		data[i], data[j.Int64()] = data[j.Int64()], data[i]
	}
	return nil
}
