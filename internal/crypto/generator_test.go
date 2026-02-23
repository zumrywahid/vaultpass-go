package crypto

import (
	"strings"
	"testing"
)

func TestGenerate(t *testing.T) {
	tests := []struct {
		name    string
		opts    GeneratorOptions
		wantErr error
	}{
		{
			name:    "default options",
			opts:    DefaultOptions(),
			wantErr: nil,
		},
		{
			name: "all options enabled",
			opts: GeneratorOptions{
				Length: 32, Uppercase: true, Lowercase: true, Numbers: true, Symbols: true,
			},
			wantErr: nil,
		},
		{
			name: "uppercase only",
			opts: GeneratorOptions{
				Length: 16, Uppercase: true,
			},
			wantErr: nil,
		},
		{
			name: "lowercase only",
			opts: GeneratorOptions{
				Length: 16, Lowercase: true,
			},
			wantErr: nil,
		},
		{
			name: "numbers only",
			opts: GeneratorOptions{
				Length: 16, Numbers: true,
			},
			wantErr: nil,
		},
		{
			name: "symbols only",
			opts: GeneratorOptions{
				Length: 16, Symbols: true,
			},
			wantErr: nil,
		},
		{
			name: "minimum length",
			opts: GeneratorOptions{
				Length: MinLength, Uppercase: true, Lowercase: true, Numbers: true, Symbols: true,
			},
			wantErr: nil,
		},
		{
			name: "maximum length",
			opts: GeneratorOptions{
				Length: MaxLength, Uppercase: true, Lowercase: true,
			},
			wantErr: nil,
		},
		{
			name: "length too short",
			opts: GeneratorOptions{
				Length: 4, Uppercase: true, Lowercase: true,
			},
			wantErr: ErrLengthTooShort,
		},
		{
			name: "length too long",
			opts: GeneratorOptions{
				Length: 200, Uppercase: true,
			},
			wantErr: ErrLengthTooLong,
		},
		{
			name: "no character types selected",
			opts: GeneratorOptions{
				Length: 16,
			},
			wantErr: ErrNoCharacterTypes,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := Generate(tt.opts)

			if tt.wantErr != nil {
				if err != tt.wantErr {
					t.Errorf("Generate() error = %v, want %v", err, tt.wantErr)
				}
				if result != "" {
					t.Error("Generate() should return empty string on error")
				}
				return
			}

			if err != nil {
				t.Fatalf("Generate() unexpected error: %v", err)
			}
			if len(result) != tt.opts.Length {
				t.Errorf("Generate() length = %d, want %d", len(result), tt.opts.Length)
			}
		})
	}
}

func TestGenerateContainsRequiredTypes(t *testing.T) {
	opts := GeneratorOptions{
		Length:    16,
		Uppercase: true,
		Lowercase: true,
		Numbers:   true,
		Symbols:   true,
	}

	// Run multiple times to reduce flakiness from randomness.
	for i := 0; i < 50; i++ {
		password, err := Generate(opts)
		if err != nil {
			t.Fatalf("Generate() unexpected error: %v", err)
		}

		if !strings.ContainsAny(password, uppercaseChars) {
			t.Errorf("password %q missing uppercase character", password)
		}
		if !strings.ContainsAny(password, lowercaseChars) {
			t.Errorf("password %q missing lowercase character", password)
		}
		if !strings.ContainsAny(password, numberChars) {
			t.Errorf("password %q missing number character", password)
		}
		if !strings.ContainsAny(password, symbolChars) {
			t.Errorf("password %q missing symbol character", password)
		}
	}
}

func TestGenerateSingleTypeContainsOnlyThatType(t *testing.T) {
	tests := []struct {
		name    string
		opts    GeneratorOptions
		charset string
	}{
		{
			name:    "uppercase only",
			opts:    GeneratorOptions{Length: 32, Uppercase: true},
			charset: uppercaseChars,
		},
		{
			name:    "lowercase only",
			opts:    GeneratorOptions{Length: 32, Lowercase: true},
			charset: lowercaseChars,
		},
		{
			name:    "numbers only",
			opts:    GeneratorOptions{Length: 32, Numbers: true},
			charset: numberChars,
		},
		{
			name:    "symbols only",
			opts:    GeneratorOptions{Length: 32, Symbols: true},
			charset: symbolChars,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			password, err := Generate(tt.opts)
			if err != nil {
				t.Fatalf("Generate() unexpected error: %v", err)
			}
			for _, ch := range password {
				if !strings.ContainsRune(tt.charset, ch) {
					t.Errorf("password contains unexpected character %q (not in %q)", string(ch), tt.charset)
				}
			}
		})
	}
}

func TestGenerateProducesUniquePasswords(t *testing.T) {
	opts := DefaultOptions()
	seen := make(map[string]bool)

	for i := 0; i < 100; i++ {
		password, err := Generate(opts)
		if err != nil {
			t.Fatalf("Generate() unexpected error: %v", err)
		}
		if seen[password] {
			t.Errorf("duplicate password generated: %q", password)
		}
		seen[password] = true
	}
}
