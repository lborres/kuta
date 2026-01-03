package crypto

import (
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"
)

func TestGenerateToken_CreateToken(t *testing.T) {
	tests := []struct {
		name           string
		byteLength     int
		expectedLength int
	}{
		{name: "zero uses default", byteLength: 0, expectedLength: DefaultTokenLength},
		{name: "negative uses default", byteLength: -10, expectedLength: DefaultTokenLength},
		{name: "16 bytes", byteLength: 16, expectedLength: 16},
		{name: "32 bytes", byteLength: 32, expectedLength: 32},
		{name: "48 bytes", byteLength: 48, expectedLength: 48},
		{name: "64 bytes", byteLength: 64, expectedLength: 64},
		{name: "1 byte minimum", byteLength: 1, expectedLength: 1},
		{name: "255 bytes large", byteLength: 255, expectedLength: 255},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			// Act
			token, err := generateToken(test.byteLength)

			// Assert
			if err != nil {
				t.Fatalf("generateToken() error = %v", err)
			}
			if token == "" {
				t.Error("generateToken() returned empty token")
			}
			// Decode to verify byte length
			decoded, err := base64.RawURLEncoding.DecodeString(token)
			if err != nil {
				t.Fatalf("failed to decode token: %v", err)
			}
			if len(decoded) != test.expectedLength {
				t.Errorf("token length = %d bytes, want %d", len(decoded), test.expectedLength)
			}
			// Verify URL-safe characters
			if strings.ContainsAny(token, "+/= ") {
				t.Errorf("token contains URL-unsafe characters: %q", token)
			}
		})
	}
}

func TestGenerateToken_Unique(t *testing.T) {
	// Arrange
	tokens := make(map[string]bool)
	iterations := 1000

	// Act
	for i := 0; i < iterations; i++ {
		token, err := generateToken(32)
		if err != nil {
			t.Fatalf("iteration %d: generateToken() error = %v", i, err)
		}
		if tokens[token] {
			t.Fatalf("duplicate token generated: %q", token)
		}
		tokens[token] = true
	}

	// Assert
	if len(tokens) != iterations {
		t.Errorf("expected %d unique tokens, got %d", iterations, len(tokens))
	}
}

func TestGenerateToken_CharacterDistribution(t *testing.T) {
	// Arrange
	charCounts := make(map[rune]int)
	iterations := 1000

	// Act
	for i := 0; i < iterations; i++ {
		token, err := generateToken(32)
		if err != nil {
			t.Fatalf("iteration %d: generateToken() error = %v", i, err)
		}
		for _, char := range token {
			charCounts[char]++
		}
	}

	// Assert
	if len(charCounts) < 40 {
		t.Errorf("poor character distribution: only %d unique characters", len(charCounts))
	}
}

func TestGenerateHashedToken_CreatePair(t *testing.T) {
	tests := []struct {
		name       string
		byteLength int
		wantErr    bool
	}{
		{name: "default length", byteLength: 0, wantErr: false},
		{name: "16 bytes", byteLength: 16, wantErr: false},
		{name: "32 bytes", byteLength: 32, wantErr: false},
		{name: "64 bytes", byteLength: 64, wantErr: false},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			// Act
			pair, err := GenerateHashedToken(test.byteLength)

			// Assert
			if (err != nil) != test.wantErr {
				t.Fatalf("GenerateHashedToken() error = %v, wantErr %v", err, test.wantErr)
			}
			if !test.wantErr {
				if pair == nil {
					t.Fatal("GenerateHashedToken() returned nil")
				}
				if pair.Token == "" {
					t.Error("GenerateHashedToken() token is empty")
				}
				if pair.Hash == "" {
					t.Error("GenerateHashedToken() hash is empty")
				}
				if pair.Token == pair.Hash {
					t.Error("GenerateHashedToken() token and hash should differ")
				}
				// Verify hash is valid SHA256
				if len(pair.Hash) != 64 {
					t.Errorf("hash length = %d, want 64 (SHA256)", len(pair.Hash))
				}
				if _, err := hex.DecodeString(pair.Hash); err != nil {
					t.Errorf("hash is not valid hex: %v", err)
				}
			}
		})
	}
}

func TestGenerateHashedToken_Unique(t *testing.T) {
	// Arrange
	const iterations = 100
	pairs := make([]TokenPair, iterations)

	// Act
	for i := 0; i < iterations; i++ {
		pair, err := GenerateHashedToken(32)
		if err != nil {
			t.Fatalf("iteration %d: GenerateHashedToken() error = %v", i, err)
		}
		pairs[i] = *pair
	}

	// Assert
	tokens := make(map[string]bool)
	hashes := make(map[string]bool)
	for i, pair := range pairs {
		if tokens[pair.Token] {
			t.Errorf("iteration %d: duplicate token", i)
		}
		if hashes[pair.Hash] {
			t.Errorf("iteration %d: duplicate hash", i)
		}
		tokens[pair.Token] = true
		hashes[pair.Hash] = true
	}
}

func TestGenerateHashedToken_Concurrent(t *testing.T) {
	// Arrange
	const goroutines = 100
	results := make(chan *TokenPair, goroutines)
	errors := make(chan error, goroutines)

	// Act
	for i := 0; i < goroutines; i++ {
		go func() {
			pair, err := GenerateHashedToken(32)
			if err != nil {
				errors <- err
				return
			}
			results <- pair
			errors <- nil
		}()
	}

	// Assert
	seen := make(map[string]bool)
	for i := 0; i < goroutines; i++ {
		if err := <-errors; err != nil {
			t.Fatalf("concurrent generation failed: %v", err)
		}
	}
	close(results)
	for pair := range results {
		if seen[pair.Token] {
			t.Errorf("duplicate token in concurrent generation: %q", pair.Token)
		}
		seen[pair.Token] = true
	}
	if len(seen) != goroutines {
		t.Errorf("expected %d unique tokens, got %d", goroutines, len(seen))
	}
}

func TestVerifyToken_ValidateToken(t *testing.T) {
	tests := []struct {
		name    string
		setup   func() (token, hash string)
		token   string
		hash    string
		wantErr bool
		wantOk  bool
	}{
		{
			name: "correct token",
			setup: func() (string, string) {
				pair, _ := GenerateHashedToken(32)
				return pair.Token, pair.Hash
			},
			wantErr: false,
			wantOk:  true,
		},
		{
			name: "wrong token",
			setup: func() (string, string) {
				pair, _ := GenerateHashedToken(32)
				return "wrong_token_value", pair.Hash
			},
			wantErr: false,
			wantOk:  false,
		},
		{
			name: "wrong hash",
			setup: func() (string, string) {
				pair, _ := GenerateHashedToken(32)
				return pair.Token, "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
			},
			wantErr: false,
			wantOk:  false,
		},
		{
			name:    "empty token",
			token:   "",
			hash:    "somehash",
			wantErr: true,
			wantOk:  false,
		},
		{
			name:    "empty hash",
			token:   "sometoken",
			hash:    "",
			wantErr: true,
			wantOk:  false,
		},
		{
			name: "modified token",
			setup: func() (string, string) {
				pair, _ := GenerateHashedToken(32)
				modifiedToken := pair.Token[:len(pair.Token)-1] + "X"
				return modifiedToken, pair.Hash
			},
			wantErr: false,
			wantOk:  false,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			// Arrange
			token, hash := test.token, test.hash
			if test.setup != nil {
				token, hash = test.setup()
			}

			// Act
			ok, err := VerifyToken(token, hash)

			// Assert
			if (err != nil) != test.wantErr {
				t.Fatalf("VerifyToken() error = %v, wantErr %v", err, test.wantErr)
			}
			if !test.wantErr && ok != test.wantOk {
				t.Errorf("VerifyToken() = %v, want %v", ok, test.wantOk)
			}
		})
	}
}

func TestVerifyToken_Consistency(t *testing.T) {
	// Arrange
	pair, _ := GenerateHashedToken(32)

	// Act & Assert
	for i := 0; i < 10; i++ {
		ok, err := VerifyToken(pair.Token, pair.Hash)
		if err != nil {
			t.Fatalf("iteration %d: VerifyToken() error = %v", i, err)
		}
		if !ok {
			t.Errorf("iteration %d: VerifyToken() should verify token", i)
		}
	}
}
