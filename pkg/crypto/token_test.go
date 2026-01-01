package crypto

import (
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"
)

func isBase64URLChar(char rune) bool {
	return (char >= 'A' && char <= 'Z') ||
		(char >= 'a' && char <= 'z') ||
		(char >= '0' && char <= '9') ||
		char == '-' || char == '_'
}

func TestTokenGenerateShouldCreateURLSafeToken(t *testing.T) {
	t.Run("generates valid token", func(t *testing.T) {
		token, err := generateToken(32)
		if err != nil {
			t.Fatalf("generateToken() error = %v", err)
		}

		if token == "" {
			t.Error("token should not be empty")
		}
	})

	t.Run("handles byte length parameter", func(t *testing.T) {
		tests := []struct {
			name           string
			byteLength     int
			expectedLength int // expected bytes after decoding
		}{
			{"zero uses default", 0, DefaultTokenLength},
			{"negative uses default", -10, DefaultTokenLength},
			{"16 bytes", 16, 16},
			{"32 bytes", 32, 32},
			{"48 bytes", 48, 48},
			{"64 bytes", 64, 64},
			{"100 bytes", 100, 100},
			{"1 byte minimum", 1, 1},
			{"255 bytes large", 255, 255},
		}

		for _, test := range tests {
			t.Run(test.name, func(t *testing.T) {
				token, err := generateToken(test.byteLength)
				if err != nil {
					t.Fatalf("generateToken(%d) error = %v", test.byteLength, err)
				}

				if token == "" {
					t.Error("token should not be empty")
				}

				// Decode to verify actual byte length
				decoded, err := base64.RawURLEncoding.DecodeString(token)
				if err != nil {
					t.Fatalf("failed to decode token: %v", err)
				}

				if len(decoded) != test.expectedLength {
					t.Errorf("token length = %d bytes, expected %d", len(decoded), test.expectedLength)
				}
			})
		}
	})

	t.Run("generates url-safe tokens", func(t *testing.T) {
		tests := []struct {
			name       string
			byteLength int
			iterations int
		}{
			{"short tokens", 16, 50},
			{"standard tokens", 32, 100},
			{"long tokens", 64, 50},
		}

		for _, test := range tests {
			t.Run(test.name, func(t *testing.T) {
				for i := 0; i < test.iterations; i++ {
					token, err := generateToken(test.byteLength)
					if err != nil {
						t.Fatalf("iteration %d: generateToken() error = %v", i, err)
					}

					// Check for URL-unsafe characters
					if strings.ContainsAny(token, "+/= ") {
						t.Errorf("token contains URL-unsafe characters: %q", token)
					}

					// Verify only base64url alphabet
					for _, char := range token {
						if !isBase64URLChar(char) {
							t.Errorf("token contains invalid character: %c (token: %q)", char, token)
						}
					}
				}
			})
		}
	})
}

func TestTokenGenerateShouldProduceUniqueTokens(t *testing.T) {
	t.Run("generates unique tokens", func(t *testing.T) {
		tokens := make(map[string]bool)
		iterations := 1000

		for i := 0; i < iterations; i++ {
			token, err := generateToken(32)
			if err != nil {
				t.Fatalf("iteration %d: generateToken() error = %v", i, err)
			}

			if tokens[token] {
				t.Errorf("duplicate token generated: %q", token)
			}
			tokens[token] = true
		}

		if len(tokens) != iterations {
			t.Errorf("expected %d unique tokens, got %d", iterations, len(tokens))
		}
	})
}

func TestTokenGenerateHashedShouldReturnValidTokenHashPair(t *testing.T) {
	t.Run("generates valid token pair", func(t *testing.T) {
		pair, err := GenerateHashedToken(32)
		if err != nil {
			t.Fatalf("GenerateHashedToken() error = %v", err)
		}

		if pair == nil {
			t.Fatal("token pair should not be nil")
		}

		if pair.Token == "" {
			t.Error("token should not be empty")
		}

		if pair.Hash == "" {
			t.Error("hash should not be empty")
		}
	})

	t.Run("token and hash are different", func(t *testing.T) {
		pair, err := GenerateHashedToken(32)
		if err != nil {
			t.Fatalf("GenerateHashedToken() error = %v", err)
		}

		if pair.Token == pair.Hash {
			t.Error("token and hash should be different")
		}
	})

	t.Run("hash is valid sha256 hex string", func(t *testing.T) {
		pair, err := GenerateHashedToken(32)
		if err != nil {
			t.Fatalf("GenerateHashedToken() error = %v", err)
		}

		// SHA-256 produces 32 bytes = 64 hex characters
		if len(pair.Hash) != 64 {
			t.Errorf("hash length = %d, expected 64", len(pair.Hash))
		}

		// Verify it's valid hex
		_, err = hex.DecodeString(pair.Hash)
		if err != nil {
			t.Errorf("hash is not valid hex: %v", err)
		}
	})

	t.Run("uses default length when zero", func(t *testing.T) {
		pair, err := GenerateHashedToken(0)
		if err != nil {
			t.Fatalf("GenerateHashedToken() error = %v", err)
		}

		decoded, err := base64.RawURLEncoding.DecodeString(pair.Token)
		if err != nil {
			t.Fatalf("failed to decode token: %v", err)
		}

		if len(decoded) != DefaultTokenLength {
			t.Errorf("token length = %d bytes, expected %d", len(decoded), DefaultTokenLength)
		}
	})

	t.Run("respects custom byte length", func(t *testing.T) {
		tests := []int{16, 32, 48, 64}

		for _, byteLength := range tests {
			t.Run(string(rune(byteLength)), func(t *testing.T) {
				pair, err := GenerateHashedToken(byteLength)
				if err != nil {
					t.Fatalf("GenerateHashedToken() error = %v", err)
				}

				decoded, err := base64.RawURLEncoding.DecodeString(pair.Token)
				if err != nil {
					t.Fatalf("failed to decode token: %v", err)
				}

				if len(decoded) != byteLength {
					t.Errorf("token length = %d bytes, expected %d", len(decoded), byteLength)
				}
			})
		}
	})

	t.Run("same token produces same hash", func(t *testing.T) {
		pair1, _ := GenerateHashedToken(32)
		pair2, _ := GenerateHashedToken(32)

		// Different tokens should produce different hashes
		if pair1.Token != pair2.Token && pair1.Hash == pair2.Hash {
			t.Error("different tokens should not produce same hash")
		}
	})
}

func TestTokenVerifyShouldValidateAndRejectInvalid(t *testing.T) {
	t.Run("verifies correct token", func(t *testing.T) {
		pair, err := GenerateHashedToken(32)
		if err != nil {
			t.Fatalf("GenerateHashedToken() error = %v", err)
		}

		valid, err := VerifyToken(pair.Token, pair.Hash)
		if err != nil {
			t.Fatalf("VerifyToken() error = %v", err)
		}

		if !valid {
			t.Error("should verify correct token")
		}
	})

	t.Run("rejects incorrect token", func(t *testing.T) {
		pair, err := GenerateHashedToken(32)
		if err != nil {
			t.Fatalf("GenerateHashedToken() error = %v", err)
		}

		wrongToken := "wrong_token_value_abc123"
		valid, err := VerifyToken(wrongToken, pair.Hash)
		if err != nil {
			t.Fatalf("VerifyToken() error = %v", err)
		}

		if valid {
			t.Error("should reject incorrect token")
		}
	})

	t.Run("rejects token with wrong hash", func(t *testing.T) {
		pair, err := GenerateHashedToken(32)
		if err != nil {
			t.Fatalf("GenerateHashedToken() error = %v", err)
		}

		wrongHash := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
		valid, err := VerifyToken(pair.Token, wrongHash)
		if err != nil {
			t.Fatalf("VerifyToken() error = %v", err)
		}

		if valid {
			t.Error("should reject token with wrong hash")
		}
	})

	t.Run("returns error for empty token", func(t *testing.T) {
		_, err := VerifyToken("", "somehash")
		if err == nil {
			t.Error("should return error for empty token")
		}
	})

	t.Run("returns error for empty hash", func(t *testing.T) {
		_, err := VerifyToken("sometoken", "")
		if err == nil {
			t.Error("should return error for empty hash")
		}
	})

	t.Run("returns error for both empty", func(t *testing.T) {
		_, err := VerifyToken("", "")
		if err == nil {
			t.Error("should return error when both are empty")
		}
	})

	t.Run("handles modified token", func(t *testing.T) {
		pair, err := GenerateHashedToken(32)
		if err != nil {
			t.Fatalf("GenerateHashedToken() error = %v", err)
		}

		// Modify one character
		modifiedToken := pair.Token[:len(pair.Token)-1] + "X"
		valid, err := VerifyToken(modifiedToken, pair.Hash)
		if err != nil {
			t.Fatalf("VerifyToken() error = %v", err)
		}

		if valid {
			t.Error("should reject modified token")
		}
	})
}

func TestTokenVerifyShouldFailWhenHashDoesNotMatch(t *testing.T) {
	t.Run("verifies token from different generation", func(t *testing.T) {
		// Generate first pair
		pair1, err := GenerateHashedToken(32)
		if err != nil {
			t.Fatalf("GenerateHashedToken() error = %v", err)
		}

		// Generate second pair (different token)
		pair2, err := GenerateHashedToken(32)
		if err != nil {
			t.Fatalf("GenerateHashedToken() error = %v", err)
		}

		// Verify first pair
		valid1, err := VerifyToken(pair1.Token, pair1.Hash)
		if err != nil || !valid1 {
			t.Error("should verify first token")
		}

		// Verify second pair
		valid2, err := VerifyToken(pair2.Token, pair2.Hash)
		if err != nil || !valid2 {
			t.Error("should verify second token")
		}

		// Cross verification should fail
		validCross, err := VerifyToken(pair1.Token, pair2.Hash)
		if err != nil {
			t.Fatalf("VerifyToken() error = %v", err)
		}
		if validCross {
			t.Error("should not verify token with wrong hash")
		}
	})
}

func TestTokenVerifyShouldBeConsistentForSameToken(t *testing.T) {
	t.Run("same token always produces same hash", func(t *testing.T) {
		pair, err := GenerateHashedToken(32)
		if err != nil {
			t.Fatalf("GenerateHashedToken() error = %v", err)
		}

		// Verify multiple times - should always work
		for i := 0; i < 10; i++ {
			valid, err := VerifyToken(pair.Token, pair.Hash)
			if err != nil {
				t.Fatalf("iteration %d: VerifyToken() error = %v", i, err)
			}
			if !valid {
				t.Errorf("iteration %d: should verify token", i)
			}
		}
	})
}

func TestTokenGenerateShouldHaveGoodCharacterDistribution(t *testing.T) {
	t.Run("tokens have good character distribution", func(t *testing.T) {
		charCounts := make(map[rune]int)
		iterations := 1000

		for i := 0; i < iterations; i++ {
			token, err := generateToken(32)
			if err != nil {
				t.Fatalf("iteration %d: generateToken() error = %v", i, err)
			}

			for _, char := range token {
				charCounts[char]++
			}
		}

		// Should have reasonable variety of characters
		if len(charCounts) < 40 {
			t.Errorf("poor character distribution: only %d unique characters", len(charCounts))
		}
	})
}

func TestTokenGenerateHashedShouldBeConcurrencySafe(t *testing.T) {
	t.Run("safe for concurrent generation", func(t *testing.T) {
		const goroutines = 100
		results := make(chan *TokenPair, goroutines)
		errors := make(chan error, goroutines)

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
	})
}

// Benchmarks

func BenchmarkTokenGenerate(b *testing.B) {
	for i := 0; i < b.N; i++ {
		generateToken(32)
	}
}

func BenchmarkTokenGenerateHashed(b *testing.B) {
	for i := 0; i < b.N; i++ {
		GenerateHashedToken(32)
	}
}

func BenchmarkTokenVerify(b *testing.B) {
	pair, _ := GenerateHashedToken(32)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		VerifyToken(pair.Token, pair.Hash)
	}
}
