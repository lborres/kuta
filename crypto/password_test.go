package crypto

import (
	"fmt"
	"strings"
	"testing"
)

func setupArgon2(t *testing.T) *Argon2 {
	t.Helper()
	return NewArgon2()
}

func setupPasswordHash(t *testing.T, password string) (*Argon2, string) {
	t.Helper()
	a := NewArgon2()
	hash, err := a.Hash(password)
	if err != nil {
		t.Fatalf("Failed to setup hash: %v", err)
	}
	return a, hash
}

func TestArgon2Hash(t *testing.T) {
	t.Run("format validation", func(t *testing.T) {
		_, hash := setupPasswordHash(t, "testPassword123")

		tests := []struct {
			name  string
			check func(string) bool
			desc  string
		}{
			{
				name:  "has argon2id algorithm",
				check: func(h string) bool { return strings.HasPrefix(h, "$argon2id$") },
				desc:  "should start with $argon2id$",
			},
			{
				name:  "has correct version",
				check: func(h string) bool { return strings.Contains(h, "$v=19$") },
				desc:  "should contain version 19",
			},
			{
				name:  "has 6 parts",
				check: func(h string) bool { return len(strings.Split(h, "$")) == 6 },
				desc:  "should have 6 parts",
			},
		}

		for _, test := range tests {
			t.Run(test.name, func(t *testing.T) {
				if !test.check(hash) {
					t.Errorf("%s: %s", test.desc, hash)
				}
			})
		}
	})

	t.Run("generates unique salts", func(t *testing.T) {
		a := setupArgon2(t)
		password := "samePassword"

		hash1, _ := a.Hash(password)
		hash2, _ := a.Hash(password)

		if hash1 == hash2 {
			t.Error("Same password should generate different hashes (unique salts)")
		}
	})

	t.Run("handles edge cases", func(t *testing.T) {
		a := setupArgon2(t)

		tests := []struct {
			name     string
			password string
		}{
			{"empty password", ""},
			{"long password", strings.Repeat("a", 128)},
			{"unicode", "パスワード🔐"},
			{"special chars", "p@ssw0rd!#$%"},
		}

		for _, test := range tests {
			t.Run(test.name, func(t *testing.T) {
				_, err := a.Hash(test.password)
				if err != nil {
					t.Errorf("Hash() should handle %s, got error: %v", test.name, err)
				}
			})
		}
	})
}

func TestArgon2HashSecurityProperties(t *testing.T) {
	t.Run("uses constant time comparison in Verify", func(t *testing.T) {
		// This is implicit in the implementation, but we can verify behavior
		a := setupArgon2(t)
		password := "password"
		hash, _ := a.Hash(password)

		// Even with slightly different passwords, timing should be consistent
		// (This is more of a behavior test than a timing test)
		valid1, _ := a.Verify("passwor", hash)   // One char short
		valid2, _ := a.Verify("password1", hash) // One char extra

		if valid1 || valid2 {
			t.Error("Should reject both modified passwords")
		}
	})

	t.Run("salt is cryptographically random", func(t *testing.T) {
		a := setupArgon2(t)
		password := "test"

		// Generate multiple hashes and ensure salts are different
		hashes := make(map[string]bool)
		for i := 0; i < 100; i++ {
			hash, _ := a.Hash(password)
			if hashes[hash] {
				t.Error("Duplicate hash detected - salt may not be random")
			}
			hashes[hash] = true
		}
	})
}

func TestArgon2VerifyCrossInstanceCompatibility(t *testing.T) {
	t.Run("verifies hash created by different instance", func(t *testing.T) {
		// Arrange
		a1 := NewArgon2()
		password := "testPassword"
		hash, _ := a1.Hash(password)

		// Act - verify with completely new instance
		a2 := NewArgon2()
		actual, err := a2.Verify(password, hash)

		// Assert
		if err != nil {
			t.Fatalf("Verify() failed: %v", err)
		}
		if !actual {
			t.Error("Should verify hash from different Argon2 instance")
		}
	})

	t.Run("verifies hash with custom parameters", func(t *testing.T) {
		// Arrange - hash with custom params
		a1 := &Argon2{
			Memory:      32 * 1024,
			Iterations:  2,
			Parallelism: 1,
			SaltLength:  8,
			KeyLength:   16,
		}
		password := "test"
		hash, _ := a1.Hash(password)

		// Act - verify with default params (should extract from hash)
		a2 := NewArgon2()
		actual, err := a2.Verify(password, hash)

		// Assert
		if err != nil {
			t.Fatalf("Verify() failed: %v", err)
		}
		if !actual {
			t.Error("Should verify hash with different Argon2 parameters")
		}
	})
}

func TestArgon2HashCustomParameters(t *testing.T) {
	t.Run("respects custom memory setting", func(t *testing.T) {
		expected := uint32(32 * 1024)
		a := &Argon2{
			Memory:      expected,
			Iterations:  3,
			Parallelism: 2,
			SaltLength:  16,
			KeyLength:   32,
		}

		hash, _ := a.Hash("test")
		params, _, _, _ := decodeArgon2Hash(hash)

		actual := params.Memory
		if actual != expected {
			t.Errorf("Memory = %d, expected %d", actual, expected)
		}
	})

	t.Run("respects custom iterations setting", func(t *testing.T) {
		expected := uint32(5)
		a := &Argon2{
			Memory:      64 * 1024,
			Iterations:  expected,
			Parallelism: 2,
			SaltLength:  16,
			KeyLength:   32,
		}

		hash, _ := a.Hash("test")
		params, _, _, _ := decodeArgon2Hash(hash)

		actual := params.Iterations
		if actual != expected {
			t.Errorf("Iterations = %d, expected %d", actual, expected)
		}
	})

	t.Run("respects custom parallelism setting", func(t *testing.T) {
		// Arrange
		expected := uint8(4)
		a := &Argon2{
			Memory:      64 * 1024,
			Iterations:  3,
			Parallelism: expected,
			SaltLength:  16,
			KeyLength:   32,
		}

		// Act
		hash, _ := a.Hash("test")
		params, _, _, _ := decodeArgon2Hash(hash)

		// Assert
		actual := params.Parallelism
		if actual != expected {
			t.Errorf("Parallelism = %d, expected %d", actual, expected)
		}
	})

	t.Run("respects custom salt length", func(t *testing.T) {
		// Arrange
		expected := 32
		a := &Argon2{
			Memory:      64 * 1024,
			Iterations:  3,
			Parallelism: 2,
			SaltLength:  uint32(expected),
			KeyLength:   32,
		}

		// Act
		hash, _ := a.Hash("test")
		_, salt, _, _ := decodeArgon2Hash(hash)

		// Assert
		actual := len(salt)
		if actual != expected {
			t.Errorf("Salt length = %d, expected %d", actual, expected)
		}
	})

	t.Run("respects custom key length", func(t *testing.T) {
		// Arrange
		expected := 64
		a := &Argon2{
			Memory:      64 * 1024,
			Iterations:  3,
			Parallelism: 2,
			SaltLength:  16,
			KeyLength:   uint32(expected),
		}

		hash, _ := a.Hash("test")
		_, _, hashBytes, _ := decodeArgon2Hash(hash)

		actual := len(hashBytes)
		if actual != expected {
			t.Errorf("Key length = %d, expected %d", actual, expected)
		}
	})
}

func TestArgon2Verify(t *testing.T) {
	t.Run("password validation", func(t *testing.T) {
		password := "correctPassword"
		a, hash := setupPasswordHash(t, password)

		tests := []struct {
			name     string
			password string
			expected bool
		}{
			{"correct password", password, true},
			{"wrong password", "wrongPassword", false},
			{"case sensitive", "correctpassword", false},
			{"extra character", "correctPassword1", false},
		}

		for _, test := range tests {
			t.Run(test.name, func(t *testing.T) {
				valid, err := a.Verify(test.password, hash)
				if err != nil {
					t.Fatalf("Verify() error = %v", err)
				}
				if valid != test.expected {
					t.Errorf("Verify() = %v, expected %v", valid, test.expected)
				}
			})
		}
	})

	t.Run("invalid hash formats", func(t *testing.T) {
		a := setupArgon2(t)

		tests := []struct {
			name string
			hash string
		}{
			{"empty", ""},
			{"invalid format", "invalid-hash"},
			{"too few parts", "$argon2id$v=19$m=65536,t=3,p=2$salt"},
			{"unsupported algorithm", "$argon2i$v=19$m=65536,t=3,p=2$salt$hash"},
			{"wrong algorithm", "$bcrypt$v=19$m=65536,t=3,p=2$salt$hash"},
		}

		for _, test := range tests {
			t.Run(test.name, func(t *testing.T) {
				_, err := a.Verify("password", test.hash)
				if err == nil {
					t.Errorf("Verify() should return error for %s", test.name)
				}
			})
		}
	})
}

func TestArgon2VerifyEdgeCases(t *testing.T) {
	t.Run("handles very long passwords", func(t *testing.T) {
		// Arrange
		a := setupArgon2(t)
		longPassword := strings.Repeat("a", 1000) // 1000 characters
		hash, _ := a.Hash(longPassword)

		// Act
		actual, err := a.Verify(longPassword, hash)

		// Assert
		if err != nil {
			t.Fatalf("Verify() failed: %v", err)
		}
		if !actual {
			t.Error("Should verify very long passwords")
		}
	})

	t.Run("rejects password with single character difference", func(t *testing.T) {
		// Arrange
		a := setupArgon2(t)
		password := "thisIsAVeryLongPasswordToTestSingleCharDiff"
		hash, _ := a.Hash(password)

		// Act - change single character in middle
		wrongPassword := "thisIsAVeryLongPasswordXoTestSingleCharDiff"
		actual, err := a.Verify(wrongPassword, hash)

		// Assert
		if err != nil {
			t.Fatalf("Verify() failed: %v", err)
		}
		if actual {
			t.Error("Should reject password with single character difference")
		}
	})

	t.Run("handles null bytes in password", func(t *testing.T) {
		// Arrange
		a := setupArgon2(t)
		password := "pass\x00word" // Contains null byte
		hash, _ := a.Hash(password)

		// Act
		actual, err := a.Verify(password, hash)

		// Assert
		if err != nil {
			t.Fatalf("Verify() failed: %v", err)
		}
		if !actual {
			t.Error("Should handle null bytes in password")
		}
	})
}

func TestArgon2DecodeHash(t *testing.T) {
	_, hash := setupPasswordHash(t, "test")
	params, salt, hashBytes, err := decodeArgon2Hash(hash)
	if err != nil {
		t.Fatalf("decodeArgon2Hash() failed: %v", err)
	}

	tests := []struct {
		name     string
		check    func() bool
		expected interface{}
		actual   interface{}
	}{
		{
			name:     "extracts memory parameter",
			check:    func() bool { return params.Memory == 64*1024 },
			expected: 64 * 1024,
			actual:   params.Memory,
		},
		{
			name:     "extracts iterations",
			check:    func() bool { return params.Iterations == 3 },
			expected: 3,
			actual:   params.Iterations,
		},
		{
			name:     "extracts parallelism",
			check:    func() bool { return params.Parallelism == 2 },
			expected: 2,
			actual:   params.Parallelism,
		},
		{
			name:     "extracts salt length",
			check:    func() bool { return len(salt) == 16 },
			expected: 16,
			actual:   len(salt),
		},
		{
			name:     "extracts hash length",
			check:    func() bool { return len(hashBytes) == 32 },
			expected: 32,
			actual:   len(hashBytes),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if !test.check() {
				t.Errorf("%s: actual %v, expected %v", test.name, test.actual, test.expected)
			}
		})
	}
}

func TestArgon2DecodeHashErrorCases(t *testing.T) {
	tests := []struct {
		name          string
		hash          string
		expectedError string
	}{
		{
			name:          "invalid version format",
			hash:          "$argon2id$v=abc$m=65536,t=3,p=2$salt$hash",
			expectedError: "invalid version",
		},
		{
			name:          "invalid memory parameter",
			hash:          "$argon2id$v=19$m=abc,t=3,p=2$salt$hash",
			expectedError: "invalid memory parameter",
		},
		{
			name:          "invalid iterations parameter",
			hash:          "$argon2id$v=19$m=65536,t=abc,p=2$salt$hash",
			expectedError: "invalid iterations parameter",
		},
		{
			name:          "invalid parallelism parameter",
			hash:          "$argon2id$v=19$m=65536,t=3,p=abc$salt$hash",
			expectedError: "invalid parallelism parameter",
		},
		{
			name:          "invalid salt encoding",
			hash:          "$argon2id$v=19$m=65536,t=3,p=2$not-base64!@#$validhash",
			expectedError: "invalid salt encoding",
		},
		{
			name:          "invalid hash encoding",
			hash:          "$argon2id$v=19$m=65536,t=3,p=2$dmFsaWRzYWx0$not-base64!@#",
			expectedError: "invalid hash encoding",
		},
		{
			name:          "wrong parameter count",
			hash:          "$argon2id$v=19$m=65536,t=3$salt$hash",
			expectedError: "invalid parameters format",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, _, _, err := decodeArgon2Hash(test.hash)
			if err == nil {
				t.Errorf("Should return error for %s", test.name)
			}
			if !strings.Contains(err.Error(), test.expectedError) {
				t.Errorf("Expected error containing %q, got %q", test.expectedError, err.Error())
			}
		})
	}
}

func TestArgon2New(t *testing.T) {
	a := setupArgon2(t)

	tests := []struct {
		name     string
		actual   interface{}
		expected interface{}
	}{
		{"memory is 64MB", a.Memory, uint32(64 * 1024)},
		{"iterations is 3", a.Iterations, uint32(3)},
		{"parallelism is 2", a.Parallelism, uint8(2)},
		{"salt length is 16", a.SaltLength, uint32(16)},
		{"key length is 32", a.KeyLength, uint32(32)},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if test.actual != test.expected {
				t.Errorf("%s: got %v, expected %v", test.name, test.actual, test.expected)
			}
		})
	}
}

func TestArgon2ConcurrentUsage(t *testing.T) {
	t.Run("handles concurrent hashing", func(t *testing.T) {
		a := setupArgon2(t)
		const goroutines = 10
		errors := make(chan error, goroutines)

		for i := 0; i < goroutines; i++ {
			go func(n int) {
				password := strings.Repeat("a", n+1)
				hash, err := a.Hash(password)
				if err != nil {
					errors <- err
					return
				}
				valid, err := a.Verify(password, hash)
				if err != nil {
					errors <- err
					return
				}
				if !valid {
					errors <- fmt.Errorf("verification failed for goroutine %d", n)
					return
				}
				errors <- nil
			}(i)
		}

		for i := 0; i < goroutines; i++ {
			if err := <-errors; err != nil {
				t.Errorf("Concurrent operation failed: %v", err)
			}
		}
	})
}
