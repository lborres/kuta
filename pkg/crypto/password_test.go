package crypto

import (
	"strings"
	"testing"
)

func TestArgon2_Hash(t *testing.T) {
	tests := []struct {
		name     string
		password string
		wantErr  bool
	}{
		{name: "success", password: "testPassword123", wantErr: false},
		{name: "empty password", password: "", wantErr: false},
		{name: "long password", password: strings.Repeat("a", 128), wantErr: false},
		{name: "unicode", password: "パスワード🔐", wantErr: false},
		{name: "special chars", password: "p@ssw0rd!#$%", wantErr: false},
		{name: "null byte", password: "pass\x00word", wantErr: false},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			// Arrange
			a := NewArgon2()

			// Act
			hash, err := a.Hash(test.password)

			// Assert
			if (err != nil) != test.wantErr {
				t.Fatalf("Hash() error = %v, wantErr %v", err, test.wantErr)
			}
			if !test.wantErr {
				if hash == "" {
					t.Error("Hash() returned empty hash")
				}
				// Format validation
				if !strings.HasPrefix(hash, "$argon2id$") {
					t.Error("Hash() should start with $argon2id$")
				}
				if !strings.Contains(hash, "$v=19$") {
					t.Error("Hash() should contain version 19")
				}
				if len(strings.Split(hash, "$")) != 6 {
					t.Error("Hash() should have 6 parts")
				}
			}
		})
	}
}

func TestArgon2_Hash_UniqueSalts(t *testing.T) {
	// Arrange
	a := NewArgon2()
	password := "samePassword"

	// Act
	hash1, _ := a.Hash(password)
	hash2, _ := a.Hash(password)

	// Assert
	if hash1 == hash2 {
		t.Error("Hash() should generate different hashes with unique salts")
	}
}

func TestArgon2_Verify(t *testing.T) {
	tests := []struct {
		name     string
		password string
		attempt  string
		wantOk   bool
	}{
		{name: "correct password", password: "correctPassword", attempt: "correctPassword", wantOk: true},
		{name: "wrong password", password: "correctPassword", attempt: "wrongPassword", wantOk: false},
		{name: "case sensitive", password: "correctPassword", attempt: "correctpassword", wantOk: false},
		{name: "extra character", password: "correctPassword", attempt: "correctPassword1", wantOk: false},
		{name: "single char difference", password: "thisIsAVeryLongPasswordToTestSingleCharDiff", attempt: "thisIsAVeryLongPasswordXoTestSingleCharDiff", wantOk: false},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			// Arrange
			a := NewArgon2()
			hash, _ := a.Hash(test.password)

			// Act
			ok, err := a.Verify(test.attempt, hash)

			// Assert
			if err != nil {
				t.Fatalf("Verify() error = %v", err)
			}
			if ok != test.wantOk {
				t.Errorf("Verify() = %v, want %v", ok, test.wantOk)
			}
		})
	}
}

func TestArgon2_Verify_InvalidHashes(t *testing.T) {
	tests := []struct {
		name string
		hash string
	}{
		{name: "empty", hash: ""},
		{name: "invalid format", hash: "invalid-hash"},
		{name: "too few parts", hash: "$argon2id$v=19$m=65536,t=3,p=2$salt"},
		{name: "unsupported algorithm", hash: "$argon2i$v=19$m=65536,t=3,p=2$salt$hash"},
		{name: "wrong algorithm", hash: "$bcrypt$v=19$m=65536,t=3,p=2$salt$hash"},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			// Arrange
			a := NewArgon2()

			// Act
			_, err := a.Verify("password", test.hash)

			// Assert
			if err == nil {
				t.Errorf("Verify() should return error for %s", test.name)
			}
		})
	}
}

func TestArgon2_Verify_AcrossInstances(t *testing.T) {
	tests := []struct {
		name     string
		hasherA  *Argon2
		hasherB  *Argon2
		password string
		wantErr  bool
	}{
		{
			name:     "default instances",
			hasherA:  NewArgon2(),
			hasherB:  NewArgon2(),
			password: "testPassword",
			wantErr:  false,
		},
		{
			name: "custom vs default",
			hasherA: &Argon2{
				Memory:      32 * 1024,
				Iterations:  2,
				Parallelism: 1,
				SaltLength:  8,
				KeyLength:   16,
			},
			hasherB:  NewArgon2(),
			password: "test",
			wantErr:  false,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			// Arrange
			hash, _ := test.hasherA.Hash(test.password)

			// Act
			ok, err := test.hasherB.Verify(test.password, hash)

			// Assert
			if (err != nil) != test.wantErr {
				t.Fatalf("Verify() error = %v, wantErr %v", err, test.wantErr)
			}
			if !test.wantErr && !ok {
				t.Error("Verify() should verify hash from different instance")
			}
		})
	}
}

func TestArgon2_Parameters(t *testing.T) {
	tests := []struct {
		name       string
		hasher     *Argon2
		paramName  string
		checkParam func(*Argon2, string) (interface{}, interface{})
	}{
		{
			name: "memory 32MB",
			hasher: &Argon2{
				Memory:      32 * 1024,
				Iterations:  3,
				Parallelism: 2,
				SaltLength:  16,
				KeyLength:   32,
			},
			paramName: "Memory",
			checkParam: func(a *Argon2, _ string) (interface{}, interface{}) {
				hash, _ := a.Hash("test")
				params, _, _, _ := decodeArgon2Hash(hash)
				return params.Memory, uint32(32 * 1024)
			},
		},
		{
			name: "iterations 5",
			hasher: &Argon2{
				Memory:      64 * 1024,
				Iterations:  5,
				Parallelism: 2,
				SaltLength:  16,
				KeyLength:   32,
			},
			paramName: "Iterations",
			checkParam: func(a *Argon2, _ string) (interface{}, interface{}) {
				hash, _ := a.Hash("test")
				params, _, _, _ := decodeArgon2Hash(hash)
				return params.Iterations, uint32(5)
			},
		},
		{
			name: "parallelism 4",
			hasher: &Argon2{
				Memory:      64 * 1024,
				Iterations:  3,
				Parallelism: 4,
				SaltLength:  16,
				KeyLength:   32,
			},
			paramName: "Parallelism",
			checkParam: func(a *Argon2, _ string) (interface{}, interface{}) {
				hash, _ := a.Hash("test")
				params, _, _, _ := decodeArgon2Hash(hash)
				return params.Parallelism, uint8(4)
			},
		},
		{
			name: "salt length 32",
			hasher: &Argon2{
				Memory:      64 * 1024,
				Iterations:  3,
				Parallelism: 2,
				SaltLength:  32,
				KeyLength:   32,
			},
			paramName: "SaltLength",
			checkParam: func(a *Argon2, _ string) (interface{}, interface{}) {
				hash, _ := a.Hash("test")
				_, salt, _, _ := decodeArgon2Hash(hash)
				return len(salt), 32
			},
		},
		{
			name: "key length 64",
			hasher: &Argon2{
				Memory:      64 * 1024,
				Iterations:  3,
				Parallelism: 2,
				SaltLength:  16,
				KeyLength:   64,
			},
			paramName: "KeyLength",
			checkParam: func(a *Argon2, _ string) (interface{}, interface{}) {
				hash, _ := a.Hash("test")
				_, _, hashBytes, _ := decodeArgon2Hash(hash)
				return len(hashBytes), 64
			},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			// Act
			actual, expected := test.checkParam(test.hasher, test.paramName)

			// Assert
			if actual != expected {
				t.Errorf("%s = %v, want %v", test.paramName, actual, expected)
			}
		})
	}
}

func TestArgon2_New_Defaults(t *testing.T) {
	// Arrange
	a := NewArgon2()

	tests := []struct {
		name     string
		actual   interface{}
		expected interface{}
	}{
		{name: "memory 64MB", actual: a.Memory, expected: uint32(64 * 1024)},
		{name: "iterations 3", actual: a.Iterations, expected: uint32(3)},
		{name: "parallelism 2", actual: a.Parallelism, expected: uint8(2)},
		{name: "salt length 16", actual: a.SaltLength, expected: uint32(16)},
		{name: "key length 32", actual: a.KeyLength, expected: uint32(32)},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			if test.actual != test.expected {
				t.Errorf("%s: got %v, want %v", test.name, test.actual, test.expected)
			}
		})
	}
}

func TestArgon2_Concurrent(t *testing.T) {
	// Arrange
	a := NewArgon2()
	const goroutines = 10
	errors := make(chan error, goroutines)

	// Act
	for i := 0; i < goroutines; i++ {
		i := i
		go func() {
			password := strings.Repeat("a", i+1)
			hash, err := a.Hash(password)
			if err != nil {
				errors <- err
				return
			}
			ok, err := a.Verify(password, hash)
			if err != nil {
				errors <- err
				return
			}
			if !ok {
				errors <- nil
				return
			}
			errors <- nil
		}()
	}

	// Assert
	for i := 0; i < goroutines; i++ {
		if err := <-errors; err != nil {
			t.Errorf("Concurrent operation failed: %v", err)
		}
	}
}

func FuzzArgon2_Hash(f *testing.F) {
	// Seed corpus with various password types
	f.Add("")                       // empty password
	f.Add("test")                   // simple password
	f.Add("testPassword123")        // alphanumeric
	f.Add("p@ssw0rd!#$%")           // special characters
	f.Add(strings.Repeat("a", 128)) // long password
	f.Add("パスワード🔐")                 // unicode
	f.Add("pass\x00word")           // null byte
	f.Add("\n\r\t")                 // whitespace
	f.Add("a\x00b\x00c")            // multiple nulls

	f.Fuzz(func(t *testing.T, password string) {
		// Arrange
		a := NewArgon2()

		// Act: Hash should never panic and always succeed
		hash, err := a.Hash(password)

		// Assert: Hash must succeed
		if err != nil {
			t.Fatalf("Hash() error = %v", err)
		}

		// Invariant 1: Hash is non-empty
		if hash == "" {
			t.Fatal("Hash() returned empty string")
		}

		// Invariant 2: Hash has correct Argon2id format
		if !strings.HasPrefix(hash, "$argon2id$") {
			t.Errorf("Hash() should start with $argon2id$, got: %q", hash[:20])
		}

		// Invariant 3: Verify the hash with correct password succeeds
		ok, err := a.Verify(password, hash)
		if err != nil {
			t.Fatalf("Verify() error = %v", err)
		}
		if !ok {
			t.Fatal("Verify() should return true for correct password")
		}
	})
}
