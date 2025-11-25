package crypto

import (
	"fmt"
	"strings"
	"testing"
)

func TestNanoIDConstructor(t *testing.T) {
	tests := []struct {
		name          string
		alphabet      string
		expectedErr   bool
		expectedNil   bool
		checkAlphabet bool
	}{
		{
			name:          "creates generator with valid alphabet",
			alphabet:      "ABCD",
			expectedErr:   false,
			expectedNil:   false,
			checkAlphabet: true,
		},
		{
			name:        "rejects empty alphabet",
			alphabet:    "",
			expectedErr: true,
			expectedNil: true,
		},
		{
			name:        "rejects alphabet larger than 255 characters",
			alphabet:    strings.Repeat("a", 256),
			expectedErr: true,
			expectedNil: true,
		},
		{
			name:        "accepts alphabet with 255 characters",
			alphabet:    strings.Repeat("a", 255),
			expectedErr: false,
			expectedNil: false,
		},
		{
			name:          "accepts small alphabet",
			alphabet:      "AB",
			expectedErr:   false,
			expectedNil:   false,
			checkAlphabet: true,
		},
		{
			name:        "rejects alphabet with 300 characters",
			alphabet:    strings.Repeat("x", 300),
			expectedErr: true,
			expectedNil: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			nanoid, err := NewCustomNanoID(test.alphabet)

			// Check error expectation
			if (err != nil) != test.expectedErr {
				t.Errorf("NewNanoIDGen() error = %v, expectedErr = %v", err, test.expectedErr)
			}

			// Check nil generator expectation
			if (nanoid == nil) != test.expectedNil {
				t.Errorf("NewNanoIDGen() gen = %v, expectedNil = %v", nanoid, test.expectedNil)
			}

			// Check alphabet is set correctly (only for valid cases)
			if test.checkAlphabet && nanoid != nil && nanoid.alphabet != test.alphabet {
				t.Errorf("alphabet = %q, want %q", nanoid.alphabet, test.alphabet)
			}
		})
	}
}

func TestNanoIDDefault(t *testing.T) {
	nanoid := NewNanoID()

	if nanoid == nil {
		t.Fatal("NewNanoIDGen() returned nil")
	}

	if nanoid.alphabet != defaultAlphabet {
		t.Errorf("alphabet = %q, expected %q", nanoid.alphabet, defaultAlphabet)
	}

	if nanoid.mask == 0 {
		t.Error("mask = 0, expected non-zero mask")
	}
}

func TestNanoIDGeneratorNewLength(t *testing.T) {
	nanoid := NewNanoID()

	tests := []struct {
		name     string
		length   []int
		expected int
	}{
		{"no argument uses default", []int{}, defaultSize},
		{"explicit default", []int{defaultSize}, defaultSize},
		{"custom length 12", []int{12}, 12},
		{"custom length 50", []int{50}, 50},
		{"zero uses default", []int{0}, defaultSize},
		{"negative uses default", []int{-5}, defaultSize},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var id string
			var err error

			if len(test.length) == 0 {
				id, err = nanoid.Generate()
			} else {
				id, err = nanoid.Generate(test.length[0])
			}

			t.Logf("actual generated id: %s\n", id)

			if err != nil {
				t.Fatalf("Generate() error = %v, expected nil", err)
			}

			if len(id) != test.expected {
				t.Errorf("len(id) = %d, expected %d", len(id), test.expected)
			}
		})
	}
}

func TestNanoIDGeneratorUsesAlphabet(t *testing.T) {
	tests := []struct {
		name     string
		alphabet string
		length   int
	}{
		{
			name:     "default alphabet",
			alphabet: defaultAlphabet,
			length:   100,
		},
		{
			name:     "custom alphabet",
			alphabet: "ABCD1234",
			length:   100,
		},
		{
			name:     "numeric only",
			alphabet: "0123456789",
			length:   50,
		},
		{
			name:     "lowercase only",
			alphabet: "abcdefghijklmnopqrstuvwxyz",
			length:   75,
		},
		{
			name:     "two character alphabet",
			alphabet: "AB",
			length:   50,
		},
		{
			name:     "single character alphabet",
			alphabet: "X",
			length:   30,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var nanoid *NanoIDGenerator
			var err error

			// Use default or custom alphabet
			if test.alphabet == defaultAlphabet {
				nanoid = NewNanoID()
			} else {
				nanoid, err = NewCustomNanoID(test.alphabet)
				if err != nil {
					t.Fatalf("NewNanoID() error = %v", err)
				}
			}

			// Generate ID
			id, err := nanoid.Generate(test.length)
			if err != nil {
				t.Fatalf("Generate() error = %v", err)
			}

			// Verify every character is from the alphabet
			for i, char := range id {
				if !strings.ContainsRune(test.alphabet, char) {
					t.Errorf("id[%d] = %q, not in alphabet %q", i, char, test.alphabet)
				}
			}
		})
	}
}

func TestNanoIDGeneratorUniqueness(t *testing.T) {
	nanoid := NewNanoID()
	seen := make(map[string]bool)
	iterations := 10000

	for i := 0; i < iterations; i++ {
		id, err := nanoid.Generate()
		if err != nil {
			t.Fatalf("iteration %d: Generate() error = %v", i, err)
		}

		if seen[id] {
			t.Fatalf("duplicate ID generated: %q", id)
		}
		seen[id] = true
	}

	if len(seen) != iterations {
		t.Errorf("generated %d unique IDs, want %d", len(seen), iterations)
	}
}

func TestNanoIDDistribution(t *testing.T) {
	t.Run("characters appear with equal probability", func(t *testing.T) {
		alphabet := "ABCD"
		nanoid, _ := NewCustomNanoID(alphabet)
		counts := make(map[rune]int)

		iterations := 10000
		idLength := 20

		for i := 0; i < iterations; i++ {
			id, err := nanoid.Generate(idLength)
			if err != nil {
				t.Fatalf("Generate() error = %v", err)
			}

			for _, char := range id {
				counts[char]++
			}
		}

		// Each character should appear roughly 25% of the time
		totalChars := iterations * idLength
		expectedPerChar := totalChars / len(alphabet)
		tolerance := 0.1 // 10% tolerance

		for _, char := range alphabet {
			count := counts[char]
			ratio := float64(count) / float64(expectedPerChar)

			if ratio < (1.0-tolerance) || ratio > (1.0+tolerance) {
				t.Errorf("char %q: count=%d, ratio=%.3f, expected ~1.0 ±%.0f%%",
					char, count, ratio, tolerance*100)
			}
		}
	})
}

func TestNanoIDGetMask(t *testing.T) {
	tests := []struct {
		alphabetLen  int
		expectedMask int
	}{
		{2, 3},     // 2 chars need mask 0b11 (3) - can represent 0-3
		{4, 7},     // 4 chars need mask 0b111 (7) - can represent 0-7
		{5, 7},     // 5 chars need mask 0b111 (7)
		{8, 15},    // 8 chars need mask 0b1111 (15)
		{9, 15},    // 9 chars need mask 0b1111 (15)
		{16, 31},   // 16 chars need mask 0b11111 (31)
		{17, 31},   // 17 chars need mask 0b11111 (31)
		{32, 63},   // 32 chars need mask 0b111111 (63)
		{33, 63},   // 33 chars need mask 0b111111 (63)
		{64, 127},  // 64 chars need mask 0b1111111 (127)
		{65, 127},  // 65 chars need mask 0b1111111 (127)
		{128, 255}, // 128 chars need mask 0b11111111 (255)
		{200, 255}, // 200 chars need mask 0b11111111 (255)
		{255, 255}, // 255 chars need mask 0b11111111 (255)
	}

	for _, test := range tests {
		t.Run(fmt.Sprintf("alphabet_%d", test.alphabetLen), func(t *testing.T) {
			// Create alphabet of specific length
			alphabet := strings.Repeat("a", test.alphabetLen)
			nanoid, err := NewCustomNanoID(alphabet)
			if err != nil {
				t.Fatalf("NewCustomNanoID() error = %v", err)
			}

			// The mask should be stored in the generator
			if nanoid.mask != test.expectedMask {
				t.Errorf("mask for alphabet length %d. actual %d (0b%b), expected %d (0b%b)",
					test.alphabetLen, nanoid.mask, nanoid.mask, test.expectedMask, test.expectedMask)
			}
		})
	}
}

func TestNanoIDGetMaskProperties(t *testing.T) {
	t.Run("mask is always (power of 2) - 1", func(t *testing.T) {
		for alphabetLen := 2; alphabetLen <= 255; alphabetLen++ {
			mask := getMask(alphabetLen)

			// Check if mask+1 is a power of 2
			// Power of 2 has only one bit set: (n+1) & n == 0
			isPowerOf2 := (mask+1)&mask == 0

			if !isPowerOf2 {
				t.Errorf("alphabetLen=%d: mask=%d, mask+1=%d is not power of 2",
					alphabetLen, mask, mask+1)
			}
		}
	})

	t.Run("mask is always > alphabetLen - 1", func(t *testing.T) {
		for alphabetLen := 2; alphabetLen <= 255; alphabetLen++ {
			mask := getMask(alphabetLen)

			if mask <= alphabetLen-1 {
				t.Errorf("alphabetLen=%d: mask=%d should be > alphabetLen-1=%d",
					alphabetLen, mask, alphabetLen-1)
			}
		}
	})
}

func TestNanoIDEdgeCases(t *testing.T) {
	tests := []struct {
		name     string
		alphabet string
		length   int
	}{
		{"minimum length 1", "ABCD", 1},
		{"large length", "ABCD", 200},
		{"single char alphabet", "X", 50},
		{"two char alphabet", "AB", 50},
		{"power of 2 alphabet (4)", "ABCD", 30},
		{"power of 2 alphabet (8)", "ABCDEFGH", 30},
		{"power of 2 alphabet (16)", "ABCDEFGHIJKLMNOP", 30},
		{"power of 2 alphabet (32)", strings.Repeat("ABCDEFGHIJKLMNOP", 2), 30},
		{"power of 2 alphabet (64)", strings.Repeat("ABCDEFGHIJKLMNOP", 4), 30},
		{"non-power of 2 (5)", "ABCDE", 30},
		{"non-power of 2 (10)", "0123456789", 30},
		{"non-power of 2 (26)", "abcdefghijklmnopqrstuvwxyz", 30},
		{"large alphabet (200)", strings.Repeat("abcdefghijklmnopqrstuvwxyz", 8)[:200], 30},
		{"max alphabet (255)", strings.Repeat("abcdefghijklmnopqrstuvwxyz", 10)[:255], 30},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			nanoid, err := NewCustomNanoID(test.alphabet)
			if err != nil {
				t.Fatalf("NewCustomNanoID() error = %v", err)
			}

			id, err := nanoid.Generate(test.length)
			if err != nil {
				t.Fatalf("Generate() error = %v", err)
			}

			if len(id) != test.length {
				t.Errorf("len(id) = %d, want %d", len(id), test.length)
			}

			// Verify all chars are from alphabet
			for i, char := range id {
				if !strings.ContainsRune(test.alphabet, char) {
					t.Errorf("id[%d] = %q, not in alphabet", i, char)
				}
			}
		})
	}
}

func TestNanoIDLengthVariations(t *testing.T) {
	nanoid := NewNanoID()

	tests := []struct {
		name   string
		length int
	}{
		{"length 1", 1},
		{"length 5", 5},
		{"length 10", 10},
		{"length 21", 21},
		{"length 50", 50},
		{"length 100", 100},
		{"length 500", 500},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			id, err := nanoid.Generate(test.length)
			if err != nil {
				t.Fatalf("Generate(%d) error = %v", test.length, err)
			}

			if len(id) != test.length {
				t.Errorf("len(id) = %d, want %d", len(id), test.length)
			}
		})
	}
}

func TestNanoIDMultipleCallsSameGenerator(t *testing.T) {
	nanoid := NewNanoID()
	ids := make(map[string]bool)

	// Generate 100 IDs with same generator
	for i := 0; i < 100; i++ {
		id, err := nanoid.Generate()
		if err != nil {
			t.Fatalf("iteration %d: Generate() error = %v", i, err)
		}

		if ids[id] {
			t.Errorf("duplicate ID on iteration %d: %q", i, id)
		}
		ids[id] = true

		if len(id) != defaultSize {
			t.Errorf("iteration %d: len(id) = %d, want %d", i, len(id), defaultSize)
		}
	}
}

func TestNanoIDConcurrency(t *testing.T) {
	t.Run("safe for concurrent use", func(t *testing.T) {
		nanoid := NewNanoID()
		const goroutines = 100
		results := make(chan string, goroutines)
		errors := make(chan error, goroutines)

		for i := 0; i < goroutines; i++ {
			go func() {
				id, err := nanoid.Generate()
				if err != nil {
					errors <- err
					return
				}
				results <- id
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
		for id := range results {
			if seen[id] {
				t.Errorf("duplicate ID in concurrent generation: %q", id)
			}
			seen[id] = true
		}

		if len(seen) != goroutines {
			t.Errorf("expected %d unique IDs, got %d", goroutines, len(seen))
		}
	})
}

func TestNanoIDAlphabetBoundaryConditions(t *testing.T) {
	tests := []struct {
		name        string
		alphabetLen int
	}{
		{"boundary at 2", 2},
		{"boundary at 3", 3},
		{"boundary at 4", 4},
		{"boundary at 7", 7},
		{"boundary at 8", 8},
		{"boundary at 15", 15},
		{"boundary at 16", 16},
		{"boundary at 31", 31},
		{"boundary at 32", 32},
		{"boundary at 63", 63},
		{"boundary at 64", 64},
		{"boundary at 127", 127},
		{"boundary at 128", 128},
		{"boundary at 254", 254},
		{"boundary at 255", 255},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			alphabet := strings.Repeat("a", test.alphabetLen)
			nanoid, err := NewCustomNanoID(alphabet)
			if err != nil {
				t.Fatalf("NewCustomNanoID() error = %v", err)
			}

			// Generate multiple IDs to ensure mask works correctly
			for i := 0; i < 10; i++ {
				id, err := nanoid.Generate(50)
				if err != nil {
					t.Fatalf("iteration %d: Generate() error = %v", i, err)
				}

				// Verify all characters are 'a'
				for j, char := range id {
					if char != 'a' {
						t.Errorf("iteration %d, position %d: char = %q, want 'a'", i, j, char)
					}
				}
			}
		})
	}
}
