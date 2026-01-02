package crypto

import (
	"fmt"
	"strings"
	"testing"
)

func TestNanoIDConstructor(t *testing.T) {
	tests := []struct {
		name         string
		args         []string
		expectErr    bool
		wantErr      error
		wantAlphabet string
	}{
		{"empty args should use default alphabet", nil, false, nil, defaultAlphabet},
		{"use custom alphabet", []string{"ABCDEFGH"}, false, nil, "ABCDEFGH"},

		// Negative Scenarios
		{"too many args", []string{"a", "b"}, true, ErrTooManyInputAlphabet, ""},
		{"reject greater than max alphabet size", []string{strings.Repeat("a", 256)}, true, ErrAlphabetTooLong, ""},

		// Edge cases
		{"empty string should use default alphabet", []string{""}, false, nil, defaultAlphabet},
		{"accept minimum alphabet size", []string{strings.Repeat("a", 8)}, false, nil, strings.Repeat("a", 8)},
		{"accept max alphabet size", []string{strings.Repeat("a", 255)}, false, nil, strings.Repeat("a", 255)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			nanoid, err := NewNanoID(test.args...)
			if err != nil && !test.expectErr {
				t.Fatalf("expected no error but got '%v'", err)
			}

			if (err != nil) && err != test.wantErr {
				t.Fatalf("expected error '%v' got '%v'", test.wantErr, err)
			}

			if nanoid == nil && !test.expectErr {
				t.Fatalf("expected nanoid object, got nil")
			}

			if !test.expectErr && nanoid != nil && nanoid.alphabet != test.wantAlphabet {
				t.Fatalf("expected alphabet %q, got %q", test.wantAlphabet, nanoid.alphabet)
			}
		})
	}
}

func TestNanoIDGetMask(t *testing.T) {
	t.Run("mask is power-of-two minus one and within bounds", func(t *testing.T) {
		for alphabetLen := minAlphabetSize; alphabetLen <= maxAlphabetSize; alphabetLen++ {
			mask := getMask(alphabetLen)

			// mask+1 must be a power of two
			if ((mask + 1) & mask) != 0 {
				t.Errorf("alphabetLen=%d: mask=%d, mask+1=%d is not power of 2", alphabetLen, mask, mask+1)
			}

			// mask must be strictly greater than alphabetLen-1
			if mask <= alphabetLen-1 {
				t.Errorf("alphabetLen=%d: mask=%d <= alphabetLen-1=%d", alphabetLen, mask, alphabetLen-1)
			}

			// mask should not exceed maxAlphabetSize
			if mask > maxAlphabetSize {
				t.Errorf("alphabetLen=%d: mask=%d > maxAlphabetSize=%d", alphabetLen, mask, maxAlphabetSize)
			}
		}
	})
}

func TestNanoIDGetMaskBitmask(t *testing.T) {
	tests := []struct {
		alphabetLen int
		wantMask    int
	}{
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
			nanoid, err := NewNanoID(alphabet)
			if err != nil {
				t.Fatalf("NewNanoID() error = %v", err)
			}

			// The mask should be stored in the generator
			if nanoid.mask != test.wantMask {
				t.Errorf("expected %d (0b%b) mask for alphabet length %d, got %d (0b%b)",
					test.wantMask, test.wantMask, test.alphabetLen, nanoid.mask, nanoid.mask)
			}
		})
	}
}

func TestNanoIDGeneratedLength(t *testing.T) {
	nanoid, _ := NewNanoID()

	tests := []struct {
		name   string
		length []int
		want   int
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

			id, err = nanoid.Generate(test.length...)

			if err != nil {
				t.Fatalf("expected nil error, got Generate() error = %v", err)
			}

			if len(id) != test.want {
				t.Errorf("expected %d, got %d", test.want, len(id))
			}
		})
	}
}

func TestNanoIDGeneratedCharacters(t *testing.T) {
	tests := []struct {
		name     string
		alphabet string
		length   int
	}{
		{"default alphabet", defaultAlphabet, 100},
		{"custom alphabet", "ABCD1234", 100},
		{"numeric only", "0123456789", 50},
		{"lowercase only", "abcdefghijklmnopqrstuvwxyz", 75},
		{"two character alphabet", "AB", 50},
		{"single character alphabet", "X", 30},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var nanoid *NanoIDGenerator
			var err error

			// Use default or custom alphabet
			if test.alphabet == defaultAlphabet {
				nanoid, _ = NewNanoID()
			} else {
				nanoid, err = NewNanoID(test.alphabet)
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

func TestNanoIDGenerateUniqueness(t *testing.T) {
	nanoid, _ := NewNanoID()
	seen := make(map[string]bool)
	iterations := 100_000

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

func TestNanoIDGenerateCharacterDistribution(t *testing.T) {
	t.Run("characters appear with equal probability", func(t *testing.T) {
		alphabet := "ABCDEFGH"
		nanoid, _ := NewNanoID(alphabet)
		counts := make(map[rune]int)

		iterations := 100000
		idLength := 22

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
		tolerance := 0.01

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

func TestNanoIDGenerateEdgeCases(t *testing.T) {
	tests := []struct {
		name     string
		alphabet string
		length   int
	}{
		{"minimum length 1", "ABCDEFGH", 1},
		{"large length", "ABCDEFGH", 200},
		{"power of 2 alphabet (8)", "ABCDEFGH", 30},
		{"power of 2 alphabet (16)", "ABCDEFGHIJKLMNOP", 30},
		{"power of 2 alphabet (32)", strings.Repeat("ABCDEFGHIJKLMNOP", 2), 30},
		{"power of 2 alphabet (64)", strings.Repeat("ABCDEFGHIJKLMNOP", 4), 30},
		{"non-power of 2 (10)", "0123456789", 30},
		{"non-power of 2 (26)", "abcdefghijklmnopqrstuvwxyz", 30},
		{"large alphabet (200)", strings.Repeat("abcdefghijklmnopqrstuvwxyz", 8)[:200], 30},
		{"max alphabet (255)", strings.Repeat("abcdefghijklmnopqrstuvwxyz", 10)[:255], 30},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			nanoid, err := NewNanoID(test.alphabet)
			if err != nil {
				t.Fatalf("NewNanoID() error = %v", err)
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

func TestNanoIDGenerateLengthVariations(t *testing.T) {
	nanoid, _ := NewNanoID()

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

func TestNanoIDGenerateConcurrency(t *testing.T) {
	t.Run("safe for concurrent use", func(t *testing.T) {
		nanoid, _ := NewNanoID()
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

func TestNanoIDGenerateAlphabetBoundaries(t *testing.T) {
	tests := []struct {
		name        string
		alphabetLen int
	}{
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
			nanoid, err := NewNanoID(alphabet)
			if err != nil {
				t.Fatalf("NewNanoID() error = %v", err)
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

// BenchmarkNanoIDUniqueness tests uniqueness at scale
// Run with: go test -bench=BenchmarkNanoIDUniqueness -benchmem -benchtime=100000x
// For more confidence: -benchtime=1000000x or -benchtime=10000000x
func BenchmarkNanoIDUniqueness(b *testing.B) {
	nanoid, _ := NewNanoID()
	seen := make(map[string]struct{}, b.N) // struct{} uses less memory than bool

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		id, err := nanoid.Generate()
		if err != nil {
			b.Fatalf("iteration %d: Generate() error = %v", i, err)
		}

		if _, exists := seen[id]; exists {
			b.Fatalf("COLLISION DETECTED at iteration %d: %q (out of %d IDs generated)", i, id, len(seen))
		}
		seen[id] = struct{}{}
	}

	// Report total unique IDs as custom metric
	b.ReportMetric(float64(len(seen)), "unique_ids")
}
