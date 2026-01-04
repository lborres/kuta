package crypto

import (
	"strings"
	"testing"
)

func TestNanoIDGenerator_New(t *testing.T) {
	tests := []struct {
		name         string
		args         []string
		wantErr      error
		wantAlphabet string
	}{
		{name: "empty args use default", args: nil, wantErr: nil, wantAlphabet: defaultAlphabet},
		{name: "custom alphabet", args: []string{"ABCDEFGH"}, wantErr: nil, wantAlphabet: "ABCDEFGH"},
		{name: "too many args", args: []string{"a", "b"}, wantErr: ErrTooManyInputAlphabet},
		{name: "alphabet too long", args: []string{strings.Repeat("a", 256)}, wantErr: ErrAlphabetTooLong},
		{name: "empty string uses default", args: []string{""}, wantErr: nil, wantAlphabet: defaultAlphabet},
		{name: "min alphabet size", args: []string{strings.Repeat("a", 8)}, wantErr: nil, wantAlphabet: strings.Repeat("a", 8)},
		{name: "max alphabet size", args: []string{strings.Repeat("a", 255)}, wantErr: nil, wantAlphabet: strings.Repeat("a", 255)},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			// Act
			nanoid, err := NewNanoID(test.args...)

			// Assert
			if (err != nil) != (test.wantErr != nil) {
				t.Fatalf("New() error = %v, wantErr %v", err, test.wantErr)
			}
			if err != test.wantErr && test.wantErr != nil {
				t.Fatalf("New() error = %v, want %v", err, test.wantErr)
			}
			if test.wantErr == nil && nanoid == nil {
				t.Fatal("New() returned nil, want *NanoIDGenerator")
			}
			if test.wantErr == nil && test.wantAlphabet != "" && nanoid.alphabet != test.wantAlphabet {
				t.Errorf("New() alphabet = %q, want %q", nanoid.alphabet, test.wantAlphabet)
			}
		})
	}
}

func TestNanoIDGenerator_GetMask(t *testing.T) {
	tests := []struct {
		name        string
		alphabetLen int
		wantMask    int
	}{
		{name: "alphabet 8", alphabetLen: 8, wantMask: 15},      // 3 bits → 4 bit mask (0xF)
		{name: "alphabet 9", alphabetLen: 9, wantMask: 15},      // 4 bits → 4 bit mask (0xF)
		{name: "alphabet 16", alphabetLen: 16, wantMask: 31},    // 4 bits → 5 bit mask (0x1F)
		{name: "alphabet 17", alphabetLen: 17, wantMask: 31},    // 5 bits → 5 bit mask (0x1F)
		{name: "alphabet 32", alphabetLen: 32, wantMask: 63},    // 5 bits → 6 bit mask (0x3F)
		{name: "alphabet 33", alphabetLen: 33, wantMask: 63},    // 6 bits → 6 bit mask (0x3F)
		{name: "alphabet 64", alphabetLen: 64, wantMask: 127},   // 6 bits → 7 bit mask (0x7F)
		{name: "alphabet 65", alphabetLen: 65, wantMask: 127},   // 7 bits → 7 bit mask (0x7F)
		{name: "alphabet 128", alphabetLen: 128, wantMask: 255}, // 7 bits → 8 bit mask (0xFF)
		{name: "alphabet 200", alphabetLen: 200, wantMask: 255}, // 8 bits → 8 bit mask (0xFF)
		{name: "alphabet 255", alphabetLen: 255, wantMask: 255}, // 8 bits → 8 bit mask (0xFF)
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			// Arrange
			alphabet := strings.Repeat("a", test.alphabetLen)
			nanoid, err := NewNanoID(alphabet)
			if err != nil {
				t.Fatalf("NewNanoID() error = %v", err)
			}

			// Assert
			if nanoid.mask != test.wantMask {
				t.Errorf("GetMask() = %d (0b%b), want %d (0b%b)",
					nanoid.mask, nanoid.mask, test.wantMask, test.wantMask)
			}
			// Verify mask properties
			if ((nanoid.mask + 1) & nanoid.mask) != 0 {
				t.Errorf("mask %d is not (power of 2 - 1)", nanoid.mask)
			}
			if nanoid.mask <= test.alphabetLen-1 {
				t.Errorf("mask %d <= alphabetLen-1 %d", nanoid.mask, test.alphabetLen-1)
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
		{name: "default alphabet", alphabet: defaultAlphabet, length: 100},
		{name: "custom alphabet", alphabet: "ABCD1234", length: 100},
		{name: "numeric only", alphabet: "0123456789", length: 50},
		{name: "lowercase only", alphabet: "abcdefghijklmnopqrstuvwxyz", length: 75},
		{name: "min size alphabet", alphabet: "ABCDEFGH", length: 50},
		{name: "max size alphabet", alphabet: strings.Repeat("abcdefghijklmnopqrstuvwxyz", 10)[:255], length: 50},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			// Arrange
			nanoid, err := NewNanoID(test.alphabet)
			if err != nil {
				t.Fatalf("NewNanoID() error = %v", err)
			}

			// Act
			id, err := nanoid.Generate(test.length)
			if err != nil {
				t.Fatalf("Generate() error = %v", err)
			}

			// Assert
			if len(id) != test.length {
				t.Errorf("len(id) = %d, want %d", len(id), test.length)
			}
			for i, char := range id {
				if !strings.ContainsRune(test.alphabet, char) {
					t.Errorf("id[%d] = %q, not in alphabet", i, char)
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

func FuzzNanoID_Generate(f *testing.F) {
	// Richer seed corpus covering boundaries and edge cases
	f.Add("", 0)                                                      // default alphabet, default length
	f.Add("ABCDEFGH", 1)                                              // minimum alphabet size, minimum length
	f.Add(strings.Repeat("abcdefghijklmnopqrstuvwxyz", 10)[:255], 22) // maximum alphabet size, default length
	f.Add(defaultAlphabet, 0)                                         // default alphabet, default length
	f.Add(defaultAlphabet, 22)                                        // explicit default length
	f.Add(defaultAlphabet, -1)                                        // negative length (uses default)
	f.Add(defaultAlphabet, 1000)                                      // large length
	f.Add("0123456789", 100)                                          // numeric only
	f.Add("abcdefghijklmnopqrstuvwxyz", 50)                           // lowercase only

	f.Fuzz(func(t *testing.T, alphabet string, length int) {
		// Normalize empty alphabet to default
		if alphabet == "" {
			alphabet = defaultAlphabet
		}

		// Guard: only test valid alphabet sizes per API contract
		if len(alphabet) < minAlphabetSize || len(alphabet) > maxAlphabetSize {
			t.Skip()
		}

		// Guard: cap extreme lengths to avoid resource exhaustion
		if length > 10000 || length < -10000 {
			t.Skip()
		}

		// Create generator
		nano, err := NewNanoID(alphabet)
		if err != nil {
			// Expected for invalid UTF-8, too short/long alphabet
			// Fuzz test validates error handling
			t.Skip()
		}

		// Generate ID
		id, err := nano.Generate(length)
		if err != nil {
			t.Fatalf("Generate(length=%d) error: %v", length, err)
		}

		// Invariant 1: ID is non-empty
		if id == "" {
			t.Fatal("Generate() returned empty string")
		}

		// Invariant 2: ID length matches specification
		expectedLen := defaultSize
		if length > 0 {
			expectedLen = length
		}

		if len(id) != expectedLen {
			t.Errorf("Generate(length=%d) returned len=%d, want %d", length, len(id), expectedLen)
		}

		// Invariant 3: All characters are from alphabet
		for i, ch := range id {
			if !strings.ContainsRune(alphabet, ch) {
				t.Errorf("Generate() position %d: char %q not in alphabet (len=%d)", i, ch, len(alphabet))
			}
		}
	})
}
