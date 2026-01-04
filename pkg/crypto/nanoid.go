package crypto

import (
	"crypto/rand"
	"errors"
	"math"
	"unicode/utf8"
)

const (
	defaultAlphabet string = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-"
	defaultSize     int    = 22 // 22 * 6 = 132 bits (uuid is 128 bits) of entropy
	maxAlphabetSize int    = 255
	minAlphabetSize int    = 8
)

var (
	ErrTooManyInputAlphabet = errors.New("must only provide 1 set of alphabet")
	ErrAlphabetTooLong      = errors.New("alphabet must contain no more than 255 characters")
	ErrAlphabetTooShort     = errors.New("alphabet must contain at least 8 characters")
	ErrAlphabetInvalidUTF8  = errors.New("alphabet must contain valid UTF-8")
	ErrAlphabetNotASCII     = errors.New("alphabet must contain only ASCII characters")
)

type NanoIDGenerator struct {
	alphabet string
	mask     int
}

func getMask(alphabetLen int) int {
	for i := 1; i <= 8; i++ {
		mask := (2 << uint(i)) - 1
		if mask > alphabetLen-1 {
			return mask
		}
	}
	return maxAlphabetSize // Max mask for 8 bits
}

func NewNanoID(a ...string) (*NanoIDGenerator, error) {
	if len(a) > 1 {
		return nil, ErrTooManyInputAlphabet
	}

	alphabet := defaultAlphabet
	if !(len(a) == 0 || a[0] == "") {
		alphabet = a[0]
	}

	if !utf8.ValidString(alphabet) {
		return nil, ErrAlphabetInvalidUTF8
	}

	// Verify all characters are ASCII (single-byte UTF-8)
	// This is required because Generate() indexes by byte position
	for _, r := range alphabet {
		if r > 127 {
			return nil, ErrAlphabetNotASCII
		}
	}

	if len(alphabet) > maxAlphabetSize {
		return nil, ErrAlphabetTooLong
	}
	if len(alphabet) < minAlphabetSize {
		return nil, ErrAlphabetTooShort
	}

	return &NanoIDGenerator{
		alphabet: alphabet,
		mask:     getMask(len(alphabet)),
	}, nil
}

func (n *NanoIDGenerator) Generate(length ...int) (string, error) {
	size := defaultSize
	if len(length) > 0 && length[0] > 0 {
		size = length[0]
	}

	alphabetLen := len(n.alphabet)
	step := int(math.Ceil(1.6 * float64(n.mask*size) / float64(alphabetLen)))

	id := make([]byte, size)
	buffer := make([]byte, step)

	for position := 0; position < size; {
		// Generate random bytes
		if _, err := rand.Read(buffer); err != nil {
			return "", err
		}

		// Map random bytes to alphabet characters
		for i := 0; i < step && position < size; i++ {
			// Apply mask to get candidate index
			index := buffer[i] & byte(n.mask)

			// Use index if it's valid for our alphabet
			if int(index) < alphabetLen {
				id[position] = n.alphabet[index]
				position++
			}
		}
	}

	return string(id), nil
}
