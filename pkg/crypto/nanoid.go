package crypto

import (
	"crypto/rand"
	"errors"
	"math"
)

const (
	defaultAlphabet string = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-"
	defaultSize     int    = 21
	maxAlphabetSize int    = 255
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

func NewCustomNanoID(alphabet string) (*NanoIDGenerator, error) {
	if alphabet == "" {
		return nil, errors.New("alphabet cannot be empty")
	}

	if len(alphabet) > maxAlphabetSize {
		return nil, errors.New("alphabet must contain no more than 255 characters")
	}

	return &NanoIDGenerator{
		alphabet: alphabet,
		mask:     getMask(len(alphabet)),
	}, nil
}

func NewNanoID() *NanoIDGenerator {
	return &NanoIDGenerator{
		alphabet: defaultAlphabet,
		mask:     getMask(len(defaultAlphabet)),
	}
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
