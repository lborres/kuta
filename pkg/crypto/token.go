package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
)

var (
	ErrTooManyArgs = errors.New("too many arguments. expected only 1")
)

const (
	DefaultTokenLength = 32 // 256 bits
)

type TokenPair struct {
	Token string // value returned to client
	Hash  string // value in storage
}

func generateToken(byteLength int) (string, error) {
	if byteLength <= 0 {
		byteLength = DefaultTokenLength
	}

	bytes := make([]byte, byteLength)

	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}

	return base64.RawURLEncoding.EncodeToString(bytes), nil
}

func GenerateHashedToken(byteLength ...int) (*TokenPair, error) {
	if len(byteLength) > 1 {
		return nil, ErrTooManyArgs
	}

	length := DefaultTokenLength

	if len(byteLength) > 0 && byteLength[0] > 0 {
		length = byteLength[0]
	}

	token, err := generateToken(length)
	if err != nil {
		return nil, err
	}

	hashedToken := HashToken(token)

	return &TokenPair{
		Token: token,
		Hash:  hashedToken,
	}, nil
}

func VerifyToken(token, storedHash string) (bool, error) {
	if token == "" || storedHash == "" {
		return false, errors.New("token and hash cannot be empty")
	}

	tokenHash := HashToken(token)

	// Constant-time comparison to prevent timing attacks
	return subtle.ConstantTimeCompare([]byte(tokenHash), []byte(storedHash)) == 1, nil
}

func HashToken(token string) string {
	hash := sha256.Sum256([]byte(token))
	return hex.EncodeToString(hash[:])
}
