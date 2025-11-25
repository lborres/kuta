package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
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

func GenerateHashedToken(byteLength int) (*TokenPair, error) {
	if byteLength <= 0 {
		byteLength = DefaultTokenLength
	}

	token, err := generateToken(byteLength)
	if err != nil {
		return nil, err
	}

	hash := sha256.Sum256([]byte(token))
	hashedToken := hex.EncodeToString(hash[:])

	return &TokenPair{
		Token: token,
		Hash:  hashedToken,
	}, nil
}

func VerifyToken(token, storedHash string) (bool, error) {
	if token == "" || storedHash == "" {
		return false, errors.New("token and hash cannot be empty")
	}

	hash := sha256.Sum256([]byte(token))
	tokenHash := hex.EncodeToString(hash[:])

	// Constant-time comparison to prevent timing attacks
	return subtle.ConstantTimeCompare([]byte(tokenHash), []byte(storedHash)) == 1, nil
}
