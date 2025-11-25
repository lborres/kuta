package core

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

type PasswordHandler interface {
	Hash(password string) (string, error)
	Verify(password, hash string) (bool, error)
}

// Ensure Argon2 implements PasswordHandler
var _ PasswordHandler = (*Argon2)(nil)

type Argon2 struct {
	Memory      uint32 // Memory cost in KiB
	Iterations  uint32 // Number of iterations (time cost)
	Parallelism uint8  // Number of parallel threads
	SaltLength  uint32 // Length of random salt. Ignored during Verify()
	KeyLength   uint32 // Length of generated key
}

// Create a new Argon2 instance
//
// @ref https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
func NewArgon2() *Argon2 {
	return &Argon2{
		Memory:      64 * 1024, // 64 MB
		Iterations:  3,
		Parallelism: 2,
		SaltLength:  16,
		KeyLength:   32,
	}
}

func (a *Argon2) Hash(password string) (string, error) {
	// Salt Generation
	salt := make([]byte, a.SaltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("failed to generate salt: %w", err)
	}

	// TODO: Consider argon2i case
	hash := argon2.IDKey(
		[]byte(password),
		salt,
		a.Iterations,
		a.Memory,
		a.Parallelism,
		a.KeyLength,
	)

	println(hash)

	// WARN: hard-coded argon2id string. Only valid due to using argon2.IDKey()
	encoded := fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version,
		a.Memory,
		a.Iterations,
		a.Parallelism,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hash))

	return encoded, nil
}

func (a *Argon2) Verify(password, encodedHash string) (bool, error) {
	params, salt, hash, err := decodeArgon2Hash(encodedHash)
	if err != nil {
		return false, err
	}

	computedHash := argon2.IDKey(
		[]byte(password),
		salt,
		params.Iterations,
		params.Memory,
		params.Parallelism,
		params.KeyLength,
	)

	return subtle.ConstantTimeCompare(hash, computedHash) == 1, nil
}

func decodeArgon2Hash(encodedHash string) (*Argon2, []byte, []byte, error) {
	parts := strings.Split(encodedHash, "$")
	if len(parts) != 6 {
		return nil, nil, nil, errors.New("invalid hash format")
	}

	if parts[1] != "argon2id" {
		return nil, nil, nil, errors.New("unsupported algorithm")
	}

	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil {
		return nil, nil, nil, fmt.Errorf("invalid version: %w", err)
	}

	params := &Argon2{}
	paramParts := strings.Split(parts[3], ",")
	if len(paramParts) != 3 {
		return nil, nil, nil, errors.New("invalid parameters format")
	}

	if _, err := fmt.Sscanf(paramParts[0], "m=%d", &params.Memory); err != nil {
		return nil, nil, nil, fmt.Errorf("invalid memory parameter: %w", err)
	}

	if _, err := fmt.Sscanf(paramParts[1], "t=%d", &params.Iterations); err != nil {
		return nil, nil, nil, fmt.Errorf("invalid iterations parameter: %w", err)
	}

	var p int
	if _, err := fmt.Sscanf(paramParts[2], "p=%d", &p); err != nil {
		return nil, nil, nil, fmt.Errorf("invalid parallelism parameter: %w", err)
	}
	params.Parallelism = uint8(p)

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return nil, nil, nil, fmt.Errorf("invalid salt encoding: %w", err)
	}

	hash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return nil, nil, nil, fmt.Errorf("invalid hash encoding: %w", err)
	}

	params.KeyLength = uint32(len(hash))

	return params, salt, hash, nil
}
