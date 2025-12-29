package core

import (
	"github.com/lborres/kuta/crypto"
)

type Config struct {
	Secret string

	Database AuthStorage

	HTTP HTTPAdapter

	// Optional config
	CacheAdapter   Cache
	SessionConfig  *SessionConfig
	PasswordHasher crypto.PasswordHandler
	BasePath       string
}

type Kuta struct {
	SessionManager *SessionManager
	PasswordHasher crypto.PasswordHandler
	Secret         string
	BasePath       string
}
