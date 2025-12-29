package core

type SessionStorage interface {
	CreateSession(session *Session) error

	// Query methods
	GetSessionByHash(tokenHash string) (*Session, error)
	GetSessionByID(id string) (*Session, error)
	GetUserSessions(userID string) ([]*Session, error)

	// Update
	UpdateSession(session *Session) error

	// Delete methods
	DeleteSessionByID(id string) error
	DeleteSessionByHash(tokenHash string) error
	DeleteUserSessions(userID string) error

	// Cleanup
	DeleteExpiredSessions() (int, error)
}

type UserStorage interface {
	CreateUser(u *User) error

	GetUserByID(id string) (*User, error)
	GetUserByEmail(email string) (*User, error)

	UpdateUser(u *User) error

	DeleteUser(id string) error
}

type AccountStorage interface {
	CreateAccount(a *Account) error

	GetAccountByID(id string) (*Account, error)
	GetAccountByUserAndProvider(userID, providerID string) ([]*Account, error)

	UpdateAccount(a *Account) error

	DeleteAccount(id string) error
}

type AuthStorage interface {
	UserStorage
	AccountStorage
	SessionStorage
}
