package core

// SessionStorage defines session-related database operations
type SessionStorage interface {
	CreateSession(session *Session) error
	GetSessionByHash(tokenHash string) (*Session, error)
	GetSessionByID(id string) (*Session, error)
	GetUserSessions(userID string) ([]*Session, error)
	UpdateSession(session *Session) error
	DeleteSessionByID(id string) error
	DeleteSessionByHash(tokenHash string) error
	DeleteUserSessions(userID string) (int, error)
	DeleteExpiredSessions() (int, error)
}

// UserStorage defines user-related database operations
type UserStorage interface {
	CreateUser(u *User) error
	GetUserByID(id string) (*User, error)
	GetUserByEmail(email string) (*User, error)
	UpdateUser(u *User) error
	DeleteUser(id string) error
}

// AccountStorage defines account-related database operations
type AccountStorage interface {
	CreateAccount(a *Account) error
	GetAccountByID(id string) (*Account, error)
	GetAccountByUserAndProvider(userID, providerID string) ([]*Account, error)
	UpdateAccount(a *Account) error
	DeleteAccount(id string) error
}

type StorageProvider interface {
	UserStorage
	AccountStorage
	SessionStorage
}
