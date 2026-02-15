package core

// AuthProvider provides authentication operations for HTTP adapters
type AuthProvider interface {
	SignUp(input SignUpInput, ipAddress, userAgent string) (*SignUpResult, error)
	SignIn(input SignInInput, ipAddress, userAgent string) (*SignInResult, error)
	SignOut(token string) error
	GetSession(token string) (*SessionData, error)
	Refresh(token string) (*RefreshResult, error)
}

type SignUpInput struct {
	Email    string  `json:"email"`
	Password string  `json:"password"`
	Name     string  `json:"name"`
	Image    *string `json:"image,omitempty"`
}

type SignUpResult struct {
	User    *User    `json:"user"`
	Session *Session `json:"session"`
	Token   string   `json:"token"` // The raw token (not the hash)
}

type SignInInput struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type SignInResult struct {
	User    *User    `json:"user"`
	Session *Session `json:"session"`
	Token   string   `json:"token"` // The raw token (not the hash)
}

type RefreshResult struct {
	Session *Session `json:"session"`
	Token   string   `json:"token"` // The raw token (not the hash)
}

type CreateSessionResult struct {
	Session *Session `json:"session"`
	Token   string   `json:"token"`
}
