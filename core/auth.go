package core

// AuthProvider provides authentication operations for HTTP adapters
type AuthProvider interface {
	SignUp(input SignUpInput, ipAddress, userAgent string) (*SignUpResult, error)
	SignIn(input SignInInput, ipAddress, userAgent string) (*SignInResult, error)
	SignOut(token string) error
	GetSession(token string) (*SessionData, error)
}

type SignUpInput struct {
	Email    string
	Password string
	Name     string
	Image    *string
}

type SignUpResult struct {
	User    *User    `json:"user"`
	Session *Session `json:"session"`
	Token   string   `json:"token"` // The raw token (not the hash)
}

type SignInInput struct {
	Email    string
	Password string
}

type SignInResult struct {
	User    *User    `json:"user"`
	Session *Session `json:"session"`
	Token   string   `json:"token"` // The raw token (not the hash)
}
