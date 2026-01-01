package core

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
