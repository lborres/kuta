package fiber

import (
	"errors"
	"net/http"
	"testing"

	"github.com/lborres/kuta/core"
)

// mockAuthProvider is a test fake implementing core.AuthProvider interface
type mockAuthProvider struct {
	signUpCalled     bool
	signUpInput      core.SignUpInput
	signUpErr        error
	signUpResult     *core.SignUpResult
	signInCalled     bool
	signInInput      core.SignInInput
	signInErr        error
	signInResult     *core.SignInResult
	signOutCalled    bool
	signOutToken     string
	signOutErr       error
	getSessionCalled bool
	getSessionToken  string
	getSessionErr    error
	getSessionData   *core.SessionData
	refreshCalled    bool
	refreshToken     string
	refreshErr       error
	refreshResult    *core.RefreshResult
}

func (m *mockAuthProvider) SignUp(input core.SignUpInput, ipAddress, userAgent string) (*core.SignUpResult, error) {
	m.signUpCalled = true
	m.signUpInput = input
	if m.signUpErr != nil {
		return nil, m.signUpErr
	}
	return m.signUpResult, nil
}

func (m *mockAuthProvider) SignIn(input core.SignInInput, ipAddress, userAgent string) (*core.SignInResult, error) {
	m.signInCalled = true
	m.signInInput = input
	if m.signInErr != nil {
		return nil, m.signInErr
	}
	return m.signInResult, nil
}

func (m *mockAuthProvider) SignOut(token string) error {
	m.signOutCalled = true
	m.signOutToken = token
	return m.signOutErr
}

func (m *mockAuthProvider) GetSession(token string) (*core.SessionData, error) {
	m.getSessionCalled = true
	m.getSessionToken = token
	if m.getSessionErr != nil {
		return nil, m.getSessionErr
	}
	return m.getSessionData, nil
}

func (m *mockAuthProvider) Refresh(token string) (*core.RefreshResult, error) {
	m.refreshCalled = true
	m.refreshToken = token
	if m.refreshErr != nil {
		return nil, m.refreshErr
	}
	return m.refreshResult, nil
}

// Requirement: authHandlers struct can be instantiated with provider and config
func TestAuthHandlers_Creation(t *testing.T) {
	mock := &mockAuthProvider{}

	h := &authHandlers{
		provider:   mock,
		sessionCfg: nil,
	}

	if h.provider == nil {
		t.Error("authHandlers should hold provider reference")
	}
}

// Requirement: authHandlers.cookieCfg returns nil when sessionCfg is nil
func TestAuthHandlers_CookieCfg_ReturnsNilWhenNoSessionConfig(t *testing.T) {
	h := &authHandlers{
		provider:   &mockAuthProvider{},
		sessionCfg: nil,
	}

	if h.cookieCfg() != nil {
		t.Error("cookieCfg should return nil when sessionCfg is nil")
	}
}

// Requirement: authHandlers.cookieCfg returns cookie config when sessionCfg exists
func TestAuthHandlers_CookieCfg_ReturnsCookieConfigWhenPresent(t *testing.T) {
	expected := &core.CookieConfig{}
	h := &authHandlers{
		provider: &mockAuthProvider{},
		sessionCfg: &core.SessionConfig{
			CookieConfig: expected,
		},
	}

	if h.cookieCfg() != expected {
		t.Error("cookieCfg should return CookieConfig from sessionCfg")
	}
}

// Requirement: mapErrorToStatus maps authentication errors to correct HTTP status codes
func TestMapErrorToStatus_ErrorMapping(t *testing.T) {
	tests := []struct {
		name       string
		err        error
		wantStatus int
	}{
		{
			name:       "maps ErrInvalidCredentials to 401",
			err:        core.ErrInvalidCredentials,
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "maps ErrUserNotFound to 401",
			err:        core.ErrUserNotFound,
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "maps ErrInvalidToken to 401",
			err:        core.ErrInvalidToken,
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "maps ErrSessionExpired to 401",
			err:        core.ErrSessionExpired,
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "maps ErrEmailRequired to 400",
			err:        core.ErrEmailRequired,
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "maps ErrPasswordRequired to 400",
			err:        core.ErrPasswordRequired,
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "defaults unknown errors to 500",
			err:        errors.New("unknown error"),
			wantStatus: http.StatusInternalServerError,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			// Act
			status := mapErrorToStatus(test.err)

			// Assert
			if status != test.wantStatus {
				t.Errorf("mapErrorToStatus should map error to %d; got %d", test.wantStatus, status)
			}
		})
	}
}
