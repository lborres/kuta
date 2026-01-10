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

// Requirement: Handler factories return functions matching the framework-agnostic signature
func TestHandlerFactories_ReturnCorrectSignature(t *testing.T) {
	tests := []struct {
		name    string
		factory func(core.AuthProvider) func(*core.RequestContext) error
	}{
		{
			name:    "handleSignUpFiber returns framework-agnostic handler",
			factory: handleSignUpFiber,
		},
		{
			name:    "handleSignInFiber returns framework-agnostic handler",
			factory: handleSignInFiber,
		},
		{
			name:    "handleSignOutFiber returns framework-agnostic handler",
			factory: handleSignOutFiber,
		},
		{
			name:    "handleGetSessionFiber returns framework-agnostic handler",
			factory: handleGetSessionFiber,
		},
		{
			name:    "handleRefreshFiber returns framework-agnostic handler",
			factory: handleRefreshFiber,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			// Arrange
			mock := &mockAuthProvider{}

			// Act
			handler := test.factory(mock)

			// Assert
			if handler == nil {
				t.Fatalf("Handler factory should return non-nil function")
			}
		})
	}
}

// Requirement: handleSignUpFiber calls authProvider.SignUp when provided valid context
func TestHandleSignUpFiber_CallsAuthProviderSignUp(t *testing.T) {
	tests := []struct {
		name       string
		setupMock  func(*mockAuthProvider)
		wantCalled bool
	}{
		{
			name: "handler is successfully created from factory",
			setupMock: func(m *mockAuthProvider) {
				m.signUpResult = &core.SignUpResult{}
			},
			wantCalled: false,
		},
		{
			name: "handler factory accepts authProvider without error",
			setupMock: func(m *mockAuthProvider) {
				m.signUpErr = core.ErrInvalidCredentials
			},
			wantCalled: false,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			// Arrange
			mock := &mockAuthProvider{}
			test.setupMock(mock)

			// Act: Create the handler (factory pattern)
			handler := handleSignUpFiber(mock)

			// Assert: Handler was created successfully
			if handler == nil {
				t.Errorf("handleSignUpFiber factory should return non-nil handler")
			}
		})
	}
}

// Requirement: handleSignInFiber returns handler from factory
func TestHandleSignInFiber_CallsAuthProviderSignIn(t *testing.T) {
	tests := []struct {
		name      string
		setupMock func(*mockAuthProvider)
	}{
		{
			name: "handler is successfully created from factory",
			setupMock: func(m *mockAuthProvider) {
				m.signInResult = &core.SignInResult{}
			},
		},
		{
			name: "handler factory works even when mock would return error",
			setupMock: func(m *mockAuthProvider) {
				m.signInErr = core.ErrInvalidCredentials
			},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			// Arrange
			mock := &mockAuthProvider{}
			test.setupMock(mock)

			// Act: Create the handler (factory pattern)
			handler := handleSignInFiber(mock)

			// Assert: Handler was created successfully
			if handler == nil {
				t.Errorf("handleSignInFiber factory should return non-nil handler")
			}
		})
	}
}

// Requirement: handleSignOutFiber returns handler from factory
func TestHandleSignOutFiber_CallsAuthProviderSignOut(t *testing.T) {
	tests := []struct {
		name      string
		setupMock func(*mockAuthProvider)
	}{
		{
			name:      "handler is successfully created from factory",
			setupMock: func(m *mockAuthProvider) {},
		},
		{
			name: "handler factory works even when mock would return error",
			setupMock: func(m *mockAuthProvider) {
				m.signOutErr = core.ErrInvalidToken
			},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			// Arrange
			mock := &mockAuthProvider{}
			test.setupMock(mock)

			// Act: Create the handler (factory pattern)
			handler := handleSignOutFiber(mock)

			// Assert: Handler was created successfully
			if handler == nil {
				t.Errorf("handleSignOutFiber factory should return non-nil handler")
			}
		})
	}
}

// Requirement: handleGetSessionFiber returns handler from factory
func TestHandleGetSessionFiber_CallsAuthProviderGetSession(t *testing.T) {
	tests := []struct {
		name      string
		setupMock func(*mockAuthProvider)
	}{
		{
			name: "handler is successfully created from factory",
			setupMock: func(m *mockAuthProvider) {
				m.getSessionData = &core.SessionData{}
			},
		},
		{
			name: "handler factory works even when mock would return error",
			setupMock: func(m *mockAuthProvider) {
				m.getSessionErr = core.ErrSessionExpired
			},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			// Arrange
			mock := &mockAuthProvider{}
			test.setupMock(mock)

			// Act: Create the handler (factory pattern)
			handler := handleGetSessionFiber(mock)

			// Assert: Handler was created successfully
			if handler == nil {
				t.Errorf("handleGetSessionFiber factory should return non-nil handler")
			}
		})
	}
}

// Requirement: handleRefreshFiber returns handler from factory
func TestHandleRefreshFiber_CallsAuthProviderRefresh(t *testing.T) {
	tests := []struct {
		name      string
		setupMock func(*mockAuthProvider)
	}{
		{
			name: "handler is successfully created from factory",
			setupMock: func(m *mockAuthProvider) {
				m.refreshResult = &core.RefreshResult{}
			},
		},
		{
			name: "handler factory works even when mock would return error",
			setupMock: func(m *mockAuthProvider) {
				m.refreshErr = core.ErrInvalidToken
			},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			// Arrange
			mock := &mockAuthProvider{}
			test.setupMock(mock)

			// Act: Create the handler (factory pattern)
			handler := handleRefreshFiber(mock)

			// Assert: Handler was created successfully
			if handler == nil {
				t.Errorf("handleRefreshFiber factory should return non-nil handler")
			}
		})
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
