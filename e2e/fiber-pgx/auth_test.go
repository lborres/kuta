package e2e

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lborres/kuta/core"
)

var (
	baseURL string
	client  *http.Client
	counter atomic.Uint64
)

// Test endpoints
const (
	signUpEndpoint    = "/api/auth/sign-up"
	signInEndpoint    = "/api/auth/sign-in"
	signOutEndpoint   = "/api/auth/sign-out"
	sessionEndpoint   = "/api/auth/session"
	refreshEndpoint   = "/api/auth/refresh"
	protectedEndpoint = "/api/protected"
)

// TestMain sets up a single E2E server for all tests in this file
func TestMain(m *testing.M) {
	// Setup: Start PostgreSQL container, create schema, start HTTP server
	log.Println("Setting up E2E test environment...")

	// Create a testing.T for logging during setup
	setupT := &testing.T{}
	var cleanup func()
	baseURL, cleanup = setupE2EServer(setupT)

	if baseURL == "" {
		log.Fatal("Failed to setup E2E server")
	}

	client = &http.Client{Timeout: 5 * time.Second}
	log.Printf("E2E server ready at %s\n", baseURL)

	// Run all tests
	exitCode := m.Run()

	// Cleanup
	log.Println("Cleaning up E2E test environment...")
	cleanup()

	os.Exit(exitCode)
}

// uniqueEmail generates a unique email for each test to avoid conflicts
func uniqueEmail(prefix string) string {
	n := counter.Add(1)
	return fmt.Sprintf("%s-%d@example.com", prefix, n)
}

// testUser creates and returns a new user via sign-up
func testUser(t *testing.T, email, password, name string) (token string, user *core.User) {
	signUpBody, _ := json.Marshal(map[string]string{
		"email":    email,
		"password": password,
		"name":     name,
	})

	resp, err := client.Post(baseURL+signUpEndpoint, "application/json", bytes.NewReader(signUpBody))
	if err != nil {
		t.Fatalf("sign-up request failed: %v", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 201 {
		t.Fatalf("sign-up failed with status %d: %s", resp.StatusCode, string(respBody))
	}

	var result core.SignUpResult
	if err := json.Unmarshal(respBody, &result); err != nil {
		t.Fatalf("failed to decode sign-up response: %v", err)
	}

	return result.Token, result.User
}

// signInUser signs in with credentials and returns token
func signInUser(t *testing.T, email, password string) string {
	signInBody, _ := json.Marshal(map[string]string{
		"email":    email,
		"password": password,
	})

	resp, err := client.Post(baseURL+signInEndpoint, "application/json", bytes.NewReader(signInBody))
	if err != nil {
		t.Fatalf("sign-in request failed: %v", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		t.Fatalf("sign-in failed with status %d: %s", resp.StatusCode, string(respBody))
	}

	var result core.SignInResult
	if err := json.Unmarshal(respBody, &result); err != nil {
		t.Fatalf("failed to decode sign-in response: %v", err)
	}

	return result.Token
}

// makeAuthRequest makes an authenticated HTTP request with Bearer token
func makeAuthRequest(t *testing.T, method, endpoint string, token string, body io.Reader) *http.Response {
	req, _ := http.NewRequest(method, baseURL+endpoint, body)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("%s %s request failed: %v", method, endpoint, err)
	}

	return resp
}

// makeAuthRequestExpectStatus makes a request and asserts the status code
func makeAuthRequestExpectStatus(t *testing.T, method, endpoint string, token string, expectedStatus int) []byte {
	resp := makeAuthRequest(t, method, endpoint, token, nil)
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != expectedStatus {
		t.Fatalf("expected status %d; got %d. Response: %s", expectedStatus, resp.StatusCode, string(respBody))
	}

	return respBody
}

// Requirement: E2E sign-up creates user in real PostgreSQL database
func TestE2E_SignUp_CreatesUserInDatabase(t *testing.T) {
	email := uniqueEmail("testuser")
	password := "SecurePass123!"
	name := "Test User"

	token, user := testUser(t, email, password, name)

	if user.Email != email {
		t.Errorf("expected email %s; got %s", email, user.Email)
	}
	if user.Name != name {
		t.Errorf("expected name %q; got %q", name, user.Name)
	}
	if token == "" {
		t.Error("expected token to be returned")
	}

	t.Logf("User created: ID=%s, Email=%s", user.ID, user.Email)
}

// Requirement: E2E sign-in authenticates user with valid credentials and returns session token
func TestE2E_SignIn_AuthenticatesUser(t *testing.T) {
	email := uniqueEmail("signin")
	password := "SecurePass123!"

	// Arrange: Create user
	_, _ = testUser(t, email, password, "SignIn User")

	// Act: Sign in
	token := signInUser(t, email, password)

	// Assert
	if token == "" {
		t.Error("expected token to be returned")
	}
}

// Requirement: E2E sign-in returns error for invalid credentials
func TestE2E_SignIn_InvalidCredentials(t *testing.T) {
	validEmail := uniqueEmail("valid")
	validPassword := "CorrectPass1!"

	// Create a valid user for wrong password test
	testUser(t, validEmail, validPassword, "Test User")

	tests := []struct {
		name     string
		email    string
		password string
		wantCode int
	}{
		{name: "returns error for non-existent user", email: "nonexistent@example.com", password: "Password123!", wantCode: 401},
		{name: "returns error for wrong password", email: validEmail, password: "WrongPass1!", wantCode: 401},
		{name: "returns error for empty email", email: "", password: "Password123!", wantCode: 400},
		{name: "returns error for empty password", email: validEmail, password: "", wantCode: 400},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			signInBody, _ := json.Marshal(map[string]string{
				"email":    test.email,
				"password": test.password,
			})

			resp, err := client.Post(baseURL+signInEndpoint, "application/json", bytes.NewReader(signInBody))
			if err != nil {
				t.Fatalf("sign-in request failed: %v", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != test.wantCode {
				respBody, _ := io.ReadAll(resp.Body)
				t.Fatalf("expected status %d; got %d. Response: %s", test.wantCode, resp.StatusCode, string(respBody))
			}
		})
	}
}

// Requirement: E2E sign-out invalidates session
func TestE2E_SignOut_InvalidatesSession(t *testing.T) {
	email := uniqueEmail("signout")
	password := "SecurePass123!"

	token, _ := testUser(t, email, password, "SignOut User")

	// Act: Sign out
	makeAuthRequestExpectStatus(t, "POST", signOutEndpoint, token, 200)

	// Assert: Token no longer valid
	resp := makeAuthRequest(t, "GET", sessionEndpoint, token, nil)
	resp.Body.Close()

	if resp.StatusCode != 401 {
		t.Errorf("expected 401 after sign-out; got %d", resp.StatusCode)
	}
}

// Requirement: E2E get session returns user and session data
func TestE2E_GetSession_ReturnsSessionData(t *testing.T) {
	email := uniqueEmail("session")
	password := "SecurePass123!"

	token, _ := testUser(t, email, password, "Session User")

	// Act: Get session
	respBody := makeAuthRequestExpectStatus(t, "GET", sessionEndpoint, token, 200)

	// Assert
	var sessionData core.SessionData
	if err := json.Unmarshal(respBody, &sessionData); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if sessionData.User == nil {
		t.Fatal("expected user in session data")
	}
	if sessionData.User.Email != email {
		t.Errorf("expected email %s; got %s", email, sessionData.User.Email)
	}
	if sessionData.Session == nil {
		t.Fatal("expected session in session data")
	}

	t.Logf("Session retrieved: UserID=%s", sessionData.User.ID)
}

// Requirement: E2E get session returns 401 for invalid token
func TestE2E_GetSession_InvalidToken(t *testing.T) {
	tests := []struct {
		name  string
		token string
	}{
		{name: "returns 401 for missing token", token: ""},
		{name: "returns 401 for invalid token", token: "invalid-token"},
		{name: "returns 401 for malformed token", token: "malformed.jwt.token"},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			resp := makeAuthRequest(t, "GET", sessionEndpoint, test.token, nil)
			defer resp.Body.Close()

			if resp.StatusCode != 401 {
				respBody, _ := io.ReadAll(resp.Body)
				t.Fatalf("expected 401; got %d. Response: %s", resp.StatusCode, string(respBody))
			}
		})
	}
}

// Requirement: E2E refresh extends session with new token
func TestE2E_Refresh_ReturnsNewToken(t *testing.T) {
	email := uniqueEmail("refresh")
	password := "SecurePass123!"

	originalToken, _ := testUser(t, email, password, "Refresh User")

	// Act: Refresh token
	respBody := makeAuthRequestExpectStatus(t, "POST", refreshEndpoint, originalToken, 200)

	// Assert
	var refreshResult core.RefreshResult
	if err := json.Unmarshal(respBody, &refreshResult); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if refreshResult.Token == "" {
		t.Error("expected new token to be returned")
	}
	if refreshResult.Session == nil {
		t.Fatal("expected session in refresh result")
	}

	// Verify new token works
	resp := makeAuthRequest(t, "GET", sessionEndpoint, refreshResult.Token, nil)
	resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Errorf("expected new token to be valid; got status %d", resp.StatusCode)
	}
}

// Requirement: E2E protected route requires authentication
func TestE2E_ProtectedRoute_RequiresAuth(t *testing.T) {
	resp := makeAuthRequest(t, "GET", protectedEndpoint, "", nil)
	defer resp.Body.Close()

	if resp.StatusCode != 401 {
		respBody, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 401; got %d. Response: %s", resp.StatusCode, string(respBody))
	}
}

// Requirement: E2E protected route allows authenticated access
func TestE2E_ProtectedRoute_AllowsAuthenticatedAccess(t *testing.T) {
	email := uniqueEmail("protected")
	password := "SecurePass123!"

	token, _ := testUser(t, email, password, "Protected User")

	// Act: Access protected route with token
	respBody := makeAuthRequestExpectStatus(t, "GET", protectedEndpoint, token, 200)

	// Assert
	var result map[string]string
	if err := json.Unmarshal(respBody, &result); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if result["message"] != "protected route" {
		t.Errorf("expected message 'protected route'; got %s", result["message"])
	}
}

// Requirement: E2E sign-up prevents duplicate emails
func TestE2E_SignUp_PreventsDuplicateEmail(t *testing.T) {
	email := uniqueEmail("duplicate")
	password := "SecurePass123!"

	// Create first user
	testUser(t, email, password, "First User")

	// Try to create duplicate
	signUpBody, _ := json.Marshal(map[string]string{
		"email":    email,
		"password": "DifferentPass1!",
		"name":     "Second User",
	})
	resp, err := client.Post(baseURL+signUpEndpoint, "application/json", bytes.NewReader(signUpBody))
	if err != nil {
		t.Fatalf("sign-up request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 409 {
		respBody, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 409; got %d. Response: %s", resp.StatusCode, string(respBody))
	}
}

// Requirement: E2E sign-up validates email format
func TestE2E_SignUp_ValidatesEmailFormat(t *testing.T) {
	tests := []struct {
		name  string
		email string
	}{
		{name: "rejects invalid email format", email: "invalid-email"},
		{name: "rejects email without @", email: "nodomain.com"},
		{name: "rejects email without domain", email: "user@"},
		{name: "rejects empty email", email: ""},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			signUpBody, _ := json.Marshal(map[string]string{
				"email":    test.email,
				"password": "Password123!",
				"name":     "Test User",
			})

			resp, err := client.Post(baseURL+signUpEndpoint, "application/json", bytes.NewReader(signUpBody))
			if err != nil {
				t.Fatalf("sign-up request failed: %v", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != 400 {
				respBody, _ := io.ReadAll(resp.Body)
				t.Fatalf("expected 400; got %d. Response: %s", resp.StatusCode, string(respBody))
			}
		})
	}
}

// Requirement: E2E sign-up validates password length
func TestE2E_SignUp_ValidatesPasswordLength(t *testing.T) {
	tests := []struct {
		name     string
		password string
		wantCode int
	}{
		{name: "rejects password too short", password: "Short1!", wantCode: 400},
		{name: "rejects empty password", password: "", wantCode: 400},
		{name: "rejects password without uppercase", password: "nouppercase1!", wantCode: 400},
		{name: "rejects password without special char", password: "NoSpecial1", wantCode: 400},
		{name: "accepts valid password", password: "ValidPass1!", wantCode: 201},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			email := uniqueEmail("password-validation")
			signUpBody, _ := json.Marshal(map[string]string{
				"email":    email,
				"password": test.password,
				"name":     "Test User",
			})

			resp, err := client.Post(baseURL+signUpEndpoint, "application/json", bytes.NewReader(signUpBody))
			if err != nil {
				t.Fatalf("sign-up request failed: %v", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != test.wantCode {
				respBody, _ := io.ReadAll(resp.Body)
				t.Fatalf("expected %d; got %d. Response: %s", test.wantCode, resp.StatusCode, string(respBody))
			}
		})
	}
}

// Requirement: E2E sign-out requires valid authentication
func TestE2E_SignOut_RequiresAuthentication(t *testing.T) {
	tests := []struct {
		name  string
		token string
	}{
		{name: "returns 401 without token", token: ""},
		{name: "returns 401 with invalid token", token: "invalid-token"},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			resp := makeAuthRequest(t, "POST", signOutEndpoint, test.token, nil)
			defer resp.Body.Close()

			if resp.StatusCode != 401 {
				respBody, _ := io.ReadAll(resp.Body)
				t.Fatalf("expected 401; got %d. Response: %s", resp.StatusCode, string(respBody))
			}
		})
	}
}

// Requirement: E2E sign-out invalidates the session and cannot be repeated
func TestE2E_SignOut_CannotBeRepeatedWithSameToken(t *testing.T) {
	email := uniqueEmail("double-signout")
	token, _ := testUser(t, email, "SecurePass123!", "Double SignOut User")

	// Sign out first time
	makeAuthRequestExpectStatus(t, "POST", signOutEndpoint, token, 200)

	// Try to sign out again
	resp := makeAuthRequest(t, "POST", signOutEndpoint, token, nil)
	defer resp.Body.Close()

	if resp.StatusCode != 401 {
		respBody, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 401 on second sign-out; got %d. Response: %s", resp.StatusCode, string(respBody))
	}
}

// Requirement: E2E refresh without token returns 401
func TestE2E_Refresh_RequiresAuthentication(t *testing.T) {
	tests := []struct {
		name  string
		token string
	}{
		{name: "returns 401 without token", token: ""},
		{name: "returns 401 with invalid token", token: "invalid-token"},
		{name: "returns 401 with malformed token", token: "malformed.token.here"},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			resp := makeAuthRequest(t, "POST", refreshEndpoint, test.token, nil)
			defer resp.Body.Close()

			if resp.StatusCode != 401 {
				respBody, _ := io.ReadAll(resp.Body)
				t.Fatalf("expected 401; got %d. Response: %s", resp.StatusCode, string(respBody))
			}
		})
	}
}

// Requirement: E2E refresh with signed-out token returns 401
func TestE2E_Refresh_FailsAfterSignOut(t *testing.T) {
	email := uniqueEmail("refresh-after-signout")
	token, _ := testUser(t, email, "SecurePass123!", "Refresh Test User")

	// Sign out
	makeAuthRequestExpectStatus(t, "POST", signOutEndpoint, token, 200)

	// Try to refresh with signed-out token
	resp := makeAuthRequest(t, "POST", refreshEndpoint, token, nil)
	defer resp.Body.Close()

	if resp.StatusCode != 401 {
		respBody, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 401; got %d. Response: %s", resp.StatusCode, string(respBody))
	}
}

// Requirement: E2E protected route with invalid token returns 401
func TestE2E_ProtectedRoute_RejectsInvalidTokens(t *testing.T) {
	tests := []struct {
		name  string
		token string
	}{
		{name: "rejects empty token", token: ""},
		{name: "rejects invalid token", token: "invalid-token-12345"},
		{name: "rejects malformed token", token: "malformed.jwt.token"},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			resp := makeAuthRequest(t, "GET", protectedEndpoint, test.token, nil)
			defer resp.Body.Close()

			if resp.StatusCode != 401 {
				respBody, _ := io.ReadAll(resp.Body)
				t.Fatalf("expected 401; got %d. Response: %s", resp.StatusCode, string(respBody))
			}
		})
	}
}

// Requirement: E2E protected route with signed-out token returns 401
func TestE2E_ProtectedRoute_RejectsSignedOutToken(t *testing.T) {
	email := uniqueEmail("protected-signout")
	token, _ := testUser(t, email, "SecurePass123!", "Protected SignOut User")

	// Verify token works initially
	resp1 := makeAuthRequest(t, "GET", protectedEndpoint, token, nil)
	resp1.Body.Close()

	if resp1.StatusCode != 200 {
		t.Fatalf("initial access failed with status %d", resp1.StatusCode)
	}

	// Sign out
	makeAuthRequestExpectStatus(t, "POST", signOutEndpoint, token, 200)

	// Try to access protected route with signed-out token
	resp2 := makeAuthRequest(t, "GET", protectedEndpoint, token, nil)
	defer resp2.Body.Close()

	if resp2.StatusCode != 401 {
		respBody, _ := io.ReadAll(resp2.Body)
		t.Fatalf("expected 401; got %d. Response: %s", resp2.StatusCode, string(respBody))
	}
}

// Requirement: E2E multiple sessions for same user
func TestE2E_MultipleSessions_AllowedForSameUser(t *testing.T) {
	email := uniqueEmail("multi-session")
	password := "SecurePass123!"

	// Create user
	token1, _ := testUser(t, email, password, "Multi Session User")

	// Sign in again (simulate second device/browser)
	token2 := signInUser(t, email, password)

	// Assert: Both tokens should be different
	if token1 == token2 {
		t.Error("expected different tokens for multiple sessions")
	}

	// Assert: Both tokens should work
	for i, token := range []string{token1, token2} {
		resp := makeAuthRequest(t, "GET", sessionEndpoint, token, nil)
		resp.Body.Close()

		if resp.StatusCode != 200 {
			t.Errorf("token %d should be valid; got status %d", i+1, resp.StatusCode)
		}
	}
}

// --- Security Tests ---

// Requirement: E2E security - rejects SQL injection attempts in email field
func TestE2E_Security_RejectsSQLInjection(t *testing.T) {
	tests := []struct {
		name  string
		email string
	}{
		{name: "rejects SQL injection with quotes", email: "admin'--"},
		{name: "rejects SQL injection with UNION", email: "admin@example.com' UNION SELECT * FROM users--"},
		{name: "rejects SQL injection with DROP", email: "admin@example.com'; DROP TABLE users--"},
		{name: "rejects SQL injection with OR", email: "' OR '1'='1"},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			signUpBody, _ := json.Marshal(map[string]string{
				"email":    test.email,
				"password": "ValidPass1!",
				"name":     "Test User",
			})

			resp, err := client.Post(baseURL+signUpEndpoint, "application/json", bytes.NewReader(signUpBody))
			if err != nil {
				t.Fatalf("sign-up request failed: %v", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode == 201 {
				t.Errorf("SQL injection should be rejected; got status 201")
			}
		})
	}
}

// Requirement: E2E security - rejects XSS attempts in input fields
func TestE2E_Security_RejectsXSSAttempts(t *testing.T) {
	tests := []struct {
		name  string
		field string
		value string
	}{
		{name: "rejects XSS in name field", field: "name", value: "<script>alert('xss')</script>"},
		{name: "rejects XSS in email field", field: "email", value: "<img src=x onerror=alert(1)>@example.com"},
		{name: "rejects XSS with event handler", field: "name", value: "<div onload=alert('xss')>User</div>"},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			email := uniqueEmail("xss-test")
			data := map[string]string{
				"email":    email,
				"password": "ValidPass1!",
				"name":     "Normal User",
			}
			data[test.field] = test.value

			signUpBody, _ := json.Marshal(data)
			resp, err := client.Post(baseURL+signUpEndpoint, "application/json", bytes.NewReader(signUpBody))
			if err != nil {
				t.Fatalf("sign-up request failed: %v", err)
			}
			defer resp.Body.Close()

			// Should either reject (400) or sanitize the input
			if resp.StatusCode == 201 {
				respBody, _ := io.ReadAll(resp.Body)
				var result core.SignUpResult
				json.Unmarshal(respBody, &result)

				// Verify the dangerous input was sanitized or escaped
				if test.field == "name" && result.User.Name == test.value {
					t.Errorf("XSS payload was not sanitized in %s field", test.field)
				}
			}
		})
	}
}

// Requirement: E2E security - prevents token manipulation
func TestE2E_Security_PreventsTokenManipulation(t *testing.T) {
	email := uniqueEmail("token-manipulation")
	token, _ := testUser(t, email, "SecurePass123!", "Test User")

	tests := []struct {
		name            string
		manipulateToken func(string) string
	}{
		{name: "rejects truncated token", manipulateToken: func(t string) string { return t[:len(t)-5] }},
		{name: "rejects token with extra characters", manipulateToken: func(t string) string { return t + "xyz" }},
		{name: "rejects token with modified characters", manipulateToken: func(t string) string {
			if len(t) > 10 {
				return t[:10] + "X" + t[11:]
			}
			return t + "X"
		}},
		{name: "rejects reversed token", manipulateToken: func(t string) string {
			runes := []rune(t)
			for i, j := 0, len(runes)-1; i < j; i, j = i+1, j-1 {
				runes[i], runes[j] = runes[j], runes[i]
			}
			return string(runes)
		}},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			manipulatedToken := test.manipulateToken(token)
			resp := makeAuthRequest(t, "GET", sessionEndpoint, manipulatedToken, nil)
			defer resp.Body.Close()

			if resp.StatusCode != 401 {
				t.Errorf("manipulated token should be rejected; got status %d", resp.StatusCode)
			}
		})
	}
}

// Requirement: E2E security - enforces rate limiting on authentication endpoints
func TestE2E_Security_RateLimiting(t *testing.T) {
	email := uniqueEmail("rate-limit")
	password := "SecurePass123!"
	testUser(t, email, password, "Rate Limit User")

	// Simulate rapid authentication attempts
	const requestCount = 20
	var statusCodes []int

	for i := 0; i < requestCount; i++ {
		signInBody, _ := json.Marshal(map[string]string{
			"email":    email,
			"password": "WrongPassword1!",
		})

		resp, err := client.Post(baseURL+signInEndpoint, "application/json", bytes.NewReader(signInBody))
		if err != nil {
			t.Logf("Request %d failed: %v", i+1, err)
			continue
		}
		statusCodes = append(statusCodes, resp.StatusCode)
		resp.Body.Close()
	}

	// After many failed attempts, should receive 429 Too Many Requests
	rateLimited := false
	for _, code := range statusCodes {
		if code == 429 {
			rateLimited = true
			break
		}
	}

	if !rateLimited {
		t.Error("expected rate limiting after multiple failed attempts")
	}
}

// Requirement: E2E security - handles very long input strings
func TestE2E_Security_HandlesLongInputs(t *testing.T) {
	tests := []struct {
		name     string
		field    string
		length   int
		wantCode int
	}{
		{name: "rejects extremely long email", field: "email", length: 1000, wantCode: 400},
		{name: "rejects extremely long password", field: "password", length: 10000, wantCode: 400},
		{name: "rejects extremely long name", field: "name", length: 5000, wantCode: 400},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			longString := string(make([]byte, test.length))
			for i := range longString {
				longString = longString[:i] + "a" + longString[i+1:]
			}

			data := map[string]string{
				"email":    uniqueEmail("long-input"),
				"password": "ValidPass1!",
				"name":     "Test User",
			}

			if test.field == "email" {
				data["email"] = longString + "@example.com"
			} else {
				data[test.field] = longString
			}

			signUpBody, _ := json.Marshal(data)
			resp, err := client.Post(baseURL+signUpEndpoint, "application/json", bytes.NewReader(signUpBody))
			if err != nil {
				t.Fatalf("sign-up request failed: %v", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != test.wantCode {
				t.Errorf("expected status %d for long %s; got %d", test.wantCode, test.field, resp.StatusCode)
			}
		})
	}
}

// Requirement: E2E security - handles special characters safely
func TestE2E_Security_HandlesSpecialCharacters(t *testing.T) {
	tests := []struct {
		name     string
		userName string
		wantCode int
	}{
		{name: "accepts unicode characters", userName: "用户名", wantCode: 201},
		{name: "accepts emoji", userName: "User 😀", wantCode: 201},
		{name: "accepts special chars", userName: "O'Brien & Sons", wantCode: 201},
		{name: "accepts accented chars", userName: "José María", wantCode: 201},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			email := uniqueEmail("special-chars")
			signUpBody, _ := json.Marshal(map[string]string{
				"email":    email,
				"password": "ValidPass1!",
				"name":     test.userName,
			})

			resp, err := client.Post(baseURL+signUpEndpoint, "application/json", bytes.NewReader(signUpBody))
			if err != nil {
				t.Fatalf("sign-up request failed: %v", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != test.wantCode {
				respBody, _ := io.ReadAll(resp.Body)
				t.Errorf("expected %d; got %d. Response: %s", test.wantCode, resp.StatusCode, string(respBody))
			}

			if resp.StatusCode == 201 {
				respBody, _ := io.ReadAll(resp.Body)
				var result core.SignUpResult
				json.Unmarshal(respBody, &result)

				if result.User.Name != test.userName {
					t.Errorf("expected name %q; got %q", test.userName, result.User.Name)
				}
			}
		})
	}
}

// Requirement: E2E security - prevents concurrent session manipulation
func TestE2E_Security_PreventsConcurrentManipulation(t *testing.T) {
	email := uniqueEmail("concurrent")
	token, _ := testUser(t, email, "SecurePass123!", "Concurrent User")

	// Try to perform multiple operations concurrently
	done := make(chan bool, 3)

	// Goroutine 1: Try to refresh
	go func() {
		resp := makeAuthRequest(t, "POST", refreshEndpoint, token, nil)
		resp.Body.Close()
		done <- true
	}()

	// Goroutine 2: Try to sign out
	go func() {
		resp := makeAuthRequest(t, "POST", signOutEndpoint, token, nil)
		resp.Body.Close()
		done <- true
	}()

	// Goroutine 3: Try to get session
	go func() {
		resp := makeAuthRequest(t, "GET", sessionEndpoint, token, nil)
		resp.Body.Close()
		done <- true
	}()

	// Wait for all to complete
	for i := 0; i < 3; i++ {
		<-done
	}

	// Verify session state is consistent
	resp := makeAuthRequest(t, "GET", sessionEndpoint, token, nil)
	defer resp.Body.Close()

	// Should either be valid or invalid, not in an inconsistent state
	if resp.StatusCode != 200 && resp.StatusCode != 401 {
		t.Errorf("unexpected status code after concurrent operations: %d", resp.StatusCode)
	}
}

// Requirement: E2E security - rejects invalid Content-Type
func TestE2E_Security_ValidatesContentType(t *testing.T) {
	email := uniqueEmail("content-type")
	signUpBody, _ := json.Marshal(map[string]string{
		"email":    email,
		"password": "ValidPass1!",
		"name":     "Test User",
	})

	tests := []struct {
		name        string
		contentType string
		wantCode    int
	}{
		{name: "accepts application/json", contentType: "application/json", wantCode: 201},
		{name: "rejects text/plain", contentType: "text/plain", wantCode: 400},
		{name: "rejects application/x-www-form-urlencoded", contentType: "application/x-www-form-urlencoded", wantCode: 400},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			req, _ := http.NewRequest("POST", baseURL+signUpEndpoint, bytes.NewReader(signUpBody))
			req.Header.Set("Content-Type", test.contentType)

			resp, err := client.Do(req)
			if err != nil {
				t.Fatalf("request failed: %v", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != test.wantCode {
				t.Errorf("expected %d for Content-Type %s; got %d", test.wantCode, test.contentType, resp.StatusCode)
			}
		})
	}
}

// Requirement: E2E security - prevents password exposure in responses
func TestE2E_Security_NoPasswordInResponses(t *testing.T) {
	email := uniqueEmail("password-leak")
	password := "SecurePass123!"

	signUpBody, _ := json.Marshal(map[string]string{
		"email":    email,
		"password": password,
		"name":     "Test User",
	})

	resp, err := client.Post(baseURL+signUpEndpoint, "application/json", bytes.NewReader(signUpBody))
	if err != nil {
		t.Fatalf("sign-up request failed: %v", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	respStr := string(respBody)

	// Check if password appears anywhere in response
	if bytes.Contains(respBody, []byte(password)) {
		t.Errorf("password found in response body: %s", respStr)
	}

	// Also check sign-in response
	signInBody, _ := json.Marshal(map[string]string{
		"email":    email,
		"password": password,
	})

	resp2, err := client.Post(baseURL+signInEndpoint, "application/json", bytes.NewReader(signInBody))
	if err != nil {
		t.Fatalf("sign-in request failed: %v", err)
	}
	defer resp2.Body.Close()

	respBody2, _ := io.ReadAll(resp2.Body)
	if bytes.Contains(respBody2, []byte(password)) {
		t.Errorf("password found in sign-in response body")
	}
}

// Requirement: E2E security - rejects null bytes in input
func TestE2E_Security_RejectsNullBytes(t *testing.T) {
	tests := []struct {
		name  string
		email string
	}{
		{name: "rejects null byte in email", email: "user\x00@example.com"},
		{name: "rejects null byte at end", email: "user@example.com\x00"},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			signUpBody, _ := json.Marshal(map[string]string{
				"email":    test.email,
				"password": "ValidPass1!",
				"name":     "Test User",
			})

			resp, err := client.Post(baseURL+signUpEndpoint, "application/json", bytes.NewReader(signUpBody))
			if err != nil {
				t.Fatalf("sign-up request failed: %v", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode == 201 {
				t.Error("null byte in input should be rejected")
			}
		})
	}
}
