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

// Requirement: E2E sign-up creates user in real PostgreSQL database
func TestE2E_SignUp_CreatesUserInDatabase(t *testing.T) {
	email := uniqueEmail("testuser")

	signUpBody, _ := json.Marshal(map[string]string{
		"email":    email,
		"password": "SecurePass123!",
		"name":     "Test User",
	})

	resp, err := client.Post(
		baseURL+"/api/auth/sign-up",
		"application/json",
		bytes.NewReader(signUpBody),
	)
	if err != nil {
		t.Fatalf("sign-up request failed: %v", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("failed to read response body: %v", err)
	}

	if resp.StatusCode != 201 {
		t.Fatalf("expected status 201; got %d. Response: %s", resp.StatusCode, string(respBody))
	}

	var result core.SignUpResult
	if err := json.Unmarshal(respBody, &result); err != nil {
		t.Fatalf("failed to decode response: %v. Response body: %s", err, string(respBody))
	}

	if result.User.Email != email {
		t.Errorf("expected email %s; got %s", email, result.User.Email)
	}

	if result.User.Name != "Test User" {
		t.Errorf("expected name 'Test User'; got %s", result.User.Name)
	}

	if result.Token == "" {
		t.Error("expected token to be returned")
	}

	t.Logf("✅ User created in PostgreSQL: ID=%s, Email=%s, Token=%s",
		result.User.ID, result.User.Email, result.Token)
}

// Requirement: E2E sign-in authenticates user with valid credentials and returns session token
func TestE2E_SignIn_AuthenticatesUser(t *testing.T) {
	email := uniqueEmail("signin")
	password := "SecurePass123!"

	// Arrange: Create a user first via sign-up
	signUpBody, _ := json.Marshal(map[string]string{
		"email":    email,
		"password": password,
		"name":     "SignIn User",
	})

	signUpResp, err := client.Post(
		baseURL+"/api/auth/sign-up",
		"application/json",
		bytes.NewReader(signUpBody),
	)
	if err != nil {
		t.Fatalf("sign-up request failed: %v", err)
	}
	signUpResp.Body.Close()

	if signUpResp.StatusCode != 201 {
		t.Fatalf("sign-up failed with status %d", signUpResp.StatusCode)
	}

	// Act: Sign in with the created user
	signInBody, _ := json.Marshal(map[string]string{
		"email":    email,
		"password": password,
	})

	resp, err := client.Post(
		baseURL+"/api/auth/sign-in",
		"application/json",
		bytes.NewReader(signInBody),
	)
	if err != nil {
		t.Fatalf("sign-in request failed: %v", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("failed to read response body: %v", err)
	}

	// Assert: Verify successful sign-in
	if resp.StatusCode != 200 {
		t.Fatalf("expected status 200; got %d. Response: %s", resp.StatusCode, string(respBody))
	}

	var result core.SignInResult
	if err := json.Unmarshal(respBody, &result); err != nil {
		t.Fatalf("failed to decode response: %v. Response body: %s", err, string(respBody))
	}

	if result.User.Email != email {
		t.Errorf("expected email %s; got %s", email, result.User.Email)
	}

	if result.Token == "" {
		t.Error("expected token to be returned")
	}

	t.Logf("✅ User signed in: ID=%s, Email=%s, Token=%s",
		result.User.ID, result.User.Email, result.Token[:10]+"...")
}

// Requirement: E2E sign-in returns error for invalid credentials
func TestE2E_SignIn_InvalidCredentials(t *testing.T) {
	validEmail := uniqueEmail("valid")
	validPassword := "CorrectPass1!"

	// Create a valid user for wrong password test
	signUpBody, _ := json.Marshal(map[string]string{
		"email":    validEmail,
		"password": validPassword,
		"name":     "Test User",
	})
	signUpResp, _ := client.Post(baseURL+"/api/auth/sign-up", "application/json", bytes.NewReader(signUpBody))
	signUpResp.Body.Close()

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

			resp, err := client.Post(
				baseURL+"/api/auth/sign-in",
				"application/json",
				bytes.NewReader(signInBody),
			)
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

	// Arrange: Create a user and sign in
	signUpBody, _ := json.Marshal(map[string]string{
		"email":    email,
		"password": password,
		"name":     "SignOut User",
	})
	signUpResp, err := client.Post(baseURL+"/api/auth/sign-up", "application/json", bytes.NewReader(signUpBody))
	if err != nil {
		t.Fatalf("sign-up request failed: %v", err)
	}
	defer signUpResp.Body.Close()

	var signUpResult core.SignUpResult
	json.NewDecoder(signUpResp.Body).Decode(&signUpResult)
	token := signUpResult.Token

	// Act: Sign out with the token
	signOutReq, _ := http.NewRequest("POST", baseURL+"/api/auth/sign-out", nil)
	signOutReq.Header.Set("Authorization", "Bearer "+token)
	signOutResp, err := client.Do(signOutReq)
	if err != nil {
		t.Fatalf("sign-out request failed: %v", err)
	}
	defer signOutResp.Body.Close()

	// Assert: Sign-out succeeds
	if signOutResp.StatusCode != 200 {
		respBody, _ := io.ReadAll(signOutResp.Body)
		t.Fatalf("expected status 200; got %d. Response: %s", signOutResp.StatusCode, string(respBody))
	}

	// Assert: Token is no longer valid - session should fail
	sessionReq, _ := http.NewRequest("GET", baseURL+"/api/auth/session", nil)
	sessionReq.Header.Set("Authorization", "Bearer "+token)
	sessionResp, err := client.Do(sessionReq)
	if err != nil {
		t.Fatalf("session request failed: %v", err)
	}
	defer sessionResp.Body.Close()

	if sessionResp.StatusCode != 401 {
		t.Errorf("expected status 401 after sign-out; got %d", sessionResp.StatusCode)
	}

	t.Log("✅ Session invalidated after sign-out")
}

// Requirement: E2E get session returns user and session data
func TestE2E_GetSession_ReturnsSessionData(t *testing.T) {
	email := uniqueEmail("session")
	password := "SecurePass123!"

	// Arrange: Create a user and get token
	signUpBody, _ := json.Marshal(map[string]string{
		"email":    email,
		"password": password,
		"name":     "Session User",
	})
	signUpResp, err := client.Post(baseURL+"/api/auth/sign-up", "application/json", bytes.NewReader(signUpBody))
	if err != nil {
		t.Fatalf("sign-up request failed: %v", err)
	}
	defer signUpResp.Body.Close()

	var signUpResult core.SignUpResult
	json.NewDecoder(signUpResp.Body).Decode(&signUpResult)
	token := signUpResult.Token

	// Act: Get session
	sessionReq, _ := http.NewRequest("GET", baseURL+"/api/auth/session", nil)
	sessionReq.Header.Set("Authorization", "Bearer "+token)
	resp, err := client.Do(sessionReq)
	if err != nil {
		t.Fatalf("session request failed: %v", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)

	// Assert
	if resp.StatusCode != 200 {
		t.Fatalf("expected status 200; got %d. Response: %s", resp.StatusCode, string(respBody))
	}

	var sessionData core.SessionData
	if err := json.Unmarshal(respBody, &sessionData); err != nil {
		t.Fatalf("failed to decode response: %v. Response body: %s", err, string(respBody))
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

	t.Logf("✅ Session retrieved: UserID=%s, SessionID=%s", sessionData.User.ID, sessionData.Session.ID)
}

// Requirement: E2E get session returns 401 for invalid token
func TestE2E_GetSession_InvalidToken(t *testing.T) {
	tests := []struct {
		name     string
		token    string
		wantCode int
	}{
		{name: "returns 401 for missing token", token: "", wantCode: 401},
		{name: "returns 401 for invalid token", token: "invalid-token", wantCode: 401},
		{name: "returns 401 for malformed token", token: "Bearer malformed", wantCode: 401},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			sessionReq, _ := http.NewRequest("GET", baseURL+"/api/auth/session", nil)
			if test.token != "" {
				sessionReq.Header.Set("Authorization", "Bearer "+test.token)
			}
			resp, err := client.Do(sessionReq)
			if err != nil {
				t.Fatalf("session request failed: %v", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != test.wantCode {
				respBody, _ := io.ReadAll(resp.Body)
				t.Fatalf("expected status %d; got %d. Response: %s", test.wantCode, resp.StatusCode, string(respBody))
			}
		})
	}
}

// Requirement: E2E refresh extends session with new token
func TestE2E_Refresh_ReturnsNewToken(t *testing.T) {
	email := uniqueEmail("refresh")
	password := "SecurePass123!"

	// Arrange: Create a user and get token
	signUpBody, _ := json.Marshal(map[string]string{
		"email":    email,
		"password": password,
		"name":     "Refresh User",
	})
	signUpResp, err := client.Post(baseURL+"/api/auth/sign-up", "application/json", bytes.NewReader(signUpBody))
	if err != nil {
		t.Fatalf("sign-up request failed: %v", err)
	}
	defer signUpResp.Body.Close()

	var signUpResult core.SignUpResult
	json.NewDecoder(signUpResp.Body).Decode(&signUpResult)
	originalToken := signUpResult.Token

	// Act: Refresh token
	refreshReq, _ := http.NewRequest("POST", baseURL+"/api/auth/refresh", nil)
	refreshReq.Header.Set("Authorization", "Bearer "+originalToken)
	resp, err := client.Do(refreshReq)
	if err != nil {
		t.Fatalf("refresh request failed: %v", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)

	// Assert
	if resp.StatusCode != 200 {
		t.Fatalf("expected status 200; got %d. Response: %s", resp.StatusCode, string(respBody))
	}

	var refreshResult core.RefreshResult
	if err := json.Unmarshal(respBody, &refreshResult); err != nil {
		t.Fatalf("failed to decode response: %v. Response body: %s", err, string(respBody))
	}

	if refreshResult.Token == "" {
		t.Error("expected new token to be returned")
	}

	if refreshResult.Session == nil {
		t.Fatal("expected session in refresh result")
	}

	// Verify new token works
	sessionReq, _ := http.NewRequest("GET", baseURL+"/api/auth/session", nil)
	sessionReq.Header.Set("Authorization", "Bearer "+refreshResult.Token)
	sessionResp, err := client.Do(sessionReq)
	if err != nil {
		t.Fatalf("session request failed: %v", err)
	}
	defer sessionResp.Body.Close()

	if sessionResp.StatusCode != 200 {
		t.Errorf("expected new token to be valid; got status %d", sessionResp.StatusCode)
	}

	t.Logf("✅ Token refreshed: SessionID=%s, NewToken=%s...", refreshResult.Session.ID, refreshResult.Token[:10])
}

// Requirement: E2E protected route requires authentication
func TestE2E_ProtectedRoute_RequiresAuth(t *testing.T) {
	// Act: Access protected route without token
	resp, err := client.Get(baseURL + "/api/protected")
	if err != nil {
		t.Fatalf("protected request failed: %v", err)
	}
	defer resp.Body.Close()

	// Assert: Returns 401
	if resp.StatusCode != 401 {
		respBody, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected status 401; got %d. Response: %s", resp.StatusCode, string(respBody))
	}

	t.Log("✅ Protected route returns 401 without authentication")
}

// Requirement: E2E protected route allows authenticated access
func TestE2E_ProtectedRoute_AllowsAuthenticatedAccess(t *testing.T) {
	email := uniqueEmail("protected")
	password := "SecurePass123!"

	// Arrange: Create a user and get token
	signUpBody, _ := json.Marshal(map[string]string{
		"email":    email,
		"password": password,
		"name":     "Protected User",
	})
	signUpResp, err := client.Post(baseURL+"/api/auth/sign-up", "application/json", bytes.NewReader(signUpBody))
	if err != nil {
		t.Fatalf("sign-up request failed: %v", err)
	}
	defer signUpResp.Body.Close()

	var signUpResult core.SignUpResult
	json.NewDecoder(signUpResp.Body).Decode(&signUpResult)
	token := signUpResult.Token

	// Act: Access protected route with token
	protectedReq, _ := http.NewRequest("GET", baseURL+"/api/protected", nil)
	protectedReq.Header.Set("Authorization", "Bearer "+token)
	resp, err := client.Do(protectedReq)
	if err != nil {
		t.Fatalf("protected request failed: %v", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)

	// Assert: Returns 200
	if resp.StatusCode != 200 {
		t.Fatalf("expected status 200; got %d. Response: %s", resp.StatusCode, string(respBody))
	}

	var result map[string]string
	if err := json.Unmarshal(respBody, &result); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if result["message"] != "protected route" {
		t.Errorf("expected message 'protected route'; got %s", result["message"])
	}

	t.Log("✅ Protected route accessible with valid token")
}

// Requirement: E2E sign-up prevents duplicate emails
func TestE2E_SignUp_PreventsDuplicateEmail(t *testing.T) {
	email := uniqueEmail("duplicate")
	password := "SecurePass123!"

	// Arrange: Create a user first
	signUpBody, _ := json.Marshal(map[string]string{
		"email":    email,
		"password": password,
		"name":     "First User",
	})
	firstResp, err := client.Post(baseURL+"/api/auth/sign-up", "application/json", bytes.NewReader(signUpBody))
	if err != nil {
		t.Fatalf("first sign-up request failed: %v", err)
	}
	firstResp.Body.Close()

	if firstResp.StatusCode != 201 {
		t.Fatalf("first sign-up failed with status %d", firstResp.StatusCode)
	}

	// Act: Try to create another user with the same email
	duplicateBody, _ := json.Marshal(map[string]string{
		"email":    email,
		"password": "DifferentPass1!",
		"name":     "Second User",
	})
	resp, err := client.Post(baseURL+"/api/auth/sign-up", "application/json", bytes.NewReader(duplicateBody))
	if err != nil {
		t.Fatalf("duplicate sign-up request failed: %v", err)
	}
	defer resp.Body.Close()

	// Assert: Returns 409 Conflict
	if resp.StatusCode != 409 {
		respBody, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected status 409; got %d. Response: %s", resp.StatusCode, string(respBody))
	}

	t.Log("✅ Duplicate email registration prevented")
}

// Requirement: E2E sign-up validates email format
func TestE2E_SignUp_ValidatesEmailFormat(t *testing.T) {
	tests := []struct {
		name     string
		email    string
		password string
		wantCode int
	}{
		{name: "rejects invalid email format", email: "invalid-email", password: "Password123!", wantCode: 400},
		{name: "rejects email without @", email: "nodomain.com", password: "Password123!", wantCode: 400},
		{name: "rejects email without domain", email: "user@", password: "Password123!", wantCode: 400},
		{name: "rejects empty email", email: "", password: "Password123!", wantCode: 400},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			signUpBody, _ := json.Marshal(map[string]string{
				"email":    test.email,
				"password": test.password,
				"name":     "Test User",
			})

			resp, err := client.Post(baseURL+"/api/auth/sign-up", "application/json", bytes.NewReader(signUpBody))
			if err != nil {
				t.Fatalf("sign-up request failed: %v", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != test.wantCode {
				respBody, _ := io.ReadAll(resp.Body)
				t.Fatalf("expected status %d; got %d. Response: %s", test.wantCode, resp.StatusCode, string(respBody))
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
			email := uniqueEmail("password-validation") // Generate unique email per test
			signUpBody, _ := json.Marshal(map[string]string{
				"email":    email,
				"password": test.password,
				"name":     "Test User",
			})

			resp, err := client.Post(baseURL+"/api/auth/sign-up", "application/json", bytes.NewReader(signUpBody))
			if err != nil {
				t.Fatalf("sign-up request failed: %v", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != test.wantCode {
				respBody, _ := io.ReadAll(resp.Body)
				t.Fatalf("expected status %d; got %d. Response: %s", test.wantCode, resp.StatusCode, string(respBody))
			}
		})
	}
}

// Requirement: E2E sign-out requires valid authentication
func TestE2E_SignOut_RequiresAuthentication(t *testing.T) {
	tests := []struct {
		name     string
		token    string
		wantCode int
	}{
		{name: "returns 401 without token", token: "", wantCode: 401},
		{name: "returns 401 with invalid token", token: "invalid-token", wantCode: 401},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			signOutReq, _ := http.NewRequest("POST", baseURL+"/api/auth/sign-out", nil)
			if test.token != "" {
				signOutReq.Header.Set("Authorization", "Bearer "+test.token)
			}
			resp, err := client.Do(signOutReq)
			if err != nil {
				t.Fatalf("sign-out request failed: %v", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != test.wantCode {
				respBody, _ := io.ReadAll(resp.Body)
				t.Fatalf("expected status %d; got %d. Response: %s", test.wantCode, resp.StatusCode, string(respBody))
			}
		})
	}
}

// Requirement: E2E sign-out invalidates the session and cannot be repeated
func TestE2E_SignOut_CannotBeRepeatedWithSameToken(t *testing.T) {
	email := uniqueEmail("double-signout")
	password := "SecurePass123!"

	// Arrange: Create user and get token
	signUpBody, _ := json.Marshal(map[string]string{
		"email":    email,
		"password": password,
		"name":     "Double SignOut User",
	})
	signUpResp, err := client.Post(baseURL+"/api/auth/sign-up", "application/json", bytes.NewReader(signUpBody))
	if err != nil {
		t.Fatalf("sign-up request failed: %v", err)
	}
	defer signUpResp.Body.Close()

	var signUpResult core.SignUpResult
	json.NewDecoder(signUpResp.Body).Decode(&signUpResult)
	token := signUpResult.Token

	// Act: Sign out first time
	signOutReq1, _ := http.NewRequest("POST", baseURL+"/api/auth/sign-out", nil)
	signOutReq1.Header.Set("Authorization", "Bearer "+token)
	signOutResp1, _ := client.Do(signOutReq1)
	signOutResp1.Body.Close()

	if signOutResp1.StatusCode != 200 {
		t.Fatalf("first sign-out failed with status %d", signOutResp1.StatusCode)
	}

	// Act: Try to sign out again with same token
	signOutReq2, _ := http.NewRequest("POST", baseURL+"/api/auth/sign-out", nil)
	signOutReq2.Header.Set("Authorization", "Bearer "+token)
	signOutResp2, err := client.Do(signOutReq2)
	if err != nil {
		t.Fatalf("second sign-out request failed: %v", err)
	}
	defer signOutResp2.Body.Close()

	// Assert: Second sign-out should fail (session is gone)
	if signOutResp2.StatusCode != 401 {
		respBody, _ := io.ReadAll(signOutResp2.Body)
		t.Fatalf("expected status 401 for second sign-out (session already invalidated); got %d. Response: %s", signOutResp2.StatusCode, string(respBody))
	}

	t.Log("✅ Sign-out invalidates session - cannot be repeated")
}

// Requirement: E2E refresh without token returns 401
func TestE2E_Refresh_RequiresAuthentication(t *testing.T) {
	tests := []struct {
		name     string
		token    string
		wantCode int
	}{
		{name: "returns 401 without token", token: "", wantCode: 401},
		{name: "returns 401 with invalid token", token: "invalid-token", wantCode: 401},
		{name: "returns 401 with malformed token", token: "malformed.token.here", wantCode: 401},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			refreshReq, _ := http.NewRequest("POST", baseURL+"/api/auth/refresh", nil)
			if test.token != "" {
				refreshReq.Header.Set("Authorization", "Bearer "+test.token)
			}
			resp, err := client.Do(refreshReq)
			if err != nil {
				t.Fatalf("refresh request failed: %v", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != test.wantCode {
				respBody, _ := io.ReadAll(resp.Body)
				t.Fatalf("expected status %d; got %d. Response: %s", test.wantCode, resp.StatusCode, string(respBody))
			}
		})
	}
}

// Requirement: E2E refresh with signed-out token returns 401
func TestE2E_Refresh_FailsAfterSignOut(t *testing.T) {
	email := uniqueEmail("refresh-after-signout")
	password := "SecurePass123!"

	// Arrange: Create user and get token
	signUpBody, _ := json.Marshal(map[string]string{
		"email":    email,
		"password": password,
		"name":     "Refresh Test User",
	})
	signUpResp, err := client.Post(baseURL+"/api/auth/sign-up", "application/json", bytes.NewReader(signUpBody))
	if err != nil {
		t.Fatalf("sign-up request failed: %v", err)
	}
	defer signUpResp.Body.Close()

	var signUpResult core.SignUpResult
	json.NewDecoder(signUpResp.Body).Decode(&signUpResult)
	token := signUpResult.Token

	// Act: Sign out
	signOutReq, _ := http.NewRequest("POST", baseURL+"/api/auth/sign-out", nil)
	signOutReq.Header.Set("Authorization", "Bearer "+token)
	signOutResp, _ := client.Do(signOutReq)
	signOutResp.Body.Close()

	// Act: Try to refresh with signed-out token
	refreshReq, _ := http.NewRequest("POST", baseURL+"/api/auth/refresh", nil)
	refreshReq.Header.Set("Authorization", "Bearer "+token)
	resp, err := client.Do(refreshReq)
	if err != nil {
		t.Fatalf("refresh request failed: %v", err)
	}
	defer resp.Body.Close()

	// Assert: Refresh should fail
	if resp.StatusCode != 401 {
		respBody, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected status 401; got %d. Response: %s", resp.StatusCode, string(respBody))
	}

	t.Log("✅ Refresh properly rejected after sign-out")
}

// Requirement: E2E protected route with invalid token returns 401
func TestE2E_ProtectedRoute_RejectsInvalidTokens(t *testing.T) {
	tests := []struct {
		name     string
		token    string
		wantCode int
	}{
		{name: "rejects empty token", token: "", wantCode: 401},
		{name: "rejects invalid token", token: "invalid-token-12345", wantCode: 401},
		{name: "rejects malformed token", token: "malformed.jwt.token", wantCode: 401},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			protectedReq, _ := http.NewRequest("GET", baseURL+"/api/protected", nil)
			if test.token != "" {
				protectedReq.Header.Set("Authorization", "Bearer "+test.token)
			}
			resp, err := client.Do(protectedReq)
			if err != nil {
				t.Fatalf("protected request failed: %v", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != test.wantCode {
				respBody, _ := io.ReadAll(resp.Body)
				t.Fatalf("expected status %d; got %d. Response: %s", test.wantCode, resp.StatusCode, string(respBody))
			}
		})
	}
}

// Requirement: E2E protected route with signed-out token returns 401
func TestE2E_ProtectedRoute_RejectsSignedOutToken(t *testing.T) {
	email := uniqueEmail("protected-signout")
	password := "SecurePass123!"

	// Arrange: Create user and get token
	signUpBody, _ := json.Marshal(map[string]string{
		"email":    email,
		"password": password,
		"name":     "Protected SignOut User",
	})
	signUpResp, err := client.Post(baseURL+"/api/auth/sign-up", "application/json", bytes.NewReader(signUpBody))
	if err != nil {
		t.Fatalf("sign-up request failed: %v", err)
	}
	defer signUpResp.Body.Close()

	var signUpResult core.SignUpResult
	json.NewDecoder(signUpResp.Body).Decode(&signUpResult)
	token := signUpResult.Token

	// Verify token works initially
	protectedReq1, _ := http.NewRequest("GET", baseURL+"/api/protected", nil)
	protectedReq1.Header.Set("Authorization", "Bearer "+token)
	protectedResp1, _ := client.Do(protectedReq1)
	protectedResp1.Body.Close()

	if protectedResp1.StatusCode != 200 {
		t.Fatalf("initial protected access failed with status %d", protectedResp1.StatusCode)
	}

	// Act: Sign out
	signOutReq, _ := http.NewRequest("POST", baseURL+"/api/auth/sign-out", nil)
	signOutReq.Header.Set("Authorization", "Bearer "+token)
	signOutResp, _ := client.Do(signOutReq)
	signOutResp.Body.Close()

	// Act: Try to access protected route with signed-out token
	protectedReq2, _ := http.NewRequest("GET", baseURL+"/api/protected", nil)
	protectedReq2.Header.Set("Authorization", "Bearer "+token)
	resp, err := client.Do(protectedReq2)
	if err != nil {
		t.Fatalf("protected request failed: %v", err)
	}
	defer resp.Body.Close()

	// Assert: Should be rejected
	if resp.StatusCode != 401 {
		respBody, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected status 401; got %d. Response: %s", resp.StatusCode, string(respBody))
	}

	t.Log("✅ Protected route properly rejects signed-out token")
}

// Requirement: E2E multiple sessions for same user
func TestE2E_MultipleSessions_AllowedForSameUser(t *testing.T) {
	email := uniqueEmail("multi-session")
	password := "SecurePass123!"

	// Arrange: Create user
	signUpBody, _ := json.Marshal(map[string]string{
		"email":    email,
		"password": password,
		"name":     "Multi Session User",
	})
	signUpResp, err := client.Post(baseURL+"/api/auth/sign-up", "application/json", bytes.NewReader(signUpBody))
	if err != nil {
		t.Fatalf("sign-up request failed: %v", err)
	}
	defer signUpResp.Body.Close()

	var signUpResult core.SignUpResult
	json.NewDecoder(signUpResp.Body).Decode(&signUpResult)
	token1 := signUpResult.Token

	// Act: Sign in again (simulate second device/browser)
	signInBody, _ := json.Marshal(map[string]string{
		"email":    email,
		"password": password,
	})
	signInResp, err := client.Post(baseURL+"/api/auth/sign-in", "application/json", bytes.NewReader(signInBody))
	if err != nil {
		t.Fatalf("sign-in request failed: %v", err)
	}
	defer signInResp.Body.Close()

	var signInResult core.SignInResult
	json.NewDecoder(signInResp.Body).Decode(&signInResult)
	token2 := signInResult.Token

	// Assert: Both tokens should be different
	if token1 == token2 {
		t.Error("expected different tokens for multiple sessions")
	}

	// Assert: Both tokens should work
	for i, token := range []string{token1, token2} {
		sessionReq, _ := http.NewRequest("GET", baseURL+"/api/auth/session", nil)
		sessionReq.Header.Set("Authorization", "Bearer "+token)
		resp, err := client.Do(sessionReq)
		if err != nil {
			t.Fatalf("session request %d failed: %v", i+1, err)
		}
		resp.Body.Close()

		if resp.StatusCode != 200 {
			t.Errorf("token %d should be valid; got status %d", i+1, resp.StatusCode)
		}
	}

	t.Logf("✅ Multiple sessions created successfully")
}
