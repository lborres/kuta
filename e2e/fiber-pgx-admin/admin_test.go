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
	"github.com/lborres/kuta/plugins/admin"
)

var (
	baseURL string
	client  *http.Client
	counter atomic.Uint64
)

func TestMain(m *testing.M) {
	log.Println("Setting up E2E test environment with admin plugin...")

	setupT := &testing.T{}
	var cleanup func()
	baseURL, cleanup = setupE2EServerWithAdmin(setupT)

	if baseURL == "" {
		log.Fatal("Failed to setup E2E server")
	}

	client = &http.Client{Timeout: 5 * time.Second}
	log.Printf("E2E server ready at %s\n", baseURL)

	exitCode := m.Run()

	log.Println("Cleaning up E2E test environment...")
	cleanup()

	os.Exit(exitCode)
}

func uniqueEmail(prefix string) string {
	n := counter.Add(1)
	return fmt.Sprintf("%s-%d@example.com", prefix, n)
}

type authResponse struct {
	User    *core.User    `json:"user"`
	Session *core.Session `json:"session"`
	Token   string        `json:"token"`
}

type adminUserResponse struct {
	admin.UserWithRole
}

// createUser is a helper to sign up a new user and return the auth token
func createUser(t *testing.T, email, password, name string) (string, *core.User) {
	signUpBody, _ := json.Marshal(map[string]string{
		"email":    email,
		"password": password,
		"name":     name,
	})

	resp, err := client.Post(
		baseURL+"/api/auth/sign-up",
		"application/json",
		bytes.NewReader(signUpBody),
	)
	if err != nil {
		t.Fatalf("sign-up failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("sign-up returned %d: %s", resp.StatusCode, body)
	}

	var authResp authResponse
	if err := json.NewDecoder(resp.Body).Decode(&authResp); err != nil {
		t.Fatalf("failed to decode sign-up response: %v", err)
	}

	return authResp.Token, authResp.User
}

// setUserRole is a helper to set a user's role directly in the database
func setUserRole(t *testing.T, adminToken, targetUserID, role string) {
	reqBody, _ := json.Marshal(map[string]string{
		"userId": targetUserID,
		"role":   role,
	})

	req, _ := http.NewRequest("POST", baseURL+"/api/auth/admin/set-role", bytes.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+adminToken)

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("set-role request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Logf("set-role returned %d: %s", resp.StatusCode, body)
	}
}

// TestE2E_AdminPlugin_SetRole tests setting a user's role
func TestE2E_AdminPlugin_SetRole(t *testing.T) {
	// Create admin user
	adminEmail := uniqueEmail("admin")
	adminToken, adminUser := createUser(t, adminEmail, "AdminPass123!", "Admin User")

	// Create regular user
	userEmail := uniqueEmail("user")
	_, regularUser := createUser(t, userEmail, "UserPass123!", "Regular User")

	// Set admin role for the admin user
	setUserRole(t, adminToken, adminUser.ID, "admin")

	// Admin sets regular user's role to moderator
	reqBody, _ := json.Marshal(map[string]string{
		"userId": regularUser.ID,
		"role":   "moderator",
	})

	req, _ := http.NewRequest("POST", baseURL+"/api/auth/admin/set-role", bytes.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+adminToken)

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("set-role request failed: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", resp.StatusCode, body)
	}

	var result adminUserResponse
	if err := json.Unmarshal(body, &result); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if result.Role != "moderator" {
		t.Errorf("expected role 'moderator', got '%s'", result.Role)
	}
	if result.User.ID != regularUser.ID {
		t.Errorf("expected user ID %s, got %s", regularUser.ID, result.User.ID)
	}
}

// TestE2E_AdminPlugin_CreateUser tests admin creating a user
func TestE2E_AdminPlugin_CreateUser(t *testing.T) {
	// Create admin user
	adminEmail := uniqueEmail("admin")
	adminToken, adminUser := createUser(t, adminEmail, "AdminPass123!", "Admin User")
	setUserRole(t, adminToken, adminUser.ID, "admin")

	// Admin creates a new user
	newUserEmail := uniqueEmail("newuser")
	reqBody, _ := json.Marshal(map[string]any{
		"email":    newUserEmail,
		"password": "NewUserPass123!",
		"name":     "New User",
		"role":     "user",
	})

	req, _ := http.NewRequest("POST", baseURL+"/api/auth/admin/create-user", bytes.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+adminToken)

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("create-user request failed: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected status 201, got %d: %s", resp.StatusCode, body)
	}

	var result struct {
		User adminUserResponse `json:"user"`
		Role string            `json:"role"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if result.User.User.Email != newUserEmail {
		t.Errorf("expected email %s, got %s", newUserEmail, result.User.User.Email)
	}
}

// TestE2E_AdminPlugin_ListUsers tests listing users
func TestE2E_AdminPlugin_ListUsers(t *testing.T) {
	// Create admin user
	adminEmail := uniqueEmail("admin")
	adminToken, adminUser := createUser(t, adminEmail, "AdminPass123!", "Admin User")
	setUserRole(t, adminToken, adminUser.ID, "admin")

	// Create a few regular users
	for i := 0; i < 3; i++ {
		userEmail := uniqueEmail(fmt.Sprintf("listuser%d", i))
		createUser(t, userEmail, "UserPass123!", fmt.Sprintf("List User %d", i))
	}

	// Admin lists users
	req, _ := http.NewRequest("GET", baseURL+"/api/auth/admin/list-users", nil)
	req.Header.Set("Authorization", "Bearer "+adminToken)

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("list-users request failed: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", resp.StatusCode, body)
	}

	var result admin.ListUsersResult
	if err := json.Unmarshal(body, &result); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if result.Total < 4 {
		t.Errorf("expected at least 4 users (1 admin + 3 created), got %d", result.Total)
	}
}

// TestE2E_AdminPlugin_BanUser tests banning a user
func TestE2E_AdminPlugin_BanUser(t *testing.T) {
	// Create admin user
	adminEmail := uniqueEmail("admin")
	adminToken, adminUser := createUser(t, adminEmail, "AdminPass123!", "Admin User")
	setUserRole(t, adminToken, adminUser.ID, "admin")

	// Create user to ban
	userEmail := uniqueEmail("tobban")
	_, userToBan := createUser(t, userEmail, "UserPass123!", "User To Ban")

	// Admin bans the user
	reqBody, _ := json.Marshal(map[string]any{
		"userId": userToBan.ID,
		"reason": "Test ban",
	})

	req, _ := http.NewRequest("POST", baseURL+"/api/auth/admin/ban-user", bytes.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+adminToken)

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("ban-user request failed: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", resp.StatusCode, body)
	}

	var result adminUserResponse
	if err := json.Unmarshal(body, &result); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if !result.Banned {
		t.Error("expected user to be banned")
	}
	if result.BanReason == nil || *result.BanReason != "Test ban" {
		t.Errorf("expected ban reason 'Test ban', got %v", result.BanReason)
	}
}

// TestE2E_AdminPlugin_UnbanUser tests unbanning a user
func TestE2E_AdminPlugin_UnbanUser(t *testing.T) {
	// Create admin user
	adminEmail := uniqueEmail("admin")
	adminToken, adminUser := createUser(t, adminEmail, "AdminPass123!", "Admin User")
	setUserRole(t, adminToken, adminUser.ID, "admin")

	// Create and ban user
	userEmail := uniqueEmail("tobban")
	_, userToBan := createUser(t, userEmail, "UserPass123!", "User To Ban")

	// Ban the user first
	banBody, _ := json.Marshal(map[string]any{
		"userId": userToBan.ID,
		"reason": "Test ban",
	})
	banReq, _ := http.NewRequest("POST", baseURL+"/api/auth/admin/ban-user", bytes.NewReader(banBody))
	banReq.Header.Set("Content-Type", "application/json")
	banReq.Header.Set("Authorization", "Bearer "+adminToken)
	client.Do(banReq)

	// Now unban the user
	unbanBody, _ := json.Marshal(map[string]any{
		"userId": userToBan.ID,
	})

	req, _ := http.NewRequest("POST", baseURL+"/api/auth/admin/unban-user", bytes.NewReader(unbanBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+adminToken)

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("unban-user request failed: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", resp.StatusCode, body)
	}

	var result core.User
	if err := json.Unmarshal(body, &result); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if result.ID != userToBan.ID {
		t.Errorf("expected user ID %s, got %s", userToBan.ID, result.ID)
	}
}

// TestE2E_AdminPlugin_Unauthorized tests that non-admin users cannot access admin endpoints
func TestE2E_AdminPlugin_Unauthorized(t *testing.T) {
	// Create regular user
	userEmail := uniqueEmail("regular")
	userToken, _ := createUser(t, userEmail, "UserPass123!", "Regular User")

	// Try to list users as non-admin
	req, _ := http.NewRequest("GET", baseURL+"/api/auth/admin/list-users", nil)
	req.Header.Set("Authorization", "Bearer "+userToken)

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("list-users request failed: %v", err)
	}
	defer resp.Body.Close()

	// Should be unauthorized since user doesn't have admin role
	if resp.StatusCode == http.StatusOK {
		t.Error("expected non-admin user to be denied access, but got 200 OK")
	}
}
