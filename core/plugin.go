package core

import "github.com/lborres/kuta/pkg/crypto"

// Plugin defines the interface that all Kuta plugins must implement
type Plugin interface {
	// ID returns a unique identifier for the plugin
	ID() string

	// Init is called when the plugin is registered, before routes are set up
	// It receives the core dependencies and can return an error if initialization fails
	Init(deps PluginDependencies) error
}

// PluginDependencies provides core services to plugins during initialization
type PluginDependencies struct {
	Storage       StorageProvider
	Auth          AuthProvider
	Passwords     crypto.PasswordHandler
	Secret        string
	SessionConfig *SessionConfig
}

// PluginWithEndpoints is an optional interface that plugins can implement
// to contribute self-contained HTTP endpoints. The adapter automatically
// registers these — no adapter-side handler code is needed per plugin.
type PluginWithEndpoints interface {
	Plugin

	// Endpoints returns the plugin's endpoint definitions.
	// Paths are relative to the plugin namespace (basePath + "/" + plugin.ID()).
	Endpoints() []PluginEndpoint
}

// PluginWithHooks is an optional interface for plugins that need to hook
// into the authentication lifecycle
type PluginWithHooks interface {
	Plugin

	// BeforeSignIn is called before a user signs in
	BeforeSignIn(userID string) error

	// AfterSignIn is called after a user successfully signs in
	AfterSignIn(userID string) error

	// BeforeSignUp is called before a user signs up
	BeforeSignUp(email string) error

	// AfterSignUp is called after a user successfully signs up
	AfterSignUp(userID string) error
}
