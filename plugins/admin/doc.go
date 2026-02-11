// Package admin provides admin functionality for Kuta authentication.
//
// The admin plugin adds role-based access control, user management,
// ban functionality, and session management capabilities for administrators.
//
// Features:
//   - Role management (set user roles)
//   - User management (create, list, get, update, delete users)
//   - Ban system (ban/unban users with optional expiration)
//   - Session management (list, revoke user sessions)
//   - Password management (set user passwords)
//   - Permission-based access control
//
// Usage:
//
//	k, err := kuta.New(kuta.Config{
//	    Secret:   "secretshouldbeatleast32charslong",
//	    Database: pgxadapter.New(pool),
//	    HTTP:     fiberadapter.New(app),
//	    Plugins: []kuta.Plugin{
//	        admin.New(admin.DefaultConfig()),
//	    },
//	})
//
// See the Config type for configuration options.
package admin
