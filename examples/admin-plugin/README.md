# Admin Plugin Example

This example demonstrates how to use the Kuta admin plugin for role-based access control, user management, and ban functionality.

## Features Demonstrated

- Plugin configuration and initialization
- Admin role assignment
- Admin-specific endpoints
- User management (create, list, ban, unban)
- Role-based access control

## Setup

1. Start PostgreSQL (using docker-compose from the root):
```bash
cd ../..
docker-compose up -d
```

2. Run migrations (from the root):
```bash
cd ../..
make migrate-up
```

3. Start the server:
```bash
go run main.go
```

## Usage

### 1. Create a regular user
```bash
curl -X POST http://localhost:8080/api/auth/sign-up \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "Password123!",
    "name": "Regular User"
  }'
```

### 2. Create an admin user (first user should be admin)
```bash
curl -X POST http://localhost:8080/api/auth/sign-up \
  -H "Content-Type: application/json" \
  -d '{
    "email": "admin@example.com",
    "password": "AdminPass123!",
    "name": "Admin User"
  }'
```

### 3. Sign in as admin
```bash
curl -X POST http://localhost:8080/api/auth/sign-in \
  -H "Content-Type: application/json" \
  -d '{
    "email": "admin@example.com",
    "password": "AdminPass123!"
  }'
```

Save the token from the response.

### 4. List all users (admin only)
```bash
curl -X GET http://localhost:8080/api/auth/admin/list-users \
  -H "Authorization: Bearer YOUR_TOKEN"
```

### 5. Set user role (admin only)
```bash
curl -X POST http://localhost:8080/api/auth/admin/set-role \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "userId": "USER_ID_HERE",
    "role": "admin"
  }'
```

### 6. Ban a user (admin only)
```bash
curl -X POST http://localhost:8080/api/auth/admin/ban-user \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "userId": "USER_ID_HERE",
    "reason": "Violation of terms"
  }'
```

### 7. Unban a user (admin only)
```bash
curl -X POST http://localhost:8080/api/auth/admin/unban-user \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "userId": "USER_ID_HERE"
  }'
```

## Plugin Configuration

```go
adminConfig := admin.DefaultConfig()
adminConfig.AdminUserIDs = []string{"specific-user-id"} // Optional whitelist
adminConfig.DefaultRole = "user"
adminConfig.AdminRoles = []string{"admin"}
adminConfig.BannedUserMessage = "You have been banned."

k, err := kuta.New(kuta.Config{
    // ... other config
    Plugins: []core.Plugin{
        admin.New(adminConfig),
    },
})
```

## Admin Endpoints

The admin plugin automatically registers these endpoints:

- `POST /api/auth/admin/set-role` - Set user role
- `POST /api/auth/admin/create-user` - Create new user
- `GET  /api/auth/admin/get-user` - Get user details
- `POST /api/auth/admin/update-user` - Update user fields
- `GET  /api/auth/admin/list-users` - List users with pagination
- `POST /api/auth/admin/ban-user` - Ban a user
- `POST /api/auth/admin/unban-user` - Unban a user
- `POST /api/auth/admin/delete-user` - Delete a user
- `POST /api/auth/admin/set-password` - Set user password
- `POST /api/auth/admin/list-user-sessions` - List user sessions
- `POST /api/auth/admin/revoke-session` - Revoke specific session
- `POST /api/auth/admin/revoke-user-sessions` - Revoke all user sessions

## Notes

- The first user created should be promoted to admin manually via database or using AdminUserIDs config
- Ban functionality automatically revokes all user sessions
- Admin users cannot ban or delete themselves
- All admin operations require authentication and proper permissions
