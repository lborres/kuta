# Kuta 🏰
*kuta [kú.tâ.]*: fortress (n.) — in Bisaya/Visayan

Simple, secure authentication framework for Go.

Greatly inspired by [Better Auth](https://github.com/better-auth/better-auth).

## Installation
```sh
go get github.com/lborres/kuta
```

## Usage

### Setup
Insert the following block in your main file after initializing your app and storage.
```go
import (
  "github.com/lborres/kuta"
  fiberadapter "github.com/lborres/kuta/adapters/fiber"
  pgxadapter "github.com/lborres/kuta/adapters/pgx"
)

func main() {
  // ...your existing code

  kuta, err = kuta.New(kuta.Config{
    Secret: "mysupersecretsecret",

    Database:      pgxadapter.New(pool),
    HTTP:          fiberadapter.New(app),
    SessionConfig: &kuta.SessionConfig{MaxAge: 24 * time.Hour},
  })
  if err != nil {
    log.Fatalf("could not create kuta instance: %v", err)
  }

  // ...your existing code
}
```

That's it! You're good to go!

You can now protect your endpoints:
```go
app.Get("/sensitive", k.Protected, SensitiveDataHandler)
```

The following endpoints are now available to you:
``` sh
POST /api/auth/sign-in # Email/password login, returns session token
POST /api/auth/sign-up # User registration
POST /api/auth/sign-out # Destroy current session
GET /api/auth/session # Get current session info (verify token, return user data)
POST /api/auth/refresh # Refresh session token (extend expiry)
```

See [examples](https://github.com/lborres/kuta/tree/main/examples) to learn more.


## Credits

Inspired by [Better Auth](https://github.com/better-auth/better-auth) - bringing the same developer experience to Go.
