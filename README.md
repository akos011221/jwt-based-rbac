# Go JWT-RBAC

A lightweight JWT-based Role-Based Access Control library for Go applications.

## Features

- JWT authentication with customizable expiration
- Role-based authorization (Admin, Editor, Viewer)
- Permission-based access control
- HTTP middleware for easy integration

## Installation

```bash
go get github.com/akos011221/jwt-based-rbac
```

## Usage

### Initialize the Service

```go
jwtService := jwtrbac.NewService(jwtrbac.Config{
    SigningKey:     []byte("your-secret-key"),
    TokenExpiresIn: 1 * time.Hour,
    Issuer:         "your-app",
})

middleware := jwtrbac.NewMiddleware(jwtService)
```

### Generate Tokens

```go
// Create token for user with Admin role
token, err := jwtService.GenerateToken("some_user", []jwtrbac.Role{jwtrbac.RoleAdmin})
```

### Protect Routes

```go

// Authenticate users
mux.Handle("/api/data", middleware.Authenticate(dataHandler))

// Require specific permission
mux.Handle("/api/update", 
    middleware.Authenticate(
        middleware.RequirePermission(jwtrbac.PermUpdate)(updateHandler),
    ),
)

// Require specific role
mux.Handle("/admin", 
    middleware.Authenticate(
        middleware.RequireRole(jwtrbac.RoleAdmin)(adminHandler),
    ),
)
```

### Access User Data in Handlers

```go

func handler(w http.ResponseWriter, r *http.Request) {
    claims, _ := jwtrbac.GetClaimsFromContext(r.Context())
    userID := claims.UserID
    // Process request...
}
```

## Example

See example.go for a complete working example.
