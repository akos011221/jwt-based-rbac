package jwtrbac

import (
	"net/http"
	"strings"
)

// Middleware is the HTTP middleware configuration
type Middleware struct {
	jwtService *Service
}

// NewMiddleware creates a new JWT middleware
func NewMiddleware(jwtService *Service) *Middleware {
	return &Middleware{
		jwtService: jwtService,
	}
}

// ExtractTokenFromRequest extracts the JWT token from the Authorization header
// ...returns the token string, or error if any
func ExtractTokenFromRequest(r *http.Request) (string, error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return "", ErrMissingAuthHeader
	}

	if !strings.HasPrefix(authHeader, "Bearer ") {
		return "", ErrInvalidAuthHeader
	}

	tokenString := strings.TrimPrefix(authHeader, "Bearer ")
	return tokenString, nil
}
