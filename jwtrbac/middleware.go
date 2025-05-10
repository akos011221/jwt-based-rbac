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

// Authenticate middleware verifies the JWT token and puts the claims in the
// request context
func (m *Middleware) Authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenString, err := ExtractTokenFromRequest(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}

		claims, err := m.jwtService.ValidateToken(tokenString)
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}

		ctx := SetClaimsInContext(r.Context(), claims)

		// Call the next handler with the context with claims
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// RequirePermission middleware ensures the user has the required permission
func (m *Middleware) RequirePermission(permission Permission) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims, err := GetClaimsFromContext(r.Context())
			if err != nil {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}

			if !HasPermission(claims.Roles, permission) {
				http.Error(w, ErrInsufficientPerms.Error(), http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RequireRole middleware ensures the user has the required role
func (m *Middleware) RequireRole(role Role) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims, err := GetClaimsFromContext(r.Context())
			if err != nil {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}

			if !HasRole(claims.Roles, role) {
				http.Error(w, ErrInsufficientPerms.Error(), http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
