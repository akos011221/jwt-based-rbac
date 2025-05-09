package jwtrbac

import (
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Custom errors used by the package
var (
	ErrInvalidToken      = errors.New("invalid token")
	ErrExpiredToken      = errors.New("token is expired")
	ErrInsufficientPerms = errors.New("insufficient permissions")
	ErrMissingAuthHeader = errors.New("missing authorization header")
	ErrInvalidAuthHeader = errors.New("invalid authorization header format")
)

// Role is a user role in the system
type Role string

// Possible roles
const (
	RoleAdmin  Role = "admin"
	RoleEditor Role = "editor"
	RoleViewer Role = "viewer"
)

// Permission is the action that can be performed
type Permission string

// Possible permissions
const (
	PermCreate Permission = "create"
	PermRead   Permission = "read"
	PermUpdate Permission = "update"
	PermDelete Permission = "delete"
)

// RolePermissions defines which permissions are granted to each role
var RolePermissions = map[Role][]Permission{
	RoleAdmin: {
		PermCreate,
		PermRead,
		PermUpdate,
		PermDelete,
	},
	RoleEditor: {
		PermCreate,
		PermRead,
		PermUpdate,
	},
	RoleViewer: {
		PermRead,
	},
}

// Claims is the custom claims in the JWT token
type Claims struct {
	UserID string `json:"user_id"`
	Roles  []Role `json:"roles"`
	jwt.RegisteredClaims
}

// Config is a JWT configuration
type Config struct {
	SigningKey     []byte
	TokenExpiresIn time.Duration
	Issuer         string
}

// Service handles JWT operations for RBAC
type Service struct {
	config Config
}

// NewService creates a new JWT RBAC service
func NewService(config Config) *Service {
	return &Service{
		config: config,
	}
}

// GenerateToken generates a new JWT token for the given user ID and roles
// It returns the signed token string or an error if token generation fails
func (s *Service) GenerateToken(userID string, roles []Role) (string, error) {
	// Token expiration time is set based on the given configuration
	expiresAt := time.Now().Add(s.config.TokenExpiresIn)

	// Claims are created with the user information and standard JWT claims
	claims := &Claims{
		UserID: userID,
		Roles:  roles,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    s.config.Issuer,
		},
	}

	// Create the new token with the claims
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// Sign that token with the signing key and return as string
	tokenString, err := token.SignedString(s.config.SigningKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w", err)
	}

	return tokenString, nil
}

// ValidateToken validates the JWT token and returns its claims if valid
func (s *Service) ValidateToken(tokenString string) (*Claims, error) {
	// Parse the token with the signing method and key
	token, err := jwt.ParseWithClaims(
		tokenString,
		&Claims{},
		func(token *jwt.Token) (interface{}, error) {
			// Validate that the oken uses the expected signing method
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return s.config.SigningKey, nil
		},
	)

	if err != nil {
		// Is it an expired token?
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, ErrExpiredToken
		}
		return nil, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}

	// Extract the claims from the token
	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, ErrInvalidToken
	}

	return claims, nil
}
