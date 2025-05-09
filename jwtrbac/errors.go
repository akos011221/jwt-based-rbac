package jwtrbac

import "errors"

// Custom errors used by the package
var (
	ErrInvalidToken      = errors.New("invalid token")
	ErrExpiredToken      = errors.New("token is expired")
	ErrInsufficientPerms = errors.New("insufficient permissions")
	ErrMissingAuthHeader = errors.New("missing authorization header")
	ErrInvalidAuthHeader = errors.New("invalid authorization header format")
)
