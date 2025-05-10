package jwtrbac

import (
	"context"
	"errors"
)

type contextKey string

const claimsContextKey contextKey = "claims"

// SetClaimsInContext adds JWT claims to a context
func SetClaimsInContext(ctx context.Context, claims *Claims) context.Context {
	return context.WithValue(ctx, claimsContextKey, claims)
}

// GetClaimsFromContext retrieves JWT claims from a contetx
func GetClaimsFromContext(ctx context.Context) (*Claims, error) {
	claims, ok := ctx.Value(claimsContextKey).(*Claims)
	if !ok {
		return nil, errors.New("claims not found in context")
	}
	return claims, nil
}
