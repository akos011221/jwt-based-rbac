package jwtrbac

import "context"

type contextKey string

const claimsContextKey contextKey = "claims"

// SetClaimsInContext adds JWT claims to a context
func SetClaimsInContext(ctx context.Context, claims *Claims) context.Context {
	return context.WithValue(ctx, claimsContextKey, claims)
}
