package jwtrbac

import "slices"

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

// Role is a user role in the system
type Role string

// Possible roles
const (
	RoleAdmin  Role = "admin"
	RoleEditor Role = "editor"
	RoleViewer Role = "viewer"
)

// HasPermission checks if the given roles have the required permission
func HasPermission(roles []Role, requiredPermission Permission) bool {
	for _, role := range roles {
		permissions, exists := RolePermissions[role]
		if !exists {
			continue
		}

		if slices.Contains(permissions, requiredPermission) {
			return true
		}
	}
	return false
}

// HasRole checks if the given roles include the required role
func HasRole(roles []Role, requiredRole Role) bool {
	return slices.Contains(roles, requiredRole)
}
