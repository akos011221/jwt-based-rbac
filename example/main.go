package main

import (
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/akos011221/jwt-based-rbac/jwtrbac"
)

func main() {
	jwtService := jwtrbac.NewService(jwtrbac.Config{
		SigningKey:     []byte("uF0r3vL8y4XnVxJ5Tu92QZq+fXMtKk9XrHz6EvCJkT0="),
		TokenExpiresIn: 1 * time.Hour,
		Issuer:         "akos011221",
	})

	jwtMiddleware := jwtrbac.NewMiddleware(jwtService)

	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Welcome.")
	})

	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		userID := r.URL.Query().Get("user_id")
		roleParam := r.URL.Query().Get("role")

		if userID == "" {
			http.Error(w, "Missing user_id parameter", http.StatusBadRequest)
			return
		}

		var roles []jwtrbac.Role
		switch roleParam {
		case "admin":
			roles = []jwtrbac.Role{jwtrbac.RoleAdmin}
		case "editor":
			roles = []jwtrbac.Role{jwtrbac.RoleEditor}
		case "viewer":
			roles = []jwtrbac.Role{jwtrbac.RoleViewer}
		default:
			roles = []jwtrbac.Role{jwtrbac.RoleViewer}
		}

		token, err := jwtService.GenerateToken(userID, roles)
		if err != nil {
			http.Error(w, "Failed to generate token", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"token": "%s"}`, token)
	})

	/* Below are the protected routes */

	readHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, err := jwtrbac.GetClaimsFromContext(r.Context())
		if err != nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		fmt.Fprintf(w, "User %s with roles %v can read data", claims.UserID, claims.Roles)
	})

	mux.Handle("/api/data",
		jwtMiddleware.Authenticate(
			jwtMiddleware.RequirePermission(jwtrbac.PermRead)(readHandler),
		),
	)

	deleteHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, _ := jwtrbac.GetClaimsFromContext(r.Context())
		fmt.Fprintf(w, "User %s with roles %v can delete data", claims.UserID, claims.Roles)
	})

	mux.Handle("/api/data/delete",
		jwtMiddleware.Authenticate(
			jwtMiddleware.RequirePermission(jwtrbac.PermDelete)(deleteHandler),
		),
	)

	adminHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, _ := jwtrbac.GetClaimsFromContext(r.Context())
		fmt.Fprintf(w, "User %s is an admin", claims.UserID)
	})

	mux.Handle("/admin",
		jwtMiddleware.Authenticate(
			jwtMiddleware.RequireRole(jwtrbac.RoleAdmin)(adminHandler),
		),
	)

	fmt.Println("Server starting on :8080")
	fmt.Println("To access this API, use:")
	fmt.Println("1) Get a token:		curl 'http://localhost:8080/login?user_id=123&role=admin'")
	fmt.Println("2) Use token with API:		curl -H 'Authorization: Bearer TOKEN' http://localhost:8080/api/data'")

	log.Fatal(http.ListenAndServe(":8080", mux))
}
