// JWT example with roles. Users:
//
//   - (admin,admin): test:read, test:write
//   - (user, user): test:read
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"slices"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
)

type contextKey struct{}

type Claims struct {
	Roles []string `json:"roles"`
	jwt.RegisteredClaims
}

var principalKey contextKey

type Principal struct {
	Username string
	Roles    []string
}

// hardcoded for simplicity
const (
	signingKey = "gxTJxtlQKvBI0EhaKfqcxw4P3m5eUeRNPXgpe84TlKk="
	cookieName = "access_token" // name of cookie where the jwt is attached
	TTLSeconds = 3600
)

func hasRole(r *http.Request, role string) bool {
	principal, ok := r.Context().Value(principalKey).(Principal)
	return ok && slices.Contains(principal.Roles, role)
}

func validateToken(tokenString string) (Principal, error) {
	claims := &Claims{}
	token, err := jwt.ParseWithClaims(
		tokenString,
		claims,
		func(token *jwt.Token) (any, error) {
			if token.Method != jwt.SigningMethodHS256 {
				return nil, fmt.Errorf(
					"unexpected signing method: %v",
					token.Header["alg"],
				)
			}
			return []byte(signingKey), nil
		},
		jwt.WithValidMethods([]string{"HS256"}),
		jwt.WithIssuer("05-jwt-example"),
		jwt.WithAudience("05-jwt-example"),
		jwt.WithExpirationRequired(),
	)

	if err != nil {
		return Principal{}, err
	}

	if !token.Valid {
		return Principal{}, errors.New("invalid token")
	}

	return Principal{
		Username: claims.Subject,
		Roles:    claims.Roles,
	}, nil

}

func createToken(principal Principal) (string, error) {
	now := time.Now()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"iss":   "05-jwt-example",
		"aud":   "05-jwt-example",
		"exp":   now.Add(time.Duration(TTLSeconds * time.Second)).Unix(),
		"iat":   now.Unix(),
		"sub":   principal.Username,
		"roles": principal.Roles,
	})

	signedToken, err := token.SignedString([]byte(signingKey))
	if err != nil {
		log.Fatal(err)
		return "", err
	}

	return signedToken, nil
}

func unauthorized(w http.ResponseWriter) {
	http.Error(w, "Unauthorized", http.StatusUnauthorized)
}

func forbidden(w http.ResponseWriter) {
	http.Error(w, "Forbidden", http.StatusForbidden)
}

func authenticate(username, password string) (Principal, error) {
	if username == "admin" && password == "admin" {
		return Principal{Username: "admin", Roles: []string{"test:read", "test:write"}}, nil
	} else if username == "user" && password == "user" {
		return Principal{Username: "user", Roles: []string{"test:read"}}, nil
	}

	return Principal{}, errors.New("invalid user and password")
}

func authenticated(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie(cookieName)
		if err != nil {
			unauthorized(w)
			return
		}

		principal, err := validateToken(cookie.Value)
		if err != nil {
			unauthorized(w)
			return
		}

		ctx := context.WithValue(r.Context(), principalKey, principal)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func login(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<10)).Decode(&body); err != nil || body.Username == "" {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	principal, err := authenticate(body.Username, body.Password)
	if err != nil {
		unauthorized(w)
		return
	}

	token, err := createToken(principal)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}

	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    token,
		HttpOnly: true,
		Secure:   false,
		MaxAge:   3600, // one hour
		SameSite: http.SameSiteLaxMode,
		Path:     "/",
	})

	w.WriteHeader(http.StatusNoContent)
}

func logout(w http.ResponseWriter, r *http.Request) {
}

func testRead(w http.ResponseWriter, r *http.Request) {
	if !hasRole(r, "test:read") {
		forbidden(w)
		return
	}

	principal, _ := r.Context().Value(principalKey).(Principal)
	fmt.Fprintf(w, "READ test: %s\n", principal.Username)
}

func testWrite(w http.ResponseWriter, r *http.Request) {
	if !hasRole(r, "test:write") {
		forbidden(w)
		return
	}

	principal, _ := r.Context().Value(principalKey).(Principal)
	fmt.Fprintf(w, "WRITE test: %s\n", principal.Username)
}

func private(w http.ResponseWriter, r *http.Request) {
	principal, _ := r.Context().Value(principalKey).(Principal)
	fmt.Fprintf(w, "private, hello %s\n", principal.Username)
}

func public(w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, "public\n")
}

func main() {

	http.Handle("GET /test", authenticated(http.HandlerFunc(testRead)))
	http.Handle("POST /test", authenticated(http.HandlerFunc(testWrite)))
	http.Handle("GET /private", authenticated(http.HandlerFunc(private)))
	http.HandleFunc("POST /login", login)
	http.HandleFunc("GET /public", public)
	http.HandleFunc("POST /logout", logout)

	log.Println("Starting TOKEN authentication example...")
	log.Println("listening on http://localhost:8888")
	if err := http.ListenAndServe(":8888", nil); err != nil {
		log.Fatalf("HTTP server failed: %v", err)
	}

}
