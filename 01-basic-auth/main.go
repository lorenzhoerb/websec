package main

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"log"
	"net/http"
	"strings"
)

type User struct {
	Username string
	password string
}

type Principal struct {
	Username string
}

type contextKey struct{}

var principalKey contextKey

// Simple authenticate implementation.
func authenticate(username, password string) (Principal, error) {
	if username != "admin" && password != "admin" {
		return Principal{}, errors.New("invalid credentials")
	}

	return Principal{Username: "admin"}, nil
}

func extractCredentials(r *http.Request) (string, string, bool) {
	header := r.Header.Get("Authorization")

	if !strings.HasPrefix(header, "Basic ") {
		return "", "", false
	}

	encoded := strings.TrimPrefix(header, "Basic ")

	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", "", false
	}

	return strings.Cut(string(decoded), ":")
}

func unauthorized(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", "Basic realm=\"User Visible Realm\"")
	http.Error(w, "Unauthorized", http.StatusUnauthorized)
}

func authenticated(next http.HandlerFunc) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {

		username, password, ok := extractCredentials(r)
		if !ok {
			unauthorized(w)
			return
		}

		principal, err := authenticate(username, password)
		if err != nil {
			unauthorized(w)
			return
		}

		ctx := context.WithValue(r.Context(), principalKey, principal)
		next(w, r.WithContext(ctx))
	}
}

func private(w http.ResponseWriter, r *http.Request) {
	principal, ok := r.Context().Value(principalKey).(Principal)

	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	io.WriteString(w, "Private! Hello "+principal.Username)
}

func public(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	io.WriteString(w, "Public")
}

func main() {

	http.HandleFunc("GET /private", authenticated(private))
	http.HandleFunc("GET /public", public)

	log.Println("Listening on :8085")
	if err := http.ListenAndServe(":8085", nil); err != nil {
		log.Fatalf("HTTP server failed: %v", err)
	}
}
