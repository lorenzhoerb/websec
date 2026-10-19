package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
)

type contextKey struct{}

var principalKey contextKey

type Principal struct {
	Username string
}

const sessionCookieName = "session_id"

var sessionStore = make(map[string]Principal)

func extractSession(r *http.Request) (string, error) {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		return "", err
	}
	return cookie.Value, nil
}

func createSession(principal Principal) (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}

	sessionID := hex.EncodeToString(b)

	sessionStore[sessionID] = principal

	return sessionID, nil
}

func unauthorized(w http.ResponseWriter) {
	http.Error(w, "Unauthorized", http.StatusUnauthorized)
}

func authenticate(username, password string) (Principal, error) {
	if username == "admin" && password == "admin" {
		return Principal{Username: "admin"}, nil
	}
	return Principal{}, errors.New("invalid user and password")
}

func authenticated(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sessionId, err := extractSession(r)
		if err != nil {
			unauthorized(w)
			return
		}

		principal, ok := sessionStore[sessionId]
		if !ok {
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

	sessionId, err := createSession(principal)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}

	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    sessionId,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   3600, // one hour
	})

	w.WriteHeader(http.StatusNoContent)
}

func logout(w http.ResponseWriter, r *http.Request) {
	sessionId, _ := extractSession(r)
	delete(sessionStore, sessionId)

	// expire session cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "session_id",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})

	w.WriteHeader(http.StatusNoContent)
}

func private(w http.ResponseWriter, r *http.Request) {
	principal, _ := r.Context().Value(principalKey).(Principal)
	fmt.Fprintf(w, "private, hello %s\n", principal.Username)
}

func public(w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, "public\n")
}

func main() {

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
