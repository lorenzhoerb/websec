package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	keyPrefix = "wsec_"
	TTL       = 30 * time.Minute
)

type TokenRecord struct {
	IssuedAt time.Time
	Username string
}

type contextKey struct{}

var usernameKey contextKey

// Tokens are stored by their SHA-256 hash, the plaintext is only shown once at issue time.
var (
	tokenStore = make(map[string]TokenRecord)
	tokenMu    sync.Mutex
)

func (t TokenRecord) IsValid() bool {
	return time.Now().Before(t.IssuedAt.Add(TTL))
}

func hashToken(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func IssueToken(username string) (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	token := keyPrefix + hex.EncodeToString(b)

	tokenMu.Lock()
	defer tokenMu.Unlock()
	tokenStore[hashToken(token)] = TokenRecord{
		Username: username,
		IssuedAt: time.Now(),
	}

	return token, nil
}

func lookupToken(token string) (TokenRecord, bool) {
	tokenMu.Lock()
	defer tokenMu.Unlock()

	key := hashToken(token)
	record, ok := tokenStore[key]
	if !ok {
		return TokenRecord{}, false
	}
	if !record.IsValid() {
		delete(tokenStore, key)
		return TokenRecord{}, false
	}
	return record, true
}

func revokeToken(token string) {
	tokenMu.Lock()
	defer tokenMu.Unlock()
	delete(tokenStore, hashToken(token))
}

func extractToken(r *http.Request) (string, bool) {
	token, found := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	return token, found && strings.HasPrefix(token, keyPrefix)
}

func unauthorized(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", "Bearer")
	http.Error(w, "Unauthorized", http.StatusUnauthorized)
}

func authenticated(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, ok := extractToken(r)
		if !ok {
			unauthorized(w)
			return
		}

		record, ok := lookupToken(token)
		if !ok {
			unauthorized(w)
			return
		}

		ctx := context.WithValue(r.Context(), usernameKey, record.Username)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func register(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Username string `json:"username"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<10)).Decode(&body); err != nil || body.Username == "" {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	token, err := IssueToken(body.Username)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"access_token": token,
		"token_type":   "Bearer",
		"expires_in":   int(TTL.Seconds()),
	})
}

func revoke(w http.ResponseWriter, r *http.Request) {
	token, _ := extractToken(r)
	revokeToken(token)
	w.WriteHeader(http.StatusNoContent)
}

func private(w http.ResponseWriter, r *http.Request) {
	username, _ := r.Context().Value(usernameKey).(string)
	fmt.Fprintf(w, "private, hello %s\n", username)
}

func public(w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, "public\n")
}

func main() {
	http.Handle("GET /private", authenticated(http.HandlerFunc(private)))
	http.Handle("POST /revoke", authenticated(http.HandlerFunc(revoke)))
	http.HandleFunc("POST /register", register)
	http.HandleFunc("GET /public", public)

	log.Println("Starting TOKEN authentication example...")
	log.Println("listening on http://localhost:8888")
	if err := http.ListenAndServe(":8888", nil); err != nil {
		log.Fatalf("HTTP server failed: %v", err)
	}
}
