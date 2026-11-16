package main

import (
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"time"
)

const (
	AuthCodeTTL     = 1 * time.Minute
	RefreshTokenTTL = 24 * time.Hour
)

type AuthCode struct {
	ClientID            string
	Username            string
	RedirectURI         string
	Scope               []string
	CodeChallenge       string
	CodeChallengeMethod string
	expiresAt           time.Time
}

type RefreshToken struct {
	ClientID  string
	Username  string
	Scope     []string
	expiresAt time.Time
}

var (
	mu            sync.Mutex
	authCodes     = make(map[string]AuthCode)
	refreshTokens = make(map[string]RefreshToken) // keyed by sha256(token)
)

func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func SaveAuthCode(code string, ac AuthCode) {
	mu.Lock()
	defer mu.Unlock()
	ac.expiresAt = time.Now().Add(AuthCodeTTL)
	authCodes[code] = ac
}

// ConsumeAuthCode looks up and deletes the code in one step, so it is single-use.
func ConsumeAuthCode(code string) (AuthCode, bool) {
	mu.Lock()
	defer mu.Unlock()
	ac, ok := authCodes[code]
	delete(authCodes, code)
	if !ok || time.Now().After(ac.expiresAt) {
		return AuthCode{}, false
	}
	return ac, true
}

func SaveRefreshToken(token string, rt RefreshToken) {
	mu.Lock()
	defer mu.Unlock()
	rt.expiresAt = time.Now().Add(RefreshTokenTTL)
	refreshTokens[hashToken(token)] = rt
}

// ConsumeRefreshToken deletes the token on use (rotation); issue a new one afterwards.
func ConsumeRefreshToken(token string) (RefreshToken, bool) {
	mu.Lock()
	defer mu.Unlock()
	key := hashToken(token)
	rt, ok := refreshTokens[key]
	delete(refreshTokens, key)
	if !ok || time.Now().After(rt.expiresAt) {
		return RefreshToken{}, false
	}
	return rt, true
}
