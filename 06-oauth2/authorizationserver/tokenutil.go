package main

import (
	"crypto/rand"
	"encoding/base64"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const AccessTokenTTL = 15 * time.Minute

// NewOpaqueToken returns a 256-bit random token, base64url-encoded without padding.
func NewOpaqueToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// IssueAccessToken returns a RS256 signed JWT access token.
// Resource servers verify it with the public key from the JWKS endpoint.
func IssueAccessToken(key *SigningKey, issuer, username, clientID string, scope []string) (string, error) {
	now := time.Now()
	claims := jwt.MapClaims{
		"iss":   issuer,
		"sub":   username,
		"aud":   clientID,
		"scope": strings.Join(scope, " "),
		"iat":   now.Unix(),
		"exp":   now.Add(AccessTokenTTL).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = key.ID
	return token.SignedString(key.Private)
}
