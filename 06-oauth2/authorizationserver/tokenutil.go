package main

import (
	"crypto/rand"
	"encoding/base64"
)

// NewOpaqueToken returns a 256-bit random token, base64url-encoded without padding.
func NewOpaqueToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
