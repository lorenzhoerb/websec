package main

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
)

type TokenRequest struct {
	GrantType    string
	ClientID     string
	Code         string
	RedirectURI  string
	CodeVerifier string
}

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	Scope        string `json:"scope,omitempty"`
}

type TokenErrorResponse struct {
	Error string `json:"error"`
}

// TODO: support refresh_token grant (see ConsumeRefreshToken) and client authentication
// grant_type=authorization_code&client_id=web-client&code=abc123authorizationcode&redirect_uri=http://localhost:3000/callback&code_verifier=original-random-verifier
func TokenHandler(issuer string, key *SigningKey) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// 1. parse request
		req, err := ParseTokenRequest(r)
		if err != nil {
			writeTokenError(w, http.StatusBadRequest, ErrInvalidRequest)
			return
		}

		// 2. validate request
		if req.GrantType != "authorization_code" {
			writeTokenError(w, http.StatusBadRequest, ErrUnsupportedGrantType)
			return
		}

		client, exists := GetClient(req.ClientID)
		if !exists || !client.Enabled {
			writeTokenError(w, http.StatusUnauthorized, ErrInvalidClient)
			return
		}

		// 3. retrieve auth code (single-use, expired codes are rejected)
		authCode, valid := ConsumeAuthCode(req.Code)
		if !valid {
			writeTokenError(w, http.StatusBadRequest, ErrInvalidGrant)
			return
		}

		// 4. validate auth code: clientID matches, redirect uri matches
		if authCode.ClientID != req.ClientID {
			writeTokenError(w, http.StatusBadRequest, ErrInvalidGrant)
			return
		}

		if authCode.RedirectURI != req.RedirectURI {
			writeTokenError(w, http.StatusBadRequest, ErrInvalidGrant)
			return
		}

		// 5. verify pkce: hash(code_verifier) == code_challenge
		if !verifyPKCE(req.CodeVerifier, authCode.CodeChallenge, authCode.CodeChallengeMethod) {
			writeTokenError(w, http.StatusBadRequest, ErrInvalidGrant)
			return
		}

		// 6. issue access and refresh token
		accessToken, err := IssueAccessToken(key, issuer, authCode.Username, authCode.ClientID, authCode.Scope)
		if err != nil {
			writeTokenError(w, http.StatusInternalServerError, ErrServerError)
			return
		}

		refreshToken, err := NewOpaqueToken()
		if err != nil {
			writeTokenError(w, http.StatusInternalServerError, ErrServerError)
			return
		}

		SaveRefreshToken(refreshToken, RefreshToken{
			ClientID: authCode.ClientID,
			Username: authCode.Username,
			Scope:    authCode.Scope,
		})

		// 7. respond
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		json.NewEncoder(w).Encode(TokenResponse{
			AccessToken:  accessToken,
			TokenType:    "Bearer",
			ExpiresIn:    int(AccessTokenTTL.Seconds()),
			RefreshToken: refreshToken,
			Scope:        strings.Join(authCode.Scope, " "),
		})
	}
}

func ParseTokenRequest(r *http.Request) (*TokenRequest, error) {
	if err := r.ParseForm(); err != nil {
		return nil, err
	}

	req := &TokenRequest{
		GrantType:    r.FormValue("grant_type"),
		ClientID:     r.FormValue("client_id"),
		Code:         r.FormValue("code"),
		RedirectURI:  r.FormValue("redirect_uri"),
		CodeVerifier: r.FormValue("code_verifier"),
	}

	if req.GrantType == "" ||
		req.ClientID == "" ||
		req.Code == "" ||
		req.RedirectURI == "" ||
		req.CodeVerifier == "" {
		return nil, errors.New("missing required parameters")
	}

	return req, nil
}

func verifyPKCE(verifier, challenge, method string) bool {
	if method != "S256" || challenge == "" {
		return false
	}

	sum := sha256.Sum256([]byte(verifier))
	computed := base64.RawURLEncoding.EncodeToString(sum[:])

	return subtle.ConstantTimeCompare([]byte(computed), []byte(challenge)) == 1
}

func writeTokenError(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(TokenErrorResponse{Error: code})
}
