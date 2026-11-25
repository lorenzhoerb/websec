package main

import (
	"errors"
	"net/http"
	"net/url"
	"strings"
)

const (
	ErrInvalidRequest       = "invalid_request"
	ErrInvalidClient        = "invalid_client"
	ErrInvalidGrant         = "invalid_grant"
	ErrUnsupportedGrantType = "unsupported_grant_type"
	ErrServerError          = "server_error"
)

type AuthorizationRequest struct {
	ClientID            string
	RedirectURI         string
	ResponseType        string
	Scope               []string
	CodeChallenge       string
	CodeChallengeMethod string
	State               string
}

func AuthorizeHandler(w http.ResponseWriter, r *http.Request) {
	// 1. parse authorization request
	req, err := ParseAuthorizationRequest(r)
	if err != nil {
		http.Error(w, "invalid authorization request", http.StatusBadRequest)
		return
	}

	// 2. validate authorization request, get client
	_, err = ValidateAuthorizationRequest(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// 3. check login session. invalid redirects to login
	session, err := extractSession(r)
	if err != nil {
		redirectToLogin(w, r)
		return
	}

	// 4. check consent
	// TODO: implement scope consent, for now accept all requested
	consentedScopes := req.Scope

	// 5. generate auth code
	code, err := IssueAuthorizationToken(req, session.Username, consentedScopes)
	if err != nil {
		redirectWithError(w, r, req.RedirectURI, ErrServerError, req.State)
		return
	}

	// 6. redirect with authorization code
	redirectWithCode(w, r, req.RedirectURI, code, req.State)
}

func ParseAuthorizationRequest(r *http.Request) (*AuthorizationRequest, error) {
	q := r.URL.Query()

	req := &AuthorizationRequest{
		ClientID:            q.Get("client_id"),
		RedirectURI:         q.Get("redirect_uri"),
		ResponseType:        q.Get("response_type"),
		Scope:               strings.Fields(q.Get("scope")),
		State:               q.Get("state"),
		CodeChallenge:       q.Get("code_challenge"),
		CodeChallengeMethod: q.Get("code_challenge_method"),
	}

	if req.ClientID == "" || req.ResponseType == "" {
		return nil, errors.New("missing required parameters")
	}

	return req, nil

}

func ValidateAuthorizationRequest(req *AuthorizationRequest) (*Client, error) {
	client, ok := GetClient(req.ClientID)
	if !ok {
		return nil, errors.New("invalid client")
	}

	if !client.Enabled {
		return nil, errors.New("client disabled")
	}

	if !client.HasRedirectURI(req.RedirectURI) {
		return nil, errors.New("invalid redirect uri")
	}

	u, err := url.Parse(req.RedirectURI)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil, errors.New("invalid redirect uri")
	}

	if !client.AllowsScopes(req.Scope) {
		return nil, errors.New("invalid scope")
	}

	return &client, nil
}

func validateRedirectURI(redirectURI string) error {
	u, err := url.Parse(redirectURI)
	if err != nil {
		return errors.New("invalid redirect uri")
	}

	if u.Scheme == "" || u.Host == "" {
		return errors.New("invalid redirect uri")
	}

	return nil
}

func IssueAuthorizationToken(req *AuthorizationRequest, userID string, scopes []string) (string, error) {
	code, err := NewOpaqueToken()
	if err != nil {
		return "", err
	}

	SaveAuthCode(code, AuthCode{
		ClientID:            req.ClientID,
		Username:            userID,
		RedirectURI:         req.RedirectURI,
		Scope:               scopes,
		CodeChallenge:       req.CodeChallenge,
		CodeChallengeMethod: req.CodeChallengeMethod,
	})

	return code, nil
}

func extractSession(r *http.Request) (Session, error) {
	cookie, err := r.Cookie(SessionCookieName)
	if err != nil {
		return Session{}, errors.New("no session")
	}

	session, ok := GetSession(cookie.Value)
	if !ok {
		return Session{}, errors.New("invalid session")
	}

	return session, nil
}

func redirectWithCode(
	w http.ResponseWriter,
	r *http.Request,
	redirectURI string,
	code string,
	state string,
) {
	target, err := url.Parse(redirectURI)
	if err != nil {
		http.Error(w, "Invalid redirect URI", http.StatusBadRequest)
		return
	}

	params := target.Query()
	params.Set("code", code)

	if state != "" {
		params.Set("state", state)
	}

	target.RawQuery = params.Encode()

	http.Redirect(w, r, target.String(), http.StatusFound)
}

func redirectWithError(
	w http.ResponseWriter,
	r *http.Request,
	redirectURI string,
	code string,
	state string,
) {
	target, err := url.Parse(redirectURI)
	if err != nil {
		http.Error(w, "Invalid redirect URI", http.StatusBadRequest)
		return
	}

	params := target.Query()
	params.Set("error", code)

	if state != "" {
		params.Set("state", state)
	}

	target.RawQuery = params.Encode()

	http.Redirect(w, r, target.String(), http.StatusFound)
}

func redirectToLogin(w http.ResponseWriter, r *http.Request) {
	returnTo := r.URL.RequestURI()
	http.Redirect(
		w,
		r,
		"/login?return_to="+url.QueryEscape(returnTo),
		http.StatusSeeOther,
	)
}
