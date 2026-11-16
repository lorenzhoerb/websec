package main

import (
	"embed"
	_ "embed"
	"html/template"
	"net/http"
	"strings"
)

const SessionCookieName = "session_id"

//go:embed templates/login.html
var templateFS embed.FS
var loginTemplate = template.Must(
	template.ParseFS(templateFS, "templates/login.html"),
)

type Authenticator interface {
	Authenticate(username, password string) error
}

func safeReturnTo(target string) string {
	if !strings.HasPrefix(target, "/") ||
		strings.HasPrefix(target, "//") ||
		strings.HasPrefix(target, "/\\") ||
		strings.ContainsAny(target, "\r\n") {
		return "/"
	}
	return target
}

func LoginPage(w http.ResponseWriter, r *http.Request) {
	loginTemplate.Execute(w, map[string]any{
		"ReturnTo": safeReturnTo(r.URL.Query().Get("return_to")),
	})
}

func LoginSubmitHandler(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	password := r.FormValue("password")
	returnTo := safeReturnTo(r.FormValue("return_to"))

	if err := Authenticate(username, password); err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		loginTemplate.Execute(w, map[string]any{
			"Error":    "Invalid username or password",
			"ReturnTo": returnTo,
		})
		return
	}

	sessionID, err := CreateSession(username)
	if err != nil {
		// TODO FAIL
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    sessionID,
		Domain:   "/",
		Path:     "/",
		MaxAge:   int(SessionTTL),
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
	http.Redirect(w, r, returnTo, http.StatusSeeOther)
}

func LogoutHandler(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(SessionCookieName)
	if err == nil {
		RevokeSession(cookie.Value)
	}

	// remove cookie
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1, // deletes cookie in browser
		HttpOnly: true,
		Secure:   false,
		SameSite: http.SameSiteLaxMode,
	})

	http.Redirect(w, r, "/login", http.StatusSeeOther)
}
