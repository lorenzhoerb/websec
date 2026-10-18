package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
)

const (
	// Represents the hash algorithm used for digest
	hashAlgorithm = "SHA-256"
	// Represents the quality of protection
	qop = "auth"
	// Represent if the clients must hash the username
	usernameHashing = false
)

type User struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

var userStore = make(map[string]User)

func generateNonce() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}

	return hex.EncodeToString(b), nil
}

func extractParameters(header string) map[string]string {
	parameters := make(map[string]string)

	parametersString := strings.TrimPrefix(header, "Digest ")
	parameterParts := strings.Split(parametersString, ",")
	for _, parameter := range parameterParts {
		key, value, found := strings.Cut(parameter, "=")
		if !found {
			continue
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		// Remove surrounding double quotes.
		if len(value) >= 2 && value[0] == '"' && value[len(value)-1] == '"' {
			value = value[1 : len(value)-1]
		}
		parameters[key] = value
	}
	return parameters
}

func hashSHA256(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func calculateHA1(usernameHash, realm, password string) string {
	return hashSHA256(usernameHash + ":" + realm + ":" + password)
}

func calculateHA2(method, requestURI string) string {
	return hashSHA256(method + ":" + requestURI)
}

func calculateResponseDigest(ha1, nonce, nc, cnonce, qop, ha2 string) string {
	log.Printf("ha1=%s, nc=%s, cnonce=%s, poq=%s, ha2=%s\n", ha1, nc, cnonce, qop, ha2)
	return hashSHA256(ha1 + ":" + nonce + ":" + nc + ":" + cnonce + ":" + qop + ":" + ha2)
}

func authenticated(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		header := r.Header.Get("Authorization")
		if !strings.HasPrefix(header, "Digest ") {
			unauthorized(w)
			return
		}

		log.Println(header)

		parameters := extractParameters(header)
		log.Printf("%v\n", parameters)
		username := parameters["username"]
		realm := parameters["realm"]
		user, exists := userStore[username]
		if !exists {
			unauthorized(w)
			return
		}

		ha1 := calculateHA1(username, realm, user.Password)
		ha2 := calculateHA2(r.Method, r.RequestURI)

		response := parameters["response"]
		nonce := parameters["nonce"]
		nc := parameters["nc"]
		cnonce := parameters["cnonce"]
		qop := parameters["qop"]
		expectedResponse := calculateResponseDigest(ha1, nonce, nc, cnonce, qop, ha2)

		if expectedResponse == response {
			next.ServeHTTP(w, r)
			return
		}

		log.Printf("response does not match: expected=%s, got=%s\n", expectedResponse, response)

		unauthorized(w)
	})
}

func unauthorized(w http.ResponseWriter) {
	// handle authenticate value
	realm := "admin"
	nonce, err := generateNonce()
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	authValue := fmt.Sprintf("Digest realm=\"%s\",\n"+
		"nonce=\"%s\",\n"+
		"algorithm=\"%s\",\n"+
		"qop=\"%s\",\n"+
		"charset=\"UTF-8\",\n"+
		"usernameHashing=\"%v\"",
		realm, nonce, hashAlgorithm, qop, usernameHashing)
	w.Header().Set("WWW-Authenticate", authValue)
	http.Error(w, "Unauthorized", http.StatusUnauthorized)
}

func register(w http.ResponseWriter, r *http.Request) {
	var user User
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&user); err != nil {
		http.Error(w, "Malformed JSON", http.StatusUnprocessableEntity)
		return
	}

	// validate
	user.Username = strings.TrimSpace(user.Username)
	if user.Username == "" || user.Password == "" {
		http.Error(w, "username and password are required", http.StatusUnprocessableEntity)
		return
	}

	// check user exists
	_, exists := userStore[user.Username]
	if exists {
		http.Error(w, "username is already used", http.StatusConflict)
		return
	}

	userStore[user.Username] = user
	w.WriteHeader(http.StatusCreated)
	log.Printf("Register user: %s\n", user.Username)
}

func private(w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, "private\n")
}

func public(w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, "public\n")
}

func main() {
	// seed user db
	adminUser := User{
		Username: "admin",
		Password: "admin",
	}
	userStore["admin"] = adminUser

	http.Handle("GET /private", authenticated(http.HandlerFunc(private)))
	http.HandleFunc("POST /register", register)
	http.HandleFunc("GET /public", public)

	log.Println("Starting DIGEST authentication example...")
	log.Println("listening on http://localhost:8888")
	http.ListenAndServe(":8888", nil)
}
