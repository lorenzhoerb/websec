package main

import (
	"log"
	"net"
	"net/http"
)

func main() {
	config := LoadConfig()
	log.Printf("config: %+v\n", config)

	seedUsers()
	seedClients()

	signingKey, err := LoadSigningKey(config.SigningKeyPath)
	if err != nil {
		log.Fatalf("failed to load signing key: %v", err)
	}
	if config.SigningKeyPath == "" {
		log.Println("no SIGNING_KEY_PATH set, generated a temporary signing key")
	}
	log.Printf("signing key kid: %s\n", signingKey.ID)

	mux := http.NewServeMux()

	// OAuth2 Endpoints
	mux.HandleFunc("GET "+MetadataEndpoint, MetadataHandler(config.Issuer))
	mux.HandleFunc("GET "+JWKSEndpoint, JWKSHandler(signingKey))
	mux.HandleFunc("GET "+AuthorizeEndpoint, AuthorizeHandler)
	mux.HandleFunc("POST "+TokenEndpoint, withCORS(TokenHandler(config.Issuer, signingKey)))
	mux.HandleFunc("OPTIONS "+TokenEndpoint, withCORS(func(w http.ResponseWriter, r *http.Request) {}))

	// Authentication Endpoints
	mux.HandleFunc("GET /login", LoginPage)
	mux.HandleFunc("POST /login", LoginSubmitHandler)
	mux.HandleFunc("POST /logout", LogoutHandler)

	// Start Server
	addr := net.JoinHostPort(config.Host, config.Port)
	log.Println("Starting authorization server...")
	log.Printf("listening on %s\n", addr)
	http.ListenAndServe(addr, mux)
}

// Allow cors for testing with oauthdebugger.com
func withCORS(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Origin") == "https://oauthdebugger.com" {
			w.Header().Set("Access-Control-Allow-Origin", "https://oauthdebugger.com")
			w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
			w.Header().Set("Access-Control-Allow-Private-Network", "true")
			w.Header().Set("Vary", "Origin")
		}
		next(w, r)
	}
}

func seedUsers() {
	if err := RegisterUser("admin", "admin"); err != nil {
		log.Fatalf("failed to seed admin user: %v", err)
	}
	log.Println("seeded users: admin")
}

func seedClients() {
	client := Client{
		ID:            "my-web-app",
		RedirectURIs:  []string{"http://localhost:8080/callback"},
		Enabled:       true,
		AllowedScopes: []string{"read:posts", "write:posts"},
	}
	if err := RegisterClient(client); err != nil {
		log.Fatalf("failed to seed client %s: %v", client.ID, err)
	}
	log.Printf("seeded client: %s\n", client.ID)

	clientOAuthDebugger := Client{
		ID:            "oauth2-debugger",
		RedirectURIs:  []string{"https://oauthdebugger.com/debug"},
		Enabled:       true,
		AllowedScopes: []string{"read:posts", "write:posts"},
	}
	if err := RegisterClient(clientOAuthDebugger); err != nil {
		log.Fatalf("failed to seed client %s: %v", clientOAuthDebugger.ID, err)
	}
	log.Printf("seeded client: %s\n", clientOAuthDebugger.ID)
}
