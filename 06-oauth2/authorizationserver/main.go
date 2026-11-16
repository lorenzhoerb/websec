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

	mux := http.NewServeMux()

	// OAuth2 Endpoints
	mux.HandleFunc("GET "+MetadataEndpoint, MetadataHandler(config.Issuer))
	mux.HandleFunc("GET "+AuthorizeEndpoint, AuthorizeHandler)
	mux.HandleFunc("POST "+TokenEndpoint, TokenHandler)

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
		log.Fatal("failed to seed client: %v", client)
	}
	log.Printf("seeded client: %s\n", client.ID)
}
