package main

import "os"

type Config struct {
	Host           string
	Port           string
	Issuer         string
	SigningKeyPath string // PEM RSA private key, empty = generate on startup
}

func LoadConfig() Config {
	cfg := Config{
		Host:           getEnv("HOST", "0.0.0.0"),
		Port:           getEnv("PORT", "8085"),
		Issuer:         getEnv("ISSUER", "http://localhost:8085"),
		SigningKeyPath: getEnv("SIGNING_KEY_PATH", ""),
	}

	return cfg
}

func getEnv(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}
