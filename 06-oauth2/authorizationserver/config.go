package main

import "os"

type Config struct {
	Host   string
	Port   string
	Issuer string
}

func LoadConfig() Config {
	cfg := Config{
		Host:   getEnv("HOST", "0.0.0.0"),
		Port:   getEnv("PORT", "8085"),
		Issuer: getEnv("ISSUER", "http://localhost:8085"),
	}

	return cfg
}

func getEnv(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}
