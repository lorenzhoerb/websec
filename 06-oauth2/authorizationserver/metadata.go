package main

import (
	"encoding/json"
	"net/http"
)

type Metadata struct {
	Issuer                        string   `json:"issuer"`
	AuthorizationEndpoint         string   `json:"authorization_endpoint"`
	TokenEndpoint                 string   `json:"token_endpoint"`
	ResponseTypesSupported        []string `json:"response_types_supported"`
	GrantTypesSupported           []string `json:"grant_types_supported"`
	CodeChallengeMethodsSupported []string `json:"code_challenge_methods_supported"`
}

func MetadataHandler(issuer string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		metadata := Metadata{
			Issuer:                        issuer,
			AuthorizationEndpoint:         issuer + AuthorizeEndpoint,
			TokenEndpoint:                 issuer + TokenEndpoint,
			ResponseTypesSupported:        SupportedResponseTypes,
			GrantTypesSupported:           SupportedGrantTypes,
			CodeChallengeMethodsSupported: SupportedCodeChallengeMethods,
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(metadata)
	}
}
