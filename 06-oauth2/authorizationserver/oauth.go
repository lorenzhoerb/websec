package main

const (
	AuthorizeEndpoint = "/oauth2/authorize"
	TokenEndpoint     = "/oauth2/token"
	MetadataEndpoint  = "/.well-known/oauth-authorization-server"
)

var (
	SupportedResponseTypes        = []string{"code"}
	SupportedGrantTypes           = []string{"authorization_code"}
	SupportedCodeChallengeMethods = []string{"S256"}
)
