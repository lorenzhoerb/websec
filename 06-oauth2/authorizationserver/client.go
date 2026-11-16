package main

import (
	"errors"
	"slices"
)

type Client struct {
	ID            string
	RedirectURIs  []string
	Enabled       bool
	AllowedScopes []string
}

var clients = make(map[string]Client)

func GetClient(clientID string) (Client, bool) {
	client, ok := clients[clientID]
	return client, ok
}

func GetRegisteredRegisteredURIs(clientID string) ([]string, bool) {
	client, ok := clients[clientID]
	return client.RedirectURIs, ok
}

func RegisterClient(client Client) error {
	_, exists := clients[client.ID]
	if exists {
		return errors.New("could not register client: client already present" + client.ID)
	}

	clients[client.ID] = client
	return nil
}

func (c *Client) AllowsScopes(scopes []string) bool {
	for _, slice := range scopes {
		if !slices.Contains(c.AllowedScopes, slice) {
			return false
		}
	}
	return true
}

func (c *Client) HasRedirectURI(uri string) bool {
	return slices.Contains(c.RedirectURIs, uri)
}
