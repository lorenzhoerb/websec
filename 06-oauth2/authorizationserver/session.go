package main

import (
	"crypto/rand"
	"encoding/hex"
	"time"
)

const SessionTTL = 1 * time.Hour

type Session struct {
	Username  string
	expiresAt time.Time
}

var sessions = make(map[string]Session)

func RevokeSession(sessionID string) {
	delete(sessions, sessionID)
}

func GetSession(sessionID string) (Session, bool) {
	session, ok := sessions[sessionID]
	return session, ok
}

func CreateSession(username string) (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}

	sessionID := hex.EncodeToString(b)
	session := Session{
		Username:  username,
		expiresAt: time.Now().Add(SessionTTL),
	}

	sessions[sessionID] = session

	return sessionID, nil
}
