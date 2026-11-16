package main

import (
	"errors"
	"regexp"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

var ErrInvalidUsernameOrPassword = errors.New("invalid username or password")

type User struct {
	Username string
	Password string // hashed
}

var users = make(map[string]User)

func GetUser(username string) (User, bool) {
	user, ok := users[username]
	return user, ok
}

func RegisterUser(username, password string) error {
	username = strings.TrimSpace(username)
	if len(username) < 3 || len(username) > 30 {
		return errors.New("username must be between 3 and 30 characters")
	}
	if !regexp.MustCompile(`^[a-zA-Z0-9_]+$`).MatchString(username) {
		return errors.New("username can only contain letters, numbers and underscores")
	}
	if _, exists := users[username]; exists {
		return errors.New("username is already used")
	}
	hashedPassword, err := hashPassword(password)
	if err != nil {
		return errors.New("failed to create user")
	}
	users[username] = User{
		Username: username,
		Password: hashedPassword,
	}
	return nil
}

func Authenticate(username, password string) error {
	user, ok := GetUser(username)
	if !ok {
		return ErrInvalidUsernameOrPassword
	}

	authenticated := verifyPassword(password, user.Password)
	if authenticated {
		return nil
	}

	return ErrInvalidUsernameOrPassword
}

func hashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword(
		[]byte(password),
		bcrypt.DefaultCost,
	)
	return string(hash), err
}

func verifyPassword(password, hash string) bool {
	return bcrypt.CompareHashAndPassword(
		[]byte(hash),
		[]byte(password),
	) == nil
}
