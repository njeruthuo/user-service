package utils

import (
	"net/mail"
	"regexp"
	"strings"
)

const (
	minPasswordLength     = 8
	maxPasswordLength     = 72
	
)

func IsValidEmail(email string) bool {
	email = strings.TrimSpace(email)

	if email == "" {
		return false
	}

	addr, err := mail.ParseAddress(email)
	if err != nil {
		return false
	}

	return addr.Address == email
}

var phoneRegex = regexp.MustCompile(`^(?:\+254\s\d{3}\s\d{3}\s\d{3}|07\d{8}|\+254\d{9})$`)

func IsValidPhone(phone string) bool {
	return phoneRegex.MatchString(phone)
}

func ValidatePassword(password string) string {
	if len(password) < minPasswordLength {
		return "Password must be at least 8 characters"
	}

	// Measured in bytes, because that is the limit bcrypt actually imposes.
	if len(password) > maxPasswordLength {
		return "Password must be at most 72 bytes"
	}

	return ""
}
