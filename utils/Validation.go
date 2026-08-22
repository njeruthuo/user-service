package utils

import (
	"net/mail"
	"regexp"
	"strings"
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
