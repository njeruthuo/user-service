package utils

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

const (
	AccessTokenTTL  = 15 * time.Minute
	RefreshTokenTTL = 7 * 24 * time.Hour

	AccessTokenType  = "access"
	RefreshTokenType = "refresh"

	tokenIssuer = "user-service"

	// Used only when JWT_SECRET is unset, so local runs and tests work
	// without extra setup. Production must set JWT_SECRET.
	developmentSecret = "insecure-development-secret-do-not-use-in-production"
)

var ErrInvalidToken = errors.New("invalid token")

type TokenPair struct {
	AccessToken  string
	RefreshToken string
}

type Claims struct {
	Email     string `json:"email"`
	Phone     string `json:"phone"`
	TokenType string `json:"token_type"`
	jwt.RegisteredClaims
}

func jwtSecret() []byte {
	if secret := os.Getenv("JWT_SECRET"); secret != "" {
		return []byte(secret)
	}
	return []byte(developmentSecret)
}

func signToken(userID, email, phone, tokenType string, ttl time.Duration) (string, error) {
	now := time.Now()

	claims := Claims{
		Email:     email,
		Phone:     phone,
		TokenType: tokenType,
		RegisteredClaims: jwt.RegisteredClaims{
			// A unique id per token, so tokens minted for the same user in
			// the same second are still distinct values. Rotation depends on
			// the replacement differing from the token it replaces.
			ID:        uuid.NewString(),
			Subject:   userID,
			Issuer:    tokenIssuer,
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
		},
	}

	signed, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(jwtSecret())
	if err != nil {
		return "", fmt.Errorf("failed to sign %s token: %w", tokenType, err)
	}

	return signed, nil
}

// GenerateTokenPair issues a short lived access token and a longer lived
// refresh token for the given user.
func GenerateTokenPair(userID, email, phone string) (TokenPair, error) {
	accessToken, err := signToken(userID, email, phone, AccessTokenType, AccessTokenTTL)
	if err != nil {
		return TokenPair{}, err
	}

	refreshToken, err := signToken(userID, email, phone, RefreshTokenType, RefreshTokenTTL)
	if err != nil {
		return TokenPair{}, err
	}

	return TokenPair{AccessToken: accessToken, RefreshToken: refreshToken}, nil
}

// ParseToken validates a signed token and returns its claims.
func ParseToken(tokenString string) (*Claims, error) {
	var claims Claims

	_, err := jwt.ParseWithClaims(
		tokenString,
		&claims,
		func(token *jwt.Token) (any, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("%w: unexpected signing method %v", ErrInvalidToken, token.Header["alg"])
			}
			return jwtSecret(), nil
		},
		jwt.WithIssuer(tokenIssuer),
	)

	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrInvalidToken, err)
	}

	return &claims, nil
}

// HashToken returns the digest stored in place of a token. Tokens are long,
// high entropy strings, so a fast digest is both safe and directly lookupable,
// unlike the bcrypt hashing used for user chosen passwords.
func HashToken(token string) string {
	digest := sha256.Sum256([]byte(token))
	return hex.EncodeToString(digest[:])
}
