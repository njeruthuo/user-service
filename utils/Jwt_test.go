package utils

import (
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func Test_GenerateTokenPair(t *testing.T) {
	userID := "6f1c1c8e-1b7a-4f4b-9a1a-4c1f0a2b3c4d"

	pair, err := GenerateTokenPair(userID, "julius@domain.com", "0768585724")
	if err != nil {
		t.Fatalf("GenerateTokenPair returned an error: %v", err)
	}

	tests := []struct {
		name      string
		token     string
		tokenType string
		ttl       time.Duration
	}{
		{"access token", pair.AccessToken, AccessTokenType, AccessTokenTTL},
		{"refresh token", pair.RefreshToken, RefreshTokenType, RefreshTokenTTL},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.token == "" {
				t.Fatal("expected a signed token, got an empty string")
			}

			claims, err := ParseToken(tt.token)
			if err != nil {
				t.Fatalf("ParseToken returned an error: %v", err)
			}

			if claims.Subject != userID {
				t.Errorf("expected subject %q, got %q", userID, claims.Subject)
			}

			if claims.Email != "julius@domain.com" {
				t.Errorf("expected email %q, got %q", "julius@domain.com", claims.Email)
			}

			if claims.Phone != "0768585724" {
				t.Errorf("expected phone %q, got %q", "0768585724", claims.Phone)
			}

			if claims.TokenType != tt.tokenType {
				t.Errorf("expected token type %q, got %q", tt.tokenType, claims.TokenType)
			}

			if claims.Issuer != tokenIssuer {
				t.Errorf("expected issuer %q, got %q", tokenIssuer, claims.Issuer)
			}

			if claims.ExpiresAt == nil {
				t.Fatal("expected an expiry claim")
			}

			expiresIn := time.Until(claims.ExpiresAt.Time)
			if expiresIn <= tt.ttl-time.Minute || expiresIn > tt.ttl {
				t.Errorf("expected expiry ~%s out, got %s", tt.ttl, expiresIn)
			}
		})
	}

	if pair.AccessToken == pair.RefreshToken {
		t.Error("access and refresh tokens should not be identical")
	}
}

func Test_ParseToken_Rejects_Bad_Tokens(t *testing.T) {
	valid, err := GenerateTokenPair("user-id", "julius@domain.com", "0768585724")
	if err != nil {
		t.Fatalf("GenerateTokenPair returned an error: %v", err)
	}

	expired := signedWith(t, jwt.SigningMethodHS256, jwtSecret(), -time.Hour)
	wrongSecret := signedWith(t, jwt.SigningMethodHS256, []byte("some-other-secret"), time.Hour)

	// A token the caller signed themselves with "alg": "none".
	unsigned, err := jwt.NewWithClaims(jwt.SigningMethodNone, Claims{
		TokenType: AccessTokenType,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "user-id",
			Issuer:    tokenIssuer,
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
	}).SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatalf("failed to build unsigned token: %v", err)
	}

	tests := []struct {
		name  string
		token string
	}{
		{"empty token", ""},
		{"garbage token", "not-a-jwt"},
		{"tampered payload", valid.AccessToken[:len(valid.AccessToken)-3] + "abc"},
		{"expired token", expired},
		{"signed with a different secret", wrongSecret},
		{"unsigned alg none token", unsigned},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			claims, err := ParseToken(tt.token)

			if err == nil {
				t.Fatalf("expected ParseToken to reject the token, got claims %+v", claims)
			}

			if !strings.Contains(err.Error(), ErrInvalidToken.Error()) {
				t.Errorf("expected an invalid token error, got %v", err)
			}
		})
	}
}

func signedWith(t *testing.T, method jwt.SigningMethod, secret []byte, ttl time.Duration) string {
	t.Helper()

	now := time.Now()

	token, err := jwt.NewWithClaims(method, Claims{
		TokenType: AccessTokenType,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "user-id",
			Issuer:    tokenIssuer,
			IssuedAt:  jwt.NewNumericDate(now.Add(-2 * time.Hour)),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
		},
	}).SignedString(secret)

	if err != nil {
		t.Fatalf("failed to sign test token: %v", err)
	}

	return token
}

func Test_JwtSecret_Prefers_Environment(t *testing.T) {
	t.Setenv("JWT_SECRET", "a-configured-secret")

	if got := string(jwtSecret()); got != "a-configured-secret" {
		t.Errorf("expected the configured secret, got %q", got)
	}

	t.Setenv("JWT_SECRET", "")

	if got := string(jwtSecret()); got != developmentSecret {
		t.Errorf("expected the development fallback, got %q", got)
	}
}

// Rotation replaces a refresh token with a new one, so tokens minted back to
// back for the same user must never come out identical.
func Test_GenerateTokenPair_Produces_Unique_Tokens(t *testing.T) {
	userID := "6f1c1c8e-1b7a-4f4b-9a1a-4c1f0a2b3c4d"

	first, err := GenerateTokenPair(userID, "julius@domain.com", "0768585724")
	if err != nil {
		t.Fatalf("GenerateTokenPair returned an error: %v", err)
	}

	second, err := GenerateTokenPair(userID, "julius@domain.com", "0768585724")
	if err != nil {
		t.Fatalf("GenerateTokenPair returned an error: %v", err)
	}

	if first.RefreshToken == second.RefreshToken {
		t.Error("two refresh tokens for the same user were identical")
	}

	if first.AccessToken == second.AccessToken {
		t.Error("two access tokens for the same user were identical")
	}

	if HashToken(first.RefreshToken) == HashToken(second.RefreshToken) {
		t.Error("distinct refresh tokens produced the same hash")
	}

	claims, err := ParseToken(second.RefreshToken)
	if err != nil {
		t.Fatalf("ParseToken returned an error: %v", err)
	}

	if claims.ID == "" {
		t.Error("expected a unique jti claim on the token")
	}
}

func Test_HashToken(t *testing.T) {
	const token = "a-refresh-token"

	hash := HashToken(token)

	if hash == token {
		t.Error("HashToken returned the token unchanged")
	}

	// SHA-256 hex digest.
	if len(hash) != 64 {
		t.Errorf("expected a 64 character digest, got %d characters", len(hash))
	}

	if hash != HashToken(token) {
		t.Error("HashToken is not deterministic")
	}

	if hash == HashToken("a-different-token") {
		t.Error("different tokens produced the same digest")
	}
}
