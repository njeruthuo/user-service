package utils

import (
	"testing"
)

func Test_Password_Digest(t *testing.T) {
	tests := []struct {
		name      string
		password  string
		expectErr bool
	}{
		{
			name:      "Valid standard password",
			password:  "securePassword123!",
			expectErr: false,
		},
		{
			name:      "Valid short password",
			password:  "a",
			expectErr: false,
		},
		{
			name:      "Valid password with special characters and spaces",
			password:  "P@ssw0rd  With Space & Symbols #$%^",
			expectErr: false,
		},
		{
			name:      "Password exceeding bcrypt 72-byte limit",
			password:  "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", // 73 chars
			expectErr: true,                                                                        // Requires PasswordDigest to explicitly check len(password) > 72
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hash, err := PasswordDigest(tt.password)

			if tt.expectErr {
				if err == nil {
					t.Errorf("PasswordDigest(%q) expected error, got nil", tt.password)
				}
				return
			}

			if err != nil {
				t.Fatalf("PasswordDigest(%q) unexpected error: %v", tt.password, err)
			}

			if len(hash) == 0 {
				t.Errorf("PasswordDigest(%q) returned an empty hash", tt.password)
			}

			if !CheckPasswordHash(tt.password, hash) {
				t.Errorf("PasswordDigest(%q) generated a hash that failed verification", tt.password)
			}
		})
	}
}
