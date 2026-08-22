package utils

import (
	"testing"
)

func Test_Valid_Emails(t *testing.T) {
	tests := []struct {
		name           string
		parameter      string
		expectedResult bool
	}{
		{
			name:           "Test email IS valid",
			parameter:      "juliusn411@gmail.com",
			expectedResult: true,
		},
		{
			name:           "Test email IS NOT valid",
			parameter:      "juliusnone",
			expectedResult: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsValidEmail(tt.parameter)
			if got != tt.expectedResult {
				t.Errorf("IsValidEmail(%q) = %v; want %v", tt.parameter, got, tt.expectedResult)
			}
		})

	}
}
func Test_Valid_Phone_Number(t *testing.T) {
	tests := []struct {
		name           string
		parameter      string
		expectedResult bool
	}{
		{
			name:           "Test phone number IS valid",
			parameter:      "0768585724",
			expectedResult: true,
		},
		{
			name:           "Test phone number IS valid",
			parameter:      "+254768585724",
			expectedResult: true,
		},
		{
			name:           "Test phone number IS valid",
			parameter:      "+254 768 585 724",
			expectedResult: true,
		},
		{
			name:           "Test phone number IS NOT valid",
			parameter:      "07 68 585 724",
			expectedResult: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsValidPhone(tt.parameter)
			if got != tt.expectedResult {
				t.Errorf("IsValidEmail(%q) = %v; want %v", tt.parameter, got, tt.expectedResult)
			}
		})

	}
}
