package authentication

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func Test_Register_Requires_Email_And_Phone(t *testing.T) {
	tests := []struct {
		name           string
		payload        string
		expectedStatus int
		expectedMsg    string
	}{
		{
			name:           "Missing email",
			payload:        `{"phone": "+12345678901", "password": "password123"}`,
			expectedStatus: http.StatusBadRequest,
			expectedMsg:    "Invalid phone or email",
		},
		{
			name:           "Missing phone",
			payload:        `{"email": "test@example.com", "password": "password123"}`,
			expectedStatus: http.StatusBadRequest,
			expectedMsg:    "Invalid phone or email",
		},
		{
			name:           "Invalid email format",
			payload:        `{"email": "not-an-email", "phone": "+12345678901", "password": "password123"}`,
			expectedStatus: http.StatusBadRequest,
			expectedMsg:    "Invalid phone or email",
		},
		{
			name:           "Invalid JSON body",
			payload:        `{"email": "test@example.com",`,
			expectedStatus: http.StatusBadRequest,
			expectedMsg:    "Invalid request body",
		},
	}

	handler := &DBHandler{}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/auth/register", strings.NewReader(tt.payload))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			handler.RegisterHandler(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("expected %d, got %d", tt.expectedStatus, w.Code)
			}

			var res AuthJsonResponse
			if err := json.NewDecoder(w.Body).Decode(&res); err != nil {
				t.Fatalf("failed to decode response: %v", err)
			}

			if res.Message != tt.expectedMsg {
				t.Errorf("expected message %q, got %q", tt.expectedMsg, res.Message)
			}
		})
	}
}
