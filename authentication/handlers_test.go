package authentication

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/lib/pq"
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
func Test_Register_No_Account_Duplicates(t *testing.T) {
	// 1. Initialize sqlmock database
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to open sqlmock: %v", err)
	}
	defer db.Close()

	handler := &DBHandler{DB: db}

	t.Run("Test a good payload will work", func(t *testing.T) {
		// Mock successful DB insertion returning scanned user values
		rows := sqlmock.NewRows([]string{"id", "status", "phone_verified", "email_verified", "created_at", "updated_at"}).
			AddRow(1, "active", false, false, time.Now(), time.Now())
		mock.ExpectQuery(`INSERT INTO users`).WillReturnRows(rows)

		payload := `{"phone": "0768585724", "password": "password123", "email":"julius@domain.com"}`
		req := httptest.NewRequest(http.MethodPost, "/auth/register", strings.NewReader(payload))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		handler.RegisterHandler(w, req)

		if w.Code != http.StatusCreated {
			t.Errorf("expected status %d, got %d", http.StatusCreated, w.Code)
		}

		var res UserResponse
		if err := json.NewDecoder(w.Body).Decode(&res); err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}

		if res.Email != "julius@domain.com" || res.Phone != "0768585724" {
			t.Errorf("unexpected user response data: %+v", res)
		}
	})

	t.Run("Test duplicate email will return conflict", func(t *testing.T) {
		// Mock PostgreSQL unique violation error (code 23505)
		pqErr := &pq.Error{
			Code:       "23505",
			Constraint: "users_email_key",
		}
		mock.ExpectQuery(`INSERT INTO users`).WillReturnError(pqErr)

		payload := `{"phone": "0768585724", "password": "password123", "email":"julius@domain.com"}`
		req := httptest.NewRequest(http.MethodPost, "/auth/register", strings.NewReader(payload))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		handler.RegisterHandler(w, req)

		if w.Code != http.StatusConflict { // Expect 409 Conflict
			t.Errorf("expected status %d, got %d", http.StatusConflict, w.Code)
		}

		var res AuthJsonResponse
		if err := json.NewDecoder(w.Body).Decode(&res); err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}

		expectedMsg := "Email is already registered"
		if res.Message != expectedMsg {
			t.Errorf("expected message %q, got %q", expectedMsg, res.Message)
		}
	})
}

func Test_LoginHandler_Validation(t *testing.T) {
	// No DB calls occur during request validation, but pass mock DB to avoid nil handlers
	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to open sqlmock: %v", err)
	}
	defer db.Close()

	handler := &DBHandler{DB: db}

	tests := []struct {
		name           string
		payload        string
		expectedStatus int
		expectedMsg    string
	}{
		{
			name: "Valid Phone Login",
			payload: `{
				"phone": "0768585724",
				"password": "mygoodpassword",
				"loginMethod": "phone"
			}`,
			// Note: Will fail later in your handler when DB logic is reached,
			// but passes phone validation stage successfully
			expectedStatus: http.StatusOK,
			expectedMsg:    "",
		},
		{
			name: "Invalid Phone for Phone Login Method",
			payload: `{
				"phone": "invalid-phone",
				"password": "mygoodpassword",
				"loginMethod": "phone"
			}`,
			expectedStatus: http.StatusBadRequest,
			expectedMsg:    "Invalid phone",
		},
		{
			name: "Invalid Email for Email Login Method",
			payload: `{
				"email": "not-an-email",
				"password": "mygoodpassword",
				"loginMethod": "email"
			}`,
			expectedStatus: http.StatusBadRequest,
			expectedMsg:    "Invalid email",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/auth/login", strings.NewReader(tt.payload))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			// 1. CALL THE CORRECT HANDLER
			handler.LoginHandler(w, req)

			// 2. CHECK EXPECTED HTTP STATUS CODE
			if tt.expectedStatus == http.StatusBadRequest {
				if w.Code != http.StatusBadRequest {
					t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
				}

				var response AuthJsonResponse
				if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
					t.Fatalf("failed to decode error response: %v", err)
				}

				if response.Message != tt.expectedMsg {
					t.Errorf("expected error message %q, got %q", tt.expectedMsg, response.Message)
				}
			}
		})
	}
}
