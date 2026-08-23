package authentication

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
	"github.com/lib/pq"
	"github.com/njeruthuo/user-service/utils"
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

const (
	testPassword = "mygoodpassword"
	testEmail    = "julius@domain.com"
	testPhone    = "0768585724"
)

var loginColumns = []string{
	"id", "email", "phone", "password_hash",
	"status", "phone_verified", "email_verified",
	"created_at", "updated_at",
}

// newLoginTest wires a handler to a fresh sqlmock so each subtest owns its own
// set of expectations.
func newLoginTest(t *testing.T) (*DBHandler, sqlmock.Sqlmock) {
	t.Helper()

	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to open sqlmock: %v", err)
	}

	t.Cleanup(func() {
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Errorf("there were unfulfilled sql expectations: %s", err)
		}
		db.Close()
	})

	return &DBHandler{DB: db}, mock
}

// loginRow builds the row the login query scans, with a real bcrypt hash so
// the password check behaves exactly as it does in production.
func loginRow(t *testing.T, id uuid.UUID, status string) *sqlmock.Rows {
	t.Helper()

	hash, err := utils.PasswordDigest(testPassword)
	if err != nil {
		t.Fatalf("failed to hash test password: %v", err)
	}

	return sqlmock.NewRows(loginColumns).AddRow(
		id, testEmail, testPhone, hash,
		status, true, true, time.Now(), time.Now(),
	)
}

func doLogin(t *testing.T, handler *DBHandler, payload string) *httptest.ResponseRecorder {
	t.Helper()

	req := httptest.NewRequest(http.MethodPost, "/auth/login", strings.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.LoginHandler(w, req)

	return w
}

func decodeMessage(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()

	var res AuthJsonResponse
	if err := json.NewDecoder(w.Body).Decode(&res); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	return res.Message
}

func Test_LoginHandler_Validation(t *testing.T) {
	tests := []struct {
		name           string
		payload        string
		expectedStatus int
		expectedMsg    string
	}{
		{
			name:           "Invalid JSON body",
			payload:        `{"email": "test@example.com",`,
			expectedStatus: http.StatusBadRequest,
			expectedMsg:    "Invalid request body",
		},
		{
			name:           "Invalid phone for phone login method",
			payload:        `{"phone": "invalid-phone", "password": "mygoodpassword", "loginMethod": "phone"}`,
			expectedStatus: http.StatusBadRequest,
			expectedMsg:    "Invalid phone",
		},
		{
			name:           "Missing phone for phone login method",
			payload:        `{"password": "mygoodpassword", "loginMethod": "phone"}`,
			expectedStatus: http.StatusBadRequest,
			expectedMsg:    "Invalid phone",
		},
		{
			name:           "Invalid email for email login method",
			payload:        `{"email": "not-an-email", "password": "mygoodpassword", "loginMethod": "email"}`,
			expectedStatus: http.StatusBadRequest,
			expectedMsg:    "Invalid email",
		},
		{
			name:           "Missing email for email login method",
			payload:        `{"password": "mygoodpassword", "loginMethod": "email"}`,
			expectedStatus: http.StatusBadRequest,
			expectedMsg:    "Invalid email",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// No query should reach the database during validation.
			handler, _ := newLoginTest(t)

			w := doLogin(t, handler, tt.payload)

			if w.Code != tt.expectedStatus {
				t.Errorf("expected status %d, got %d", tt.expectedStatus, w.Code)
			}

			if msg := decodeMessage(t, w); msg != tt.expectedMsg {
				t.Errorf("expected message %q, got %q", tt.expectedMsg, msg)
			}
		})
	}
}

// assertTokenPair checks the handler returned a usable pair of signed tokens
// carrying the identity of the user that just logged in.
func assertTokenPair(t *testing.T, w *httptest.ResponseRecorder, userID uuid.UUID) {
	t.Helper()

	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("expected Content-Type application/json, got %q", ct)
	}

	var res UserLoginResponse
	if err := json.NewDecoder(w.Body).Decode(&res); err != nil {
		t.Fatalf("failed to decode login response: %v", err)
	}

	if res.AccessToken == "" {
		t.Fatal("expected an access token, got an empty string")
	}

	if res.RefreshToken == "" {
		t.Fatal("expected a refresh token, got an empty string")
	}

	if res.AccessToken == res.RefreshToken {
		t.Error("access and refresh tokens should not be identical")
	}

	cases := []struct {
		token     string
		tokenType string
		ttl       time.Duration
	}{
		{res.AccessToken, utils.AccessTokenType, utils.AccessTokenTTL},
		{res.RefreshToken, utils.RefreshTokenType, utils.RefreshTokenTTL},
	}

	for _, c := range cases {
		claims, err := utils.ParseToken(c.token)
		if err != nil {
			t.Fatalf("%s token failed to parse: %v", c.tokenType, err)
		}

		if claims.Subject != userID.String() {
			t.Errorf("%s token: expected subject %q, got %q", c.tokenType, userID, claims.Subject)
		}

		if claims.Email != testEmail {
			t.Errorf("%s token: expected email %q, got %q", c.tokenType, testEmail, claims.Email)
		}

		if claims.Phone != testPhone {
			t.Errorf("%s token: expected phone %q, got %q", c.tokenType, testPhone, claims.Phone)
		}

		if claims.TokenType != c.tokenType {
			t.Errorf("expected token_type %q, got %q", c.tokenType, claims.TokenType)
		}

		if claims.ExpiresAt == nil {
			t.Fatalf("%s token: expected an expiry claim", c.tokenType)
		}

		// Allow a small window for the time elapsed during the request.
		expiresIn := time.Until(claims.ExpiresAt.Time)
		if expiresIn <= c.ttl-time.Minute || expiresIn > c.ttl {
			t.Errorf("%s token: expected expiry ~%s out, got %s", c.tokenType, c.ttl, expiresIn)
		}
	}
}

func Test_LoginHandler_Returns_Tokens_On_Success(t *testing.T) {
	t.Run("Successful login via email", func(t *testing.T) {
		handler, mock := newLoginTest(t)
		userID := uuid.New()

		mock.ExpectQuery(`SELECT (.+) FROM users\s+WHERE email = \$1`).
			WithArgs(testEmail).
			WillReturnRows(loginRow(t, userID, "active"))

		payload := `{"email": "` + testEmail + `", "password": "` + testPassword + `", "loginMethod": "email"}`
		w := doLogin(t, handler, payload)

		if w.Code != http.StatusOK {
			t.Fatalf("expected status %d, got %d", http.StatusOK, w.Code)
		}

		assertTokenPair(t, w, userID)
	})

	t.Run("Successful login via phone", func(t *testing.T) {
		handler, mock := newLoginTest(t)
		userID := uuid.New()

		mock.ExpectQuery(`SELECT (.+) FROM users\s+WHERE phone = \$1`).
			WithArgs(testPhone).
			WillReturnRows(loginRow(t, userID, "active"))

		payload := `{"phone": "` + testPhone + `", "password": "` + testPassword + `", "loginMethod": "phone"}`
		w := doLogin(t, handler, payload)

		if w.Code != http.StatusOK {
			t.Fatalf("expected status %d, got %d", http.StatusOK, w.Code)
		}

		assertTokenPair(t, w, userID)
	})
}

func Test_LoginHandler_DatabasePaths(t *testing.T) {
	t.Run("Unknown user returns 401", func(t *testing.T) {
		handler, mock := newLoginTest(t)

		mock.ExpectQuery(`SELECT (.+) FROM users\s+WHERE email = \$1`).
			WithArgs("notfound@domain.com").
			WillReturnError(sql.ErrNoRows)

		w := doLogin(t, handler, `{"email": "notfound@domain.com", "password": "`+testPassword+`", "loginMethod": "email"}`)

		if w.Code != http.StatusUnauthorized {
			t.Fatalf("expected status %d, got %d", http.StatusUnauthorized, w.Code)
		}

		if msg := decodeMessage(t, w); msg != "Invalid credentials" {
			t.Errorf("expected message %q, got %q", "Invalid credentials", msg)
		}
	})

	t.Run("Wrong password returns 401", func(t *testing.T) {
		handler, mock := newLoginTest(t)

		mock.ExpectQuery(`SELECT (.+) FROM users\s+WHERE email = \$1`).
			WithArgs(testEmail).
			WillReturnRows(loginRow(t, uuid.New(), "active"))

		w := doLogin(t, handler, `{"email": "`+testEmail+`", "password": "definitely-not-the-password", "loginMethod": "email"}`)

		if w.Code != http.StatusUnauthorized {
			t.Fatalf("expected status %d, got %d", http.StatusUnauthorized, w.Code)
		}

		if msg := decodeMessage(t, w); msg != "Invalid credentials" {
			t.Errorf("expected message %q, got %q", "Invalid credentials", msg)
		}
	})

	t.Run("Disabled account returns 403", func(t *testing.T) {
		handler, mock := newLoginTest(t)

		mock.ExpectQuery(`SELECT (.+) FROM users\s+WHERE email = \$1`).
			WithArgs(testEmail).
			WillReturnRows(loginRow(t, uuid.New(), "disabled"))

		w := doLogin(t, handler, `{"email": "`+testEmail+`", "password": "`+testPassword+`", "loginMethod": "email"}`)

		if w.Code != http.StatusForbidden {
			t.Fatalf("expected status %d, got %d", http.StatusForbidden, w.Code)
		}

		if msg := decodeMessage(t, w); msg != "Account is not active" {
			t.Errorf("expected message %q, got %q", "Account is not active", msg)
		}
	})

	t.Run("Unexpected database error returns 500", func(t *testing.T) {
		handler, mock := newLoginTest(t)

		mock.ExpectQuery(`SELECT (.+) FROM users\s+WHERE phone = \$1`).
			WithArgs(testPhone).
			WillReturnError(errors.New("connection reset"))

		w := doLogin(t, handler, `{"phone": "`+testPhone+`", "password": "`+testPassword+`", "loginMethod": "phone"}`)

		if w.Code != http.StatusInternalServerError {
			t.Fatalf("expected status %d, got %d", http.StatusInternalServerError, w.Code)
		}

		if msg := decodeMessage(t, w); msg != "Internal server error" {
			t.Errorf("expected message %q, got %q", "Internal server error", msg)
		}
	})

	t.Run("No login method defaults to phone lookup", func(t *testing.T) {
		handler, mock := newLoginTest(t)
		userID := uuid.New()

		mock.ExpectQuery(`SELECT (.+) FROM users\s+WHERE phone = \$1`).
			WithArgs(testPhone).
			WillReturnRows(loginRow(t, userID, "active"))

		w := doLogin(t, handler, `{"phone": "`+testPhone+`", "password": "`+testPassword+`"}`)

		if w.Code != http.StatusOK {
			t.Fatalf("expected status %d, got %d", http.StatusOK, w.Code)
		}

		assertTokenPair(t, w, userID)
	})
}

// The login response must never leak the stored password hash.
func Test_LoginHandler_Response_Excludes_Password_Hash(t *testing.T) {
	handler, mock := newLoginTest(t)

	mock.ExpectQuery(`SELECT (.+) FROM users\s+WHERE email = \$1`).
		WithArgs(testEmail).
		WillReturnRows(loginRow(t, uuid.New(), "active"))

	w := doLogin(t, handler, `{"email": "`+testEmail+`", "password": "`+testPassword+`", "loginMethod": "email"}`)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	body := w.Body.String()
	for _, leaked := range []string{"password_hash", "$2a$", testPassword} {
		if strings.Contains(body, leaked) {
			t.Errorf("login response leaked %q: %s", leaked, body)
		}
	}
}
