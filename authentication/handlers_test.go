package authentication

import (
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/lib/pq"
	"github.com/njeruthuo/user-service/datatypes"
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
	handler, mock := newLoginTest(t)

	t.Run("Test a good payload will work", func(t *testing.T) {
		userID := uuid.New()

		rows := sqlmock.NewRows([]string{"id", "status", "phone_verified", "email_verified", "created_at", "updated_at"}).
			AddRow(userID, "active", false, false, time.Now(), time.Now())
		mock.ExpectQuery(`INSERT INTO users`).WillReturnRows(rows)

		payload := `{"phone": "0768585724", "password": "password123", "email":"julius@domain.com"}`
		req := httptest.NewRequest(http.MethodPost, "/auth/register", strings.NewReader(payload))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		handler.RegisterHandler(w, req)

		if w.Code != http.StatusCreated {
			t.Errorf("expected status %d, got %d", http.StatusCreated, w.Code)
		}

		var res datatypes.UserResponse
		if err := json.NewDecoder(w.Body).Decode(&res); err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}

		if res.ID != userID {
			t.Errorf("expected the id the database assigned, got %v", res.ID)
		}

		if res.Email != "julius@domain.com" || res.Phone != "0768585724" {
			t.Errorf("unexpected user response data: %+v", res)
		}
	})

	t.Run("A registration never echoes the password", func(t *testing.T) {
		mock.ExpectQuery(`INSERT INTO users`).WillReturnRows(
			sqlmock.NewRows([]string{"id", "status", "phone_verified", "email_verified", "created_at", "updated_at"}).
				AddRow(uuid.New(), "active", false, false, time.Now(), time.Now()),
		)

		payload := `{"phone": "0768585724", "password": "` + testPassword + `", "email":"julius@domain.com"}`
		req := httptest.NewRequest(http.MethodPost, "/auth/register", strings.NewReader(payload))
		w := httptest.NewRecorder()

		handler.RegisterHandler(w, req)

		if strings.Contains(w.Body.String(), testPassword) || strings.Contains(w.Body.String(), "password") {
			t.Errorf("registration response leaked password material: %s", w.Body.String())
		}
	})
}

func Test_Register_Conflicts_And_Failures(t *testing.T) {
	payload := `{"phone": "0768585724", "password": "password123", "email":"julius@domain.com"}`

	tests := []struct {
		name           string
		dbError        error
		expectedStatus int
		expectedMsg    string
	}{
		{
			name:           "Duplicate email",
			dbError:        &pq.Error{Code: "23505", Constraint: "users_email_key"},
			expectedStatus: http.StatusConflict,
			expectedMsg:    "Email is already registered",
		},
		{
			name:           "Duplicate phone",
			dbError:        &pq.Error{Code: "23505", Constraint: "users_phone_key"},
			expectedStatus: http.StatusConflict,
			expectedMsg:    "Phone number is already registered",
		},
		{
			// Some other unique index the handler does not know by name.
			name:           "Unique violation on an unknown constraint",
			dbError:        &pq.Error{Code: "23505", Constraint: "users_something_key"},
			expectedStatus: http.StatusConflict,
			expectedMsg:    "User already exists",
		},
		{
			// Not a duplicate at all: answering 201 here would tell the caller
			// an account exists that was never written.
			name:           "Constraint violation that is not a duplicate",
			dbError:        &pq.Error{Code: "23514", Constraint: "users_status_check"},
			expectedStatus: http.StatusInternalServerError,
			expectedMsg:    "Internal server error",
		},
		{
			name:           "Connection failure",
			dbError:        errors.New("connection reset"),
			expectedStatus: http.StatusInternalServerError,
			expectedMsg:    "Internal server error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler, mock := newLoginTest(t)

			mock.ExpectQuery(`INSERT INTO users`).WillReturnError(tt.dbError)

			req := httptest.NewRequest(http.MethodPost, "/auth/register", strings.NewReader(payload))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			handler.RegisterHandler(w, req)

			if w.Code != tt.expectedStatus {
				t.Fatalf("expected status %d, got %d (body: %s)", tt.expectedStatus, w.Code, w.Body.String())
			}

			if msg := decodeMessage(t, w); msg != tt.expectedMsg {
				t.Errorf("expected message %q, got %q", tt.expectedMsg, msg)
			}

			if got := w.Header().Get("Content-Type"); got != "application/json" {
				t.Errorf("expected Content-Type %q, got %q", "application/json", got)
			}
		})
	}
}

func Test_Register_Rejects_A_Password_Bcrypt_Cannot_Hash(t *testing.T) {
	// bcrypt refuses inputs longer than 72 bytes, so an over long password
	// has to be turned away rather than stored half hashed.
	handler, _ := newLoginTest(t)

	payload := `{"phone": "0768585724", "email":"julius@domain.com", "password": "` +
		strings.Repeat("a", 100) + `"}`

	req := httptest.NewRequest(http.MethodPost, "/auth/register", strings.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.RegisterHandler(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected status %d, got %d", http.StatusBadRequest, w.Code)
	}

	if msg := decodeMessage(t, w); msg != "Bad password" {
		t.Errorf("expected message %q, got %q", "Bad password", msg)
	}
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

// capturedArg matches any value while recording it, so a test can assert on
// the exact argument the handler passed to the driver.
type capturedArg struct {
	value driver.Value
}

func (c *capturedArg) Match(v driver.Value) bool {
	c.value = v
	return true
}

// expectRefreshTokenInsert expects the row written for a newly issued refresh
// token and returns the captured token hash.
func expectRefreshTokenInsert(mock sqlmock.Sqlmock, userID uuid.UUID) *capturedArg {
	hash := &capturedArg{}

	mock.ExpectExec(`INSERT INTO refresh_tokens`).
		WithArgs(userID, hash, sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(1, 1))

	return hash
}

// assertStoredHash checks the persisted digest belongs to the returned token
// and that the raw token itself was never written to the database.
func assertStoredHash(t *testing.T, captured *capturedArg, refreshToken string) {
	t.Helper()

	stored, ok := captured.value.(string)
	if !ok {
		t.Fatalf("expected the stored token hash to be a string, got %T", captured.value)
	}

	if stored == refreshToken {
		t.Fatal("the raw refresh token was stored instead of its hash")
	}

	if stored != utils.HashToken(refreshToken) {
		t.Errorf("stored hash %q does not match the issued refresh token", stored)
	}
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

func assertTokenPair(t *testing.T, w *httptest.ResponseRecorder, userID uuid.UUID) string {
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

	return res.RefreshToken
}

func Test_LoginHandler_Returns_Tokens_On_Success(t *testing.T) {
	t.Run("Successful login via email", func(t *testing.T) {
		handler, mock := newLoginTest(t)
		userID := uuid.New()

		mock.ExpectQuery(`SELECT (.+) FROM users\s+WHERE email = \$1`).
			WithArgs(testEmail).
			WillReturnRows(loginRow(t, userID, "active"))

		storedHash := expectRefreshTokenInsert(mock, userID)

		payload := `{"email": "` + testEmail + `", "password": "` + testPassword + `", "loginMethod": "email"}`
		w := doLogin(t, handler, payload)

		if w.Code != http.StatusOK {
			t.Fatalf("expected status %d, got %d", http.StatusOK, w.Code)
		}

		assertStoredHash(t, storedHash, assertTokenPair(t, w, userID))
	})

	t.Run("Successful login via phone", func(t *testing.T) {
		handler, mock := newLoginTest(t)
		userID := uuid.New()

		mock.ExpectQuery(`SELECT (.+) FROM users\s+WHERE phone = \$1`).
			WithArgs(testPhone).
			WillReturnRows(loginRow(t, userID, "active"))

		storedHash := expectRefreshTokenInsert(mock, userID)

		payload := `{"phone": "` + testPhone + `", "password": "` + testPassword + `", "loginMethod": "phone"}`
		w := doLogin(t, handler, payload)

		if w.Code != http.StatusOK {
			t.Fatalf("expected status %d, got %d", http.StatusOK, w.Code)
		}

		assertStoredHash(t, storedHash, assertTokenPair(t, w, userID))
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

		expectRefreshTokenInsert(mock, userID)

		w := doLogin(t, handler, `{"phone": "`+testPhone+`", "password": "`+testPassword+`"}`)

		if w.Code != http.StatusOK {
			t.Fatalf("expected status %d, got %d", http.StatusOK, w.Code)
		}

		assertTokenPair(t, w, userID)
	})
}

func Test_LoginHandler_Response_Excludes_Password_Hash(t *testing.T) {
	handler, mock := newLoginTest(t)

	userID := uuid.New()

	mock.ExpectQuery(`SELECT (.+) FROM users\s+WHERE email = \$1`).
		WithArgs(testEmail).
		WillReturnRows(loginRow(t, userID, "active"))

	expectRefreshTokenInsert(mock, userID)

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

func Test_LoginHandler_Fails_When_Refresh_Token_Cannot_Be_Stored(t *testing.T) {
	handler, mock := newLoginTest(t)
	userID := uuid.New()

	mock.ExpectQuery(`SELECT (.+) FROM users\s+WHERE email = \$1`).
		WithArgs(testEmail).
		WillReturnRows(loginRow(t, userID, "active"))

	mock.ExpectExec(`INSERT INTO refresh_tokens`).
		WillReturnError(errors.New("connection reset"))

	w := doLogin(t, handler, `{"email": "`+testEmail+`", "password": "`+testPassword+`", "loginMethod": "email"}`)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected status %d, got %d", http.StatusInternalServerError, w.Code)
	}

	if msg := decodeMessage(t, w); msg != "Internal server error" {
		t.Errorf("expected message %q, got %q", "Internal server error", msg)
	}

	// A token that could not be recorded must not be handed to the caller.
	if strings.Contains(w.Body.String(), "refreshToken") {
		t.Errorf("handler returned a token it failed to persist: %s", w.Body.String())
	}
}

var refreshTokenColumns = []string{"id", "user_id", "expires_at", "revoked_at"}

func doRefresh(t *testing.T, handler *DBHandler, payload string) *httptest.ResponseRecorder {
	t.Helper()

	req := httptest.NewRequest(http.MethodPost, "/auth/refresh", strings.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.RefreshTokenHandler(w, req)

	return w
}

// issueTokens mints a token pair for a user the way LoginHandler would.
func issueTokens(t *testing.T, userID uuid.UUID) utils.TokenPair {
	t.Helper()

	pair, err := utils.GenerateTokenPair(userID.String(), testEmail, testPhone)
	if err != nil {
		t.Fatalf("failed to generate tokens: %v", err)
	}

	return pair
}

func Test_RefreshTokenHandler_Rejects_Bad_Requests(t *testing.T) {
	userID := uuid.New()
	pair := issueTokens(t, userID)

	tests := []struct {
		name           string
		payload        string
		expectedStatus int
		expectedMsg    string
	}{
		{
			name:           "Invalid JSON body",
			payload:        `{"refreshToken":`,
			expectedStatus: http.StatusBadRequest,
			expectedMsg:    "Invalid request body",
		},
		{
			name:           "Missing refresh token",
			payload:        `{}`,
			expectedStatus: http.StatusBadRequest,
			expectedMsg:    "Refresh token is required",
		},
		{
			name:           "Unparseable token",
			payload:        `{"refreshToken": "not-a-jwt"}`,
			expectedStatus: http.StatusUnauthorized,
			expectedMsg:    "Invalid refresh token",
		},
		{
			name:           "Tampered token",
			payload:        `{"refreshToken": "` + pair.RefreshToken[:len(pair.RefreshToken)-3] + `abc"}`,
			expectedStatus: http.StatusUnauthorized,
			expectedMsg:    "Invalid refresh token",
		},
		{
			// An access token is signed with the same secret, so only the
			// token_type claim keeps it from being redeemed here.
			name:           "Access token presented as a refresh token",
			payload:        `{"refreshToken": "` + pair.AccessToken + `"}`,
			expectedStatus: http.StatusUnauthorized,
			expectedMsg:    "Invalid refresh token",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// None of these reach the database.
			handler, _ := newLoginTest(t)

			w := doRefresh(t, handler, tt.payload)

			if w.Code != tt.expectedStatus {
				t.Errorf("expected status %d, got %d", tt.expectedStatus, w.Code)
			}

			if msg := decodeMessage(t, w); msg != tt.expectedMsg {
				t.Errorf("expected message %q, got %q", tt.expectedMsg, msg)
			}
		})
	}
}

func Test_RefreshTokenHandler_Rotates_Tokens(t *testing.T) {
	handler, mock := newLoginTest(t)

	userID := uuid.New()
	oldPair := issueTokens(t, userID)
	tokenID := uuid.New()

	// The presented token is on record, live, and unrevoked.
	mock.ExpectQuery(`SELECT id, user_id, expires_at, revoked_at\s+FROM refresh_tokens`).
		WithArgs(utils.HashToken(oldPair.RefreshToken)).
		WillReturnRows(sqlmock.NewRows(refreshTokenColumns).AddRow(
			tokenID, userID, time.Now().Add(utils.RefreshTokenTTL), nil,
		))

	mock.ExpectQuery(`SELECT email, phone, status\s+FROM users`).
		WithArgs(userID).
		WillReturnRows(sqlmock.NewRows([]string{"email", "phone", "status"}).
			AddRow(testEmail, testPhone, "active"))

	mock.ExpectBegin()

	mock.ExpectExec(`UPDATE refresh_tokens\s+SET revoked_at = NOW\(\)\s+WHERE id = \$1`).
		WithArgs(tokenID).
		WillReturnResult(sqlmock.NewResult(0, 1))

	storedHash := expectRefreshTokenInsert(mock, userID)

	mock.ExpectCommit()

	w := doRefresh(t, handler, `{"refreshToken": "`+oldPair.RefreshToken+`"}`)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d (body: %s)", http.StatusOK, w.Code, w.Body.String())
	}

	newRefreshToken := assertTokenPair(t, w, userID)

	if newRefreshToken == oldPair.RefreshToken {
		t.Error("expected a rotated refresh token, got the one that was presented")
	}

	assertStoredHash(t, storedHash, newRefreshToken)
}

func Test_RefreshTokenHandler_DatabasePaths(t *testing.T) {
	userID := uuid.New()
	pair := issueTokens(t, userID)
	tokenHash := utils.HashToken(pair.RefreshToken)

	t.Run("Unknown token returns 401", func(t *testing.T) {
		handler, mock := newLoginTest(t)

		mock.ExpectQuery(`SELECT id, user_id, expires_at, revoked_at\s+FROM refresh_tokens`).
			WithArgs(tokenHash).
			WillReturnError(sql.ErrNoRows)

		w := doRefresh(t, handler, `{"refreshToken": "`+pair.RefreshToken+`"}`)

		if w.Code != http.StatusUnauthorized {
			t.Fatalf("expected status %d, got %d", http.StatusUnauthorized, w.Code)
		}

		if msg := decodeMessage(t, w); msg != "Invalid refresh token" {
			t.Errorf("expected message %q, got %q", "Invalid refresh token", msg)
		}
	})

	t.Run("Expired token returns 401", func(t *testing.T) {
		handler, mock := newLoginTest(t)

		// Still a structurally valid JWT, but the stored row has lapsed.
		mock.ExpectQuery(`SELECT id, user_id, expires_at, revoked_at\s+FROM refresh_tokens`).
			WithArgs(tokenHash).
			WillReturnRows(sqlmock.NewRows(refreshTokenColumns).AddRow(
				uuid.New(), userID, time.Now().Add(-time.Hour), nil,
			))

		w := doRefresh(t, handler, `{"refreshToken": "`+pair.RefreshToken+`"}`)

		if w.Code != http.StatusUnauthorized {
			t.Fatalf("expected status %d, got %d", http.StatusUnauthorized, w.Code)
		}

		if msg := decodeMessage(t, w); msg != "Refresh token has expired" {
			t.Errorf("expected message %q, got %q", "Refresh token has expired", msg)
		}
	})

	t.Run("Reused token revokes every session for the user", func(t *testing.T) {
		handler, mock := newLoginTest(t)

		mock.ExpectQuery(`SELECT id, user_id, expires_at, revoked_at\s+FROM refresh_tokens`).
			WithArgs(tokenHash).
			WillReturnRows(sqlmock.NewRows(refreshTokenColumns).AddRow(
				uuid.New(), userID, time.Now().Add(utils.RefreshTokenTTL), time.Now().Add(-time.Minute),
			))

		mock.ExpectExec(`UPDATE refresh_tokens\s+SET revoked_at = NOW\(\)\s+WHERE user_id = \$1 AND revoked_at IS NULL`).
			WithArgs(userID).
			WillReturnResult(sqlmock.NewResult(0, 3))

		w := doRefresh(t, handler, `{"refreshToken": "`+pair.RefreshToken+`"}`)

		if w.Code != http.StatusUnauthorized {
			t.Fatalf("expected status %d, got %d", http.StatusUnauthorized, w.Code)
		}

		if msg := decodeMessage(t, w); msg != "Invalid refresh token" {
			t.Errorf("expected message %q, got %q", "Invalid refresh token", msg)
		}
	})

	t.Run("Token rotated concurrently returns 401", func(t *testing.T) {
		handler, mock := newLoginTest(t)

		mock.ExpectQuery(`SELECT id, user_id, expires_at, revoked_at\s+FROM refresh_tokens`).
			WithArgs(tokenHash).
			WillReturnRows(sqlmock.NewRows(refreshTokenColumns).AddRow(
				uuid.New(), userID, time.Now().Add(utils.RefreshTokenTTL), nil,
			))

		mock.ExpectQuery(`SELECT email, phone, status\s+FROM users`).
			WithArgs(userID).
			WillReturnRows(sqlmock.NewRows([]string{"email", "phone", "status"}).
				AddRow(testEmail, testPhone, "active"))

		mock.ExpectBegin()

		// Another request revoked the row between the read and the update.
		mock.ExpectExec(`UPDATE refresh_tokens\s+SET revoked_at = NOW\(\)`).
			WillReturnResult(sqlmock.NewResult(0, 0))

		mock.ExpectRollback()

		w := doRefresh(t, handler, `{"refreshToken": "`+pair.RefreshToken+`"}`)

		if w.Code != http.StatusUnauthorized {
			t.Fatalf("expected status %d, got %d", http.StatusUnauthorized, w.Code)
		}

		if msg := decodeMessage(t, w); msg != "Invalid refresh token" {
			t.Errorf("expected message %q, got %q", "Invalid refresh token", msg)
		}
	})

	t.Run("Disabled account returns 403", func(t *testing.T) {
		handler, mock := newLoginTest(t)

		mock.ExpectQuery(`SELECT id, user_id, expires_at, revoked_at\s+FROM refresh_tokens`).
			WithArgs(tokenHash).
			WillReturnRows(sqlmock.NewRows(refreshTokenColumns).AddRow(
				uuid.New(), userID, time.Now().Add(utils.RefreshTokenTTL), nil,
			))

		mock.ExpectQuery(`SELECT email, phone, status\s+FROM users`).
			WithArgs(userID).
			WillReturnRows(sqlmock.NewRows([]string{"email", "phone", "status"}).
				AddRow(testEmail, testPhone, "disabled"))

		w := doRefresh(t, handler, `{"refreshToken": "`+pair.RefreshToken+`"}`)

		if w.Code != http.StatusForbidden {
			t.Fatalf("expected status %d, got %d", http.StatusForbidden, w.Code)
		}

		if msg := decodeMessage(t, w); msg != "Account is not active" {
			t.Errorf("expected message %q, got %q", "Account is not active", msg)
		}
	})

	t.Run("Deleted user returns 401", func(t *testing.T) {
		handler, mock := newLoginTest(t)

		mock.ExpectQuery(`SELECT id, user_id, expires_at, revoked_at\s+FROM refresh_tokens`).
			WithArgs(tokenHash).
			WillReturnRows(sqlmock.NewRows(refreshTokenColumns).AddRow(
				uuid.New(), userID, time.Now().Add(utils.RefreshTokenTTL), nil,
			))

		mock.ExpectQuery(`SELECT email, phone, status\s+FROM users`).
			WithArgs(userID).
			WillReturnError(sql.ErrNoRows)

		w := doRefresh(t, handler, `{"refreshToken": "`+pair.RefreshToken+`"}`)

		if w.Code != http.StatusUnauthorized {
			t.Fatalf("expected status %d, got %d", http.StatusUnauthorized, w.Code)
		}
	})

	t.Run("Unexpected database error returns 500", func(t *testing.T) {
		handler, mock := newLoginTest(t)

		mock.ExpectQuery(`SELECT id, user_id, expires_at, revoked_at\s+FROM refresh_tokens`).
			WithArgs(tokenHash).
			WillReturnError(errors.New("connection reset"))

		w := doRefresh(t, handler, `{"refreshToken": "`+pair.RefreshToken+`"}`)

		if w.Code != http.StatusInternalServerError {
			t.Fatalf("expected status %d, got %d", http.StatusInternalServerError, w.Code)
		}

		if msg := decodeMessage(t, w); msg != "Internal server error" {
			t.Errorf("expected message %q, got %q", "Internal server error", msg)
		}
	})

	t.Run("Failed commit returns 500 and no tokens", func(t *testing.T) {
		handler, mock := newLoginTest(t)

		mock.ExpectQuery(`SELECT id, user_id, expires_at, revoked_at\s+FROM refresh_tokens`).
			WithArgs(tokenHash).
			WillReturnRows(sqlmock.NewRows(refreshTokenColumns).AddRow(
				uuid.New(), userID, time.Now().Add(utils.RefreshTokenTTL), nil,
			))

		mock.ExpectQuery(`SELECT email, phone, status\s+FROM users`).
			WithArgs(userID).
			WillReturnRows(sqlmock.NewRows([]string{"email", "phone", "status"}).
				AddRow(testEmail, testPhone, "active"))

		mock.ExpectBegin()
		mock.ExpectExec(`UPDATE refresh_tokens`).WillReturnResult(sqlmock.NewResult(0, 1))
		mock.ExpectExec(`INSERT INTO refresh_tokens`).WillReturnResult(sqlmock.NewResult(1, 1))
		mock.ExpectCommit().WillReturnError(errors.New("connection reset"))

		w := doRefresh(t, handler, `{"refreshToken": "`+pair.RefreshToken+`"}`)

		if w.Code != http.StatusInternalServerError {
			t.Fatalf("expected status %d, got %d", http.StatusInternalServerError, w.Code)
		}

		if strings.Contains(w.Body.String(), "refreshToken") {
			t.Errorf("handler returned tokens from an uncommitted rotation: %s", w.Body.String())
		}
	})
}

func doLogout(t *testing.T, handler *DBHandler, payload string) *httptest.ResponseRecorder {
	t.Helper()

	req := httptest.NewRequest(http.MethodPost, "/auth/logout", strings.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.LogoutHandler(w, req)

	return w
}

// revokeByHashQuery matches the single statement logout is allowed to run: it
// revokes by token hash, and only rows that are still live.
const revokeByHashQuery = `UPDATE refresh_tokens\s+SET revoked_at = NOW\(\)\s+WHERE token_hash = \$1 AND revoked_at IS NULL`

func Test_LogoutHandler_Rejects_Bad_Requests(t *testing.T) {
	userID := uuid.New()
	pair := issueTokens(t, userID)

	tests := []struct {
		name           string
		payload        string
		expectedStatus int
		expectedMsg    string
	}{
		{
			name:           "Invalid JSON body",
			payload:        `{"refreshToken":`,
			expectedStatus: http.StatusBadRequest,
			expectedMsg:    "Invalid request body",
		},
		{
			name:           "Missing refresh token",
			payload:        `{}`,
			expectedStatus: http.StatusBadRequest,
			expectedMsg:    "Refresh token is required",
		},
		{
			name:           "Empty refresh token",
			payload:        `{"refreshToken": ""}`,
			expectedStatus: http.StatusBadRequest,
			expectedMsg:    "Refresh token is required",
		},
		{
			name:           "Unparseable token",
			payload:        `{"refreshToken": "not-a-jwt"}`,
			expectedStatus: http.StatusUnauthorized,
			expectedMsg:    "Invalid refresh token",
		},
		{
			// Signed with a different secret, so the signature check is the
			// only thing standing between a forged token and a revocation.
			name:           "Tampered token",
			payload:        `{"refreshToken": "` + pair.RefreshToken[:len(pair.RefreshToken)-3] + `abc"}`,
			expectedStatus: http.StatusUnauthorized,
			expectedMsg:    "Invalid refresh token",
		},
		{
			// An access token is signed with the same secret, so only the
			// token_type claim keeps it from revoking a session.
			name:           "Access token presented as a refresh token",
			payload:        `{"refreshToken": "` + pair.AccessToken + `"}`,
			expectedStatus: http.StatusUnauthorized,
			expectedMsg:    "Invalid refresh token",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// newLoginTest asserts no unexpected statements ran, which is the
			// point here: none of these requests may touch the database.
			handler, _ := newLoginTest(t)

			w := doLogout(t, handler, tt.payload)

			if w.Code != tt.expectedStatus {
				t.Errorf("expected status %d, got %d", tt.expectedStatus, w.Code)
			}

			if msg := decodeMessage(t, w); msg != tt.expectedMsg {
				t.Errorf("expected message %q, got %q", tt.expectedMsg, msg)
			}
		})
	}
}

func Test_LogoutHandler_Revokes_The_Presented_Token(t *testing.T) {
	handler, mock := newLoginTest(t)

	userID := uuid.New()
	pair := issueTokens(t, userID)

	mock.ExpectExec(revokeByHashQuery).
		WithArgs(utils.HashToken(pair.RefreshToken)).
		WillReturnResult(sqlmock.NewResult(0, 1))

	w := doLogout(t, handler, `{"refreshToken": "`+pair.RefreshToken+`"}`)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d (body: %s)", http.StatusOK, w.Code, w.Body.String())
	}

	if msg := decodeMessage(t, w); msg != "Logged out successfully" {
		t.Errorf("expected message %q, got %q", "Logged out successfully", msg)
	}

	if got := w.Header().Get("Content-Type"); got != "application/json" {
		t.Errorf("expected Content-Type %q, got %q", "application/json", got)
	}
}

func Test_LogoutHandler_Revokes_Only_That_Session(t *testing.T) {
	handler, mock := newLoginTest(t)

	userID := uuid.New()
	sessions := []utils.TokenPair{issueTokens(t, userID), issueTokens(t, userID)}

	revoked := &capturedArg{}

	mock.ExpectExec(revokeByHashQuery).
		WithArgs(revoked).
		WillReturnResult(sqlmock.NewResult(0, 1))

	w := doLogout(t, handler, `{"refreshToken": "`+sessions[0].RefreshToken+`"}`)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status %d, got %d", http.StatusOK, w.Code)
	}

	if revoked.value != utils.HashToken(sessions[0].RefreshToken) {
		t.Errorf("expected the presented token to be revoked, got %v", revoked.value)
	}

	if revoked.value == utils.HashToken(sessions[1].RefreshToken) {
		t.Error("logout revoked a different session belonging to the same user")
	}
}

func Test_LogoutHandler_Is_Idempotent(t *testing.T) {
	userID := uuid.New()
	pair := issueTokens(t, userID)

	// A second logout, or one for a token that was never stored, matches no
	// live row. The client has nothing to do with a failure here, and a
	// distinguishable answer would leak which token values exist.
	tests := []struct {
		name         string
		rowsAffected int64
	}{
		{name: "Token already revoked", rowsAffected: 0},
		{name: "Token not on record", rowsAffected: 0},
		{name: "Live token revoked", rowsAffected: 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler, mock := newLoginTest(t)

			mock.ExpectExec(revokeByHashQuery).
				WithArgs(utils.HashToken(pair.RefreshToken)).
				WillReturnResult(sqlmock.NewResult(0, tt.rowsAffected))

			w := doLogout(t, handler, `{"refreshToken": "`+pair.RefreshToken+`"}`)

			if w.Code != http.StatusOK {
				t.Fatalf("expected status %d, got %d", http.StatusOK, w.Code)
			}

			if msg := decodeMessage(t, w); msg != "Logged out successfully" {
				t.Errorf("expected message %q, got %q", "Logged out successfully", msg)
			}
		})
	}
}

// expiredRefreshToken signs a refresh token that lapsed an hour ago, the way
// a client that sat idle past the refresh window would still be holding one.
func expiredRefreshToken(t *testing.T, userID uuid.UUID) string {
	t.Helper()

	now := time.Now().Add(-2 * time.Hour)

	claims := utils.Claims{
		Email:     testEmail,
		Phone:     testPhone,
		TokenType: utils.RefreshTokenType,
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        uuid.NewString(),
			Subject:   userID.String(),
			Issuer:    "user-service",
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
		},
	}

	signed, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).
		SignedString([]byte("insecure-development-secret-do-not-use-in-production"))

	if err != nil {
		t.Fatalf("failed to sign an expired token: %v", err)
	}

	return signed
}

func Test_LogoutHandler_Rejects_An_Expired_Refresh_Token(t *testing.T) {
	// ParseToken enforces the expiry, so the request never reaches the
	// database: the token is already unusable and there is nothing to revoke
	// that a sweep of lapsed rows would not clean up anyway.
	handler, _ := newLoginTest(t)

	w := doLogout(t, handler, `{"refreshToken": "`+expiredRefreshToken(t, uuid.New())+`"}`)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected status %d, got %d", http.StatusUnauthorized, w.Code)
	}

	if msg := decodeMessage(t, w); msg != "Invalid refresh token" {
		t.Errorf("expected message %q, got %q", "Invalid refresh token", msg)
	}
}

func Test_LogoutHandler_Database_Error_Returns_500(t *testing.T) {
	handler, mock := newLoginTest(t)

	userID := uuid.New()
	pair := issueTokens(t, userID)

	mock.ExpectExec(revokeByHashQuery).
		WithArgs(utils.HashToken(pair.RefreshToken)).
		WillReturnError(errors.New("connection reset"))

	w := doLogout(t, handler, `{"refreshToken": "`+pair.RefreshToken+`"}`)

	// A revocation that did not land must not be reported as a logout, or the
	// client discards a token that is still redeemable.
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected status %d, got %d", http.StatusInternalServerError, w.Code)
	}

	if msg := decodeMessage(t, w); msg != "Internal server error" {
		t.Errorf("expected message %q, got %q", "Internal server error", msg)
	}
}

func Test_LogoutHandler_Revoked_Token_Cannot_Be_Refreshed(t *testing.T) {
	handler, mock := newLoginTest(t)

	userID := uuid.New()
	pair := issueTokens(t, userID)
	tokenHash := utils.HashToken(pair.RefreshToken)

	mock.ExpectExec(revokeByHashQuery).
		WithArgs(tokenHash).
		WillReturnResult(sqlmock.NewResult(0, 1))

	if w := doLogout(t, handler, `{"refreshToken": "`+pair.RefreshToken+`"}`); w.Code != http.StatusOK {
		t.Fatalf("expected logout to succeed, got status %d", w.Code)
	}

	// The row logout wrote is what the refresh path now reads back: a revoked
	// token, which it treats as a replay and answers with 401.
	mock.ExpectQuery(`SELECT id, user_id, expires_at, revoked_at\s+FROM refresh_tokens`).
		WithArgs(tokenHash).
		WillReturnRows(sqlmock.NewRows(refreshTokenColumns).AddRow(
			uuid.New(), userID, time.Now().Add(utils.RefreshTokenTTL), time.Now(),
		))

	mock.ExpectExec(`UPDATE refresh_tokens\s+SET revoked_at = NOW\(\)\s+WHERE user_id = \$1 AND revoked_at IS NULL`).
		WithArgs(userID).
		WillReturnResult(sqlmock.NewResult(0, 1))

	w := doRefresh(t, handler, `{"refreshToken": "`+pair.RefreshToken+`"}`)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected a logged out token to be unusable, got status %d", w.Code)
	}

	if strings.Contains(w.Body.String(), "accessToken") {
		t.Errorf("refresh minted tokens for a logged out session: %s", w.Body.String())
	}
}

func Test_RefreshTokenHandler_Transaction_Failures(t *testing.T) {
	userID := uuid.New()
	pair := issueTokens(t, userID)
	tokenHash := utils.HashToken(pair.RefreshToken)

	// expectRotationPreamble sets up the two reads every rotation performs
	// before it opens its transaction.
	expectRotationPreamble := func(mock sqlmock.Sqlmock) {
		mock.ExpectQuery(`SELECT id, user_id, expires_at, revoked_at\s+FROM refresh_tokens`).
			WithArgs(tokenHash).
			WillReturnRows(sqlmock.NewRows(refreshTokenColumns).AddRow(
				uuid.New(), userID, time.Now().Add(utils.RefreshTokenTTL), nil,
			))

		mock.ExpectQuery(`SELECT email, phone, status\s+FROM users`).
			WithArgs(userID).
			WillReturnRows(sqlmock.NewRows([]string{"email", "phone", "status"}).
				AddRow(testEmail, testPhone, "active"))
	}

	tests := []struct {
		name  string
		setup func(mock sqlmock.Sqlmock)
	}{
		{
			name: "Transaction cannot be opened",
			setup: func(mock sqlmock.Sqlmock) {
				mock.ExpectBegin().WillReturnError(errors.New("connection reset"))
			},
		},
		{
			name: "Revocation fails",
			setup: func(mock sqlmock.Sqlmock) {
				mock.ExpectBegin()
				mock.ExpectExec(`UPDATE refresh_tokens`).WillReturnError(errors.New("deadlock detected"))
				mock.ExpectRollback()
			},
		},
		{
			name: "Driver cannot report rows affected",
			setup: func(mock sqlmock.Sqlmock) {
				mock.ExpectBegin()
				mock.ExpectExec(`UPDATE refresh_tokens`).
					WillReturnResult(sqlmock.NewErrorResult(errors.New("no RowsAffected available")))
				mock.ExpectRollback()
			},
		},
		{
			name: "Replacement token cannot be stored",
			setup: func(mock sqlmock.Sqlmock) {
				mock.ExpectBegin()
				mock.ExpectExec(`UPDATE refresh_tokens`).WillReturnResult(sqlmock.NewResult(0, 1))
				mock.ExpectExec(`INSERT INTO refresh_tokens`).WillReturnError(errors.New("disk full"))
				mock.ExpectRollback()
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler, mock := newLoginTest(t)

			expectRotationPreamble(mock)
			tt.setup(mock)

			w := doRefresh(t, handler, `{"refreshToken": "`+pair.RefreshToken+`"}`)

			if w.Code != http.StatusInternalServerError {
				t.Fatalf("expected status %d, got %d", http.StatusInternalServerError, w.Code)
			}

			if msg := decodeMessage(t, w); msg != "Internal server error" {
				t.Errorf("expected message %q, got %q", "Internal server error", msg)
			}

			// The old token was not rotated away, so it must stay usable.
			if strings.Contains(w.Body.String(), "refreshToken") {
				t.Errorf("handler returned tokens from a failed rotation: %s", w.Body.String())
			}
		})
	}
}
