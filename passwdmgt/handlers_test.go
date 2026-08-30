package passwdmgt

import (
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/njeruthuo/user-service/messaging"
	"github.com/njeruthuo/user-service/utils"
)

const (
	testEmail       = "julius@domain.com"
	testPhone       = "0768585724"
	testPassword    = "mygoodpassword"
	testNewPassword = "mybrandnewpassword"

	// Mirrors utils.developmentSecret, which tests cannot reach directly.
	testSigningSecret = "insecure-development-secret-do-not-use-in-production"
)

// TestMain keeps the handlers' operational logging out of the test output; the
// tests assert on responses and sql traffic, not on log lines.
func TestMain(m *testing.M) {
	log.SetOutput(io.Discard)
	code := m.Run()
	log.SetOutput(os.Stderr)
	os.Exit(code)
}

// newTest wires a handler to a fresh sqlmock so each subtest owns its own set
// of expectations, and fails the subtest if any goes unmet.
func newTest(t *testing.T) (*DBHandler, sqlmock.Sqlmock) {
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

// capturedArg matches any value while recording it, so a test can assert on
// the exact argument the handler passed to the driver.
type capturedArg struct {
	value driver.Value
}

func (c *capturedArg) Match(v driver.Value) bool {
	c.value = v
	return true
}

func (c *capturedArg) String(t *testing.T) string {
	t.Helper()

	s, ok := c.value.(string)
	if !ok {
		t.Fatalf("expected a string argument, got %T", c.value)
	}

	return s
}

// recordingDeliverer stands in for the channel a reset token is sent over.
type recordingDeliverer struct {
	calls int
	email string
	phone string
	token string
	err   error
}

func (d *recordingDeliverer) DeliverPasswordReset(email, phone, token string) error {
	d.calls++
	d.email = email
	d.phone = phone
	d.token = token

	return d.err
}

func post(t *testing.T, path, payload string) *http.Request {
	t.Helper()

	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")

	return req
}

func doForgot(t *testing.T, handler *DBHandler, payload string) *httptest.ResponseRecorder {
	t.Helper()

	w := httptest.NewRecorder()
	handler.ForgotPasswordHandler(w, post(t, "/auth/forgot-password", payload))

	return w
}

func doReset(t *testing.T, handler *DBHandler, payload string) *httptest.ResponseRecorder {
	t.Helper()

	w := httptest.NewRecorder()
	handler.ResetPasswordHandler(w, post(t, "/auth/reset-password", payload))

	return w
}

func doChange(t *testing.T, handler *DBHandler, authorization, payload string) *httptest.ResponseRecorder {
	t.Helper()

	req := post(t, "/auth/change-password", payload)
	if authorization != "" {
		req.Header.Set("Authorization", authorization)
	}

	w := httptest.NewRecorder()
	handler.ChangePasswordHandler(w, req)

	return w
}

func decodeMessage(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()

	var res utils.ResponseType
	if err := json.NewDecoder(w.Body).Decode(&res); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	return res.Message
}

// assertJSON checks the status line and the content type every response in
// this package is expected to carry.
func assertJSON(t *testing.T, w *httptest.ResponseRecorder, status int, message string) {
	t.Helper()

	if w.Code != status {
		t.Fatalf("expected status %d, got %d (body: %s)", status, w.Code, w.Body.String())
	}

	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("expected Content-Type application/json, got %q", ct)
	}

	if msg := decodeMessage(t, w); msg != message {
		t.Errorf("expected message %q, got %q", message, msg)
	}
}

// stubResetToken pins the value ForgotPasswordHandler will mint, and restores
// the real generator afterwards.
func stubResetToken(t *testing.T, token string, err error) {
	t.Helper()

	original := newResetToken
	newResetToken = func() (string, error) { return token, err }

	t.Cleanup(func() { newResetToken = original })
}

func issueTokens(t *testing.T, userID uuid.UUID) utils.TokenPair {
	t.Helper()

	pair, err := utils.GenerateTokenPair(userID.String(), testEmail, testPhone)
	if err != nil {
		t.Fatalf("failed to issue tokens: %v", err)
	}

	return pair
}

func bearer(pair utils.TokenPair) string {
	return "Bearer " + pair.AccessToken
}

// signAccessToken mints an access token with claims the normal generator would
// never produce, for the cases where those claims are the thing under test.
func signAccessToken(t *testing.T, subject string, ttl time.Duration) string {
	t.Helper()

	now := time.Now()

	claims := utils.Claims{
		Email:     testEmail,
		Phone:     testPhone,
		TokenType: utils.AccessTokenType,
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        uuid.NewString(),
			Subject:   subject,
			Issuer:    "user-service",
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
		},
	}

	signed, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(testSigningSecret))
	if err != nil {
		t.Fatalf("failed to sign a token: %v", err)
	}

	return signed
}

// -----------------------------------------------------------------------------
// validatePassword
// -----------------------------------------------------------------------------

func Test_ValidatePassword(t *testing.T) {
	tests := []struct {
		name     string
		password string
		expected string
	}{
		{"Empty", "", "Password must be at least 8 characters"},
		{"One short", strings.Repeat("a", 7), "Password must be at least 8 characters"},
		{"Exactly the minimum", strings.Repeat("a", 8), ""},
		{"Exactly the bcrypt limit", strings.Repeat("a", 72), ""},
		{"One past the bcrypt limit", strings.Repeat("a", 73), "Password must be at most 72 bytes"},
		// Byte length is what bcrypt counts, so a short multi byte password
		// can still be over the limit.
		{"Multi byte over the limit", strings.Repeat("é", 37), "Password must be at most 72 bytes"},
		{"Multi byte under the limit", strings.Repeat("é", 8), ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := utils.ValidatePassword(tt.password); got != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, got)
			}
		})
	}
}

// -----------------------------------------------------------------------------
// bearerToken
// -----------------------------------------------------------------------------

func Test_BearerToken(t *testing.T) {
	tests := []struct {
		name     string
		header   string
		expected string
	}{
		{"Missing header", "", ""},
		{"No scheme", "abc.def.ghi", ""},
		{"Wrong scheme", "Basic abc.def.ghi", ""},
		{"Bearer with no credential", "Bearer ", ""},
		{"Well formed", "Bearer abc.def.ghi", "abc.def.ghi"},
		// Schemes are case insensitive per RFC 7235.
		{"Lowercase scheme", "bearer abc.def.ghi", "abc.def.ghi"},
		{"Padded credential", "Bearer   abc.def.ghi  ", "abc.def.ghi"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/auth/change-password", nil)
			if tt.header != "" {
				req.Header.Set("Authorization", tt.header)
			}

			if got := bearerToken(req); got != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, got)
			}
		})
	}
}

// -----------------------------------------------------------------------------
// newResetToken
// -----------------------------------------------------------------------------

func Test_NewResetToken_Is_Long_And_Unique(t *testing.T) {
	seen := make(map[string]bool, 100)

	for range 100 {
		token, err := newResetToken()
		if err != nil {
			t.Fatalf("failed to mint a reset token: %v", err)
		}

		// 32 random bytes in unpadded base64url.
		if len(token) != 43 {
			t.Fatalf("expected a 43 character token, got %d characters", len(token))
		}

		if strings.ContainsAny(token, "+/=") {
			t.Errorf("token %q is not URL safe", token)
		}

		if seen[token] {
			t.Fatalf("reset token %q was minted twice", token)
		}

		seen[token] = true
	}
}

// -----------------------------------------------------------------------------
// ForgotPasswordHandler
// -----------------------------------------------------------------------------

const (
	forgotLookupByEmail = `SELECT id, email, phone FROM users WHERE email = \$1`
	forgotLookupByPhone = `SELECT id, email, phone FROM users WHERE phone = \$1`
	retireResetTokens   = `UPDATE verification_tokens\s+SET used_at = NOW\(\)\s+WHERE user_id = \$1 AND type = \$2 AND used_at IS NULL`
	insertResetToken    = `INSERT INTO verification_tokens`
)

func Test_ForgotPasswordHandler_Rejects_Bad_Requests(t *testing.T) {
	tests := []struct {
		name     string
		payload  string
		expected string
	}{
		{"Invalid JSON", `{"email": `, "Invalid request body"},
		{"Empty body", ``, "Invalid request body"},
		{"Neither email nor phone", `{}`, "Email or phone is required"},
		{"Both fields blank", `{"email": "", "phone": ""}`, "Email or phone is required"},
		{"Malformed email", `{"email": "not-an-email"}`, "Invalid email"},
		{"Email with a display name", `{"email": "Julius <julius@domain.com>"}`, "Invalid email"},
		{"Malformed phone", `{"phone": "12345"}`, "Invalid phone"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// No expectations: a rejected request must never touch the database.
			handler, _ := newTest(t)

			assertJSON(t, doForgot(t, handler, tt.payload), http.StatusBadRequest, tt.expected)
		})
	}
}

func Test_ForgotPasswordHandler_Issues_A_Token(t *testing.T) {
	handler, mock := newTest(t)

	userID := uuid.New()
	deliverer := &recordingDeliverer{}
	handler.Deliverer = deliverer

	const token = "a-known-reset-token"
	stubResetToken(t, token, nil)

	mock.ExpectQuery(forgotLookupByEmail).
		WithArgs(testEmail).
		WillReturnRows(sqlmock.NewRows([]string{"id", "email", "phone"}).
			AddRow(userID, testEmail, testPhone))

	mock.ExpectExec(retireResetTokens).
		WithArgs(userID, passwordResetType).
		WillReturnResult(sqlmock.NewResult(0, 1))

	storedHash := &capturedArg{}
	expiresAt := &capturedArg{}

	mock.ExpectExec(insertResetToken).
		WithArgs(userID, passwordResetType, storedHash, expiresAt).
		WillReturnResult(sqlmock.NewResult(1, 1))

	w := doForgot(t, handler, `{"email": "`+testEmail+`"}`)

	assertJSON(t, w, http.StatusOK, resetRequestedMessage)

	stored := storedHash.String(t)

	if stored == token {
		t.Fatal("the raw reset token was stored instead of its hash")
	}

	if stored != utils.HashToken(token) {
		t.Errorf("stored hash %q does not match the minted token", stored)
	}

	expiry, ok := expiresAt.value.(time.Time)
	if !ok {
		t.Fatalf("expected a time for expires_at, got %T", expiresAt.value)
	}

	if delta := time.Until(expiry) - ResetTokenTTL; delta > time.Minute || delta < -time.Minute {
		t.Errorf("expected an expiry about %v out, got %v", ResetTokenTTL, time.Until(expiry))
	}

	// The token reaches the account owner and nobody else.
	if deliverer.calls != 1 {
		t.Fatalf("expected one delivery, got %d", deliverer.calls)
	}

	if deliverer.token != token {
		t.Errorf("expected the minted token to be delivered, got %q", deliverer.token)
	}

	if deliverer.email != testEmail || deliverer.phone != testPhone {
		t.Errorf("expected delivery to the account contacts, got %q / %q", deliverer.email, deliverer.phone)
	}

	if strings.Contains(w.Body.String(), token) {
		t.Errorf("the response leaked the reset token: %s", w.Body.String())
	}
}

func Test_ForgotPasswordHandler_Accepts_A_Phone(t *testing.T) {
	handler, mock := newTest(t)

	userID := uuid.New()
	stubResetToken(t, "a-known-reset-token", nil)

	mock.ExpectQuery(forgotLookupByPhone).
		WithArgs(testPhone).
		WillReturnRows(sqlmock.NewRows([]string{"id", "email", "phone"}).
			AddRow(userID, testEmail, testPhone))

	mock.ExpectExec(retireResetTokens).WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(insertResetToken).WillReturnResult(sqlmock.NewResult(1, 1))

	assertJSON(t, doForgot(t, handler, `{"phone": "`+testPhone+`"}`), http.StatusOK, resetRequestedMessage)
}

func Test_ForgotPasswordHandler_Prefers_Email_When_Both_Are_Given(t *testing.T) {
	handler, mock := newTest(t)

	stubResetToken(t, "a-known-reset-token", nil)

	// Only the email lookup is expected, so a phone lookup would fail the test.
	mock.ExpectQuery(forgotLookupByEmail).
		WithArgs(testEmail).
		WillReturnError(sql.ErrNoRows)

	assertJSON(
		t,
		doForgot(t, handler, `{"email": "`+testEmail+`", "phone": "`+testPhone+`"}`),
		http.StatusOK,
		resetRequestedMessage,
	)
}

// An unknown account must be indistinguishable from a known one, or the
// endpoint becomes a way to enumerate who has registered.
func Test_ForgotPasswordHandler_Does_Not_Disclose_Whether_An_Account_Exists(t *testing.T) {
	stubResetToken(t, "a-known-reset-token", nil)

	knownHandler, knownMock := newTest(t)
	knownMock.ExpectQuery(forgotLookupByEmail).
		WillReturnRows(sqlmock.NewRows([]string{"id", "email", "phone"}).
			AddRow(uuid.New(), testEmail, testPhone))
	knownMock.ExpectExec(retireResetTokens).WillReturnResult(sqlmock.NewResult(0, 0))
	knownMock.ExpectExec(insertResetToken).WillReturnResult(sqlmock.NewResult(1, 1))

	known := doForgot(t, knownHandler, `{"email": "`+testEmail+`"}`)

	unknownHandler, unknownMock := newTest(t)
	unknownMock.ExpectQuery(forgotLookupByEmail).WillReturnError(sql.ErrNoRows)

	unknown := doForgot(t, unknownHandler, `{"email": "nobody@domain.com"}`)

	if known.Code != unknown.Code {
		t.Errorf("status differs between a known (%d) and unknown (%d) account", known.Code, unknown.Code)
	}

	if known.Body.String() != unknown.Body.String() {
		t.Errorf("body differs: known %q, unknown %q", known.Body.String(), unknown.Body.String())
	}
}

func Test_ForgotPasswordHandler_Succeeds_Without_A_Deliverer(t *testing.T) {
	handler, mock := newTest(t)

	stubResetToken(t, "a-known-reset-token", nil)

	mock.ExpectQuery(forgotLookupByEmail).
		WillReturnRows(sqlmock.NewRows([]string{"id", "email", "phone"}).
			AddRow(uuid.New(), testEmail, testPhone))
	mock.ExpectExec(retireResetTokens).WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(insertResetToken).WillReturnResult(sqlmock.NewResult(1, 1))

	assertJSON(t, doForgot(t, handler, `{"email": "`+testEmail+`"}`), http.StatusOK, resetRequestedMessage)
}

// A channel that is down is our problem, not something the caller can act on,
// and must not change the answer they get.
func Test_ForgotPasswordHandler_Survives_A_Delivery_Failure(t *testing.T) {
	handler, mock := newTest(t)

	deliverer := &recordingDeliverer{err: errors.New("smtp unavailable")}
	handler.Deliverer = deliverer

	stubResetToken(t, "a-known-reset-token", nil)

	mock.ExpectQuery(forgotLookupByEmail).
		WillReturnRows(sqlmock.NewRows([]string{"id", "email", "phone"}).
			AddRow(uuid.New(), testEmail, testPhone))
	mock.ExpectExec(retireResetTokens).WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(insertResetToken).WillReturnResult(sqlmock.NewResult(1, 1))

	assertJSON(t, doForgot(t, handler, `{"email": "`+testEmail+`"}`), http.StatusOK, resetRequestedMessage)

	if deliverer.calls != 1 {
		t.Errorf("expected delivery to have been attempted once, got %d", deliverer.calls)
	}
}

func Test_ForgotPasswordHandler_Failures(t *testing.T) {
	tests := []struct {
		name  string
		setup func(t *testing.T, mock sqlmock.Sqlmock)
	}{
		{
			name: "Lookup fails",
			setup: func(t *testing.T, mock sqlmock.Sqlmock) {
				stubResetToken(t, "a-known-reset-token", nil)
				mock.ExpectQuery(forgotLookupByEmail).WillReturnError(errors.New("connection reset"))
			},
		},
		{
			name: "Token cannot be generated",
			setup: func(t *testing.T, mock sqlmock.Sqlmock) {
				stubResetToken(t, "", errors.New("entropy source unavailable"))
				mock.ExpectQuery(forgotLookupByEmail).
					WillReturnRows(sqlmock.NewRows([]string{"id", "email", "phone"}).
						AddRow(uuid.New(), testEmail, testPhone))
			},
		},
		{
			name: "Outstanding tokens cannot be retired",
			setup: func(t *testing.T, mock sqlmock.Sqlmock) {
				stubResetToken(t, "a-known-reset-token", nil)
				mock.ExpectQuery(forgotLookupByEmail).
					WillReturnRows(sqlmock.NewRows([]string{"id", "email", "phone"}).
						AddRow(uuid.New(), testEmail, testPhone))
				mock.ExpectExec(retireResetTokens).WillReturnError(errors.New("deadlock detected"))
			},
		},
		{
			name: "Token cannot be stored",
			setup: func(t *testing.T, mock sqlmock.Sqlmock) {
				stubResetToken(t, "a-known-reset-token", nil)
				mock.ExpectQuery(forgotLookupByEmail).
					WillReturnRows(sqlmock.NewRows([]string{"id", "email", "phone"}).
						AddRow(uuid.New(), testEmail, testPhone))
				mock.ExpectExec(retireResetTokens).WillReturnResult(sqlmock.NewResult(0, 0))
				mock.ExpectExec(insertResetToken).WillReturnError(errors.New("disk full"))
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler, mock := newTest(t)

			deliverer := &recordingDeliverer{}
			handler.Deliverer = deliverer

			tt.setup(t, mock)

			w := doForgot(t, handler, `{"email": "`+testEmail+`"}`)

			assertJSON(t, w, http.StatusInternalServerError, "Internal server error")

			// A reset that failed to record must not send a link the user
			// could not then redeem.
			if deliverer.calls != 0 {
				t.Errorf("expected no delivery after a failure, got %d", deliverer.calls)
			}
		})
	}
}

// -----------------------------------------------------------------------------
// ResetPasswordHandler
// -----------------------------------------------------------------------------

const (
	resetTokenLookup   = `SELECT id, user_id, expires_at, used_at\s+FROM verification_tokens\s+WHERE token_hash = \$1 AND type = \$2`
	spendResetToken    = `UPDATE verification_tokens\s+SET used_at = NOW\(\)\s+WHERE id = \$1 AND used_at IS NULL`
	updatePasswordHash = `UPDATE users\s+SET password_hash = \$1, updated_at = NOW\(\)\s+WHERE id = \$2`
	revokeUserTokens   = `UPDATE refresh_tokens\s+SET revoked_at = NOW\(\)\s+WHERE user_id = \$1 AND revoked_at IS NULL`
)

var resetTokenColumns = []string{"id", "user_id", "expires_at", "used_at"}

func Test_ResetPasswordHandler_Rejects_Bad_Requests(t *testing.T) {
	tests := []struct {
		name     string
		payload  string
		expected string
	}{
		{"Invalid JSON", `{"token": `, "Invalid request body"},
		{"Empty body", ``, "Invalid request body"},
		{"Missing token", `{"newPassword": "` + testNewPassword + `"}`, "Reset token is required"},
		{"Blank token", `{"token": "", "newPassword": "` + testNewPassword + `"}`, "Reset token is required"},
		{"Missing password", `{"token": "a-token"}`, "Password must be at least 8 characters"},
		{"Short password", `{"token": "a-token", "newPassword": "short"}`, "Password must be at least 8 characters"},
		{
			name:     "Password past the bcrypt limit",
			payload:  `{"token": "a-token", "newPassword": "` + strings.Repeat("a", 73) + `"}`,
			expected: "Password must be at most 72 bytes",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// No expectations: a rejected request must never touch the database.
			handler, _ := newTest(t)

			assertJSON(t, doReset(t, handler, tt.payload), http.StatusBadRequest, tt.expected)
		})
	}
}

func Test_ResetPasswordHandler_Resets_The_Password(t *testing.T) {
	handler, mock := newTest(t)

	userID := uuid.New()
	tokenID := uuid.New()

	const token = "a-known-reset-token"

	mock.ExpectQuery(resetTokenLookup).
		WithArgs(utils.HashToken(token), passwordResetType).
		WillReturnRows(sqlmock.NewRows(resetTokenColumns).
			AddRow(tokenID, userID, time.Now().Add(ResetTokenTTL), nil))

	mock.ExpectBegin()

	mock.ExpectExec(spendResetToken).
		WithArgs(tokenID).
		WillReturnResult(sqlmock.NewResult(0, 1))

	storedHash := &capturedArg{}

	mock.ExpectExec(updatePasswordHash).
		WithArgs(storedHash, userID).
		WillReturnResult(sqlmock.NewResult(0, 1))

	// A password change ends every session opened with the old one.
	mock.ExpectExec(revokeUserTokens).
		WithArgs(userID).
		WillReturnResult(sqlmock.NewResult(0, 2))

	mock.ExpectCommit()

	w := doReset(t, handler, `{"token": "`+token+`", "newPassword": "`+testNewPassword+`"}`)

	assertJSON(t, w, http.StatusOK, "Password has been reset")

	stored := storedHash.String(t)

	if stored == testNewPassword {
		t.Fatal("the new password was stored in the clear")
	}

	if !utils.CheckPasswordHash(testNewPassword, stored) {
		t.Error("the stored hash does not verify against the new password")
	}

	if strings.Contains(w.Body.String(), testNewPassword) {
		t.Errorf("the response leaked the new password: %s", w.Body.String())
	}
}

func Test_ResetPasswordHandler_Rejects_Unusable_Tokens(t *testing.T) {
	const token = "a-known-reset-token"

	usedAt := time.Now().Add(-time.Minute)

	tests := []struct {
		name  string
		setup func(mock sqlmock.Sqlmock)
	}{
		{
			name: "Unknown token",
			setup: func(mock sqlmock.Sqlmock) {
				mock.ExpectQuery(resetTokenLookup).WillReturnError(sql.ErrNoRows)
			},
		},
		{
			name: "Already spent token",
			setup: func(mock sqlmock.Sqlmock) {
				mock.ExpectQuery(resetTokenLookup).
					WillReturnRows(sqlmock.NewRows(resetTokenColumns).
						AddRow(uuid.New(), uuid.New(), time.Now().Add(ResetTokenTTL), usedAt))
			},
		},
		{
			name: "Expired token",
			setup: func(mock sqlmock.Sqlmock) {
				mock.ExpectQuery(resetTokenLookup).
					WillReturnRows(sqlmock.NewRows(resetTokenColumns).
						AddRow(uuid.New(), uuid.New(), time.Now().Add(-time.Minute), nil))
			},
		},
		{
			name: "Token spent between the read and the write",
			setup: func(mock sqlmock.Sqlmock) {
				mock.ExpectQuery(resetTokenLookup).
					WillReturnRows(sqlmock.NewRows(resetTokenColumns).
						AddRow(uuid.New(), uuid.New(), time.Now().Add(ResetTokenTTL), nil))
				mock.ExpectBegin()
				mock.ExpectExec(spendResetToken).WillReturnResult(sqlmock.NewResult(0, 0))
				mock.ExpectRollback()
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler, mock := newTest(t)

			tt.setup(mock)

			w := doReset(t, handler, `{"token": "`+token+`", "newPassword": "`+testNewPassword+`"}`)

			// One answer for every unusable token, so the response cannot be
			// used to tell an unknown token from a spent or lapsed one.
			assertJSON(t, w, http.StatusUnauthorized, "Invalid or expired reset token")
		})
	}
}

func Test_ResetPasswordHandler_Failures(t *testing.T) {
	const token = "a-known-reset-token"

	// expectLiveToken sets up the read every reset performs before it opens a
	// transaction.
	expectLiveToken := func(mock sqlmock.Sqlmock) {
		mock.ExpectQuery(resetTokenLookup).
			WillReturnRows(sqlmock.NewRows(resetTokenColumns).
				AddRow(uuid.New(), uuid.New(), time.Now().Add(ResetTokenTTL), nil))
	}

	tests := []struct {
		name  string
		setup func(mock sqlmock.Sqlmock)
	}{
		{
			name: "Token lookup fails",
			setup: func(mock sqlmock.Sqlmock) {
				mock.ExpectQuery(resetTokenLookup).WillReturnError(errors.New("connection reset"))
			},
		},
		{
			name: "Transaction cannot be opened",
			setup: func(mock sqlmock.Sqlmock) {
				expectLiveToken(mock)
				mock.ExpectBegin().WillReturnError(errors.New("connection reset"))
			},
		},
		{
			name: "Spending the token fails",
			setup: func(mock sqlmock.Sqlmock) {
				expectLiveToken(mock)
				mock.ExpectBegin()
				mock.ExpectExec(spendResetToken).WillReturnError(errors.New("deadlock detected"))
				mock.ExpectRollback()
			},
		},
		{
			name: "Driver cannot report rows affected",
			setup: func(mock sqlmock.Sqlmock) {
				expectLiveToken(mock)
				mock.ExpectBegin()
				mock.ExpectExec(spendResetToken).
					WillReturnResult(sqlmock.NewErrorResult(errors.New("no RowsAffected available")))
				mock.ExpectRollback()
			},
		},
		{
			name: "Password cannot be written",
			setup: func(mock sqlmock.Sqlmock) {
				expectLiveToken(mock)
				mock.ExpectBegin()
				mock.ExpectExec(spendResetToken).WillReturnResult(sqlmock.NewResult(0, 1))
				mock.ExpectExec(updatePasswordHash).WillReturnError(errors.New("disk full"))
				mock.ExpectRollback()
			},
		},
		{
			name: "Sessions cannot be revoked",
			setup: func(mock sqlmock.Sqlmock) {
				expectLiveToken(mock)
				mock.ExpectBegin()
				mock.ExpectExec(spendResetToken).WillReturnResult(sqlmock.NewResult(0, 1))
				mock.ExpectExec(updatePasswordHash).WillReturnResult(sqlmock.NewResult(0, 1))
				mock.ExpectExec(revokeUserTokens).WillReturnError(errors.New("deadlock detected"))
				mock.ExpectRollback()
			},
		},
		{
			name: "Commit fails",
			setup: func(mock sqlmock.Sqlmock) {
				expectLiveToken(mock)
				mock.ExpectBegin()
				mock.ExpectExec(spendResetToken).WillReturnResult(sqlmock.NewResult(0, 1))
				mock.ExpectExec(updatePasswordHash).WillReturnResult(sqlmock.NewResult(0, 1))
				mock.ExpectExec(revokeUserTokens).WillReturnResult(sqlmock.NewResult(0, 1))
				mock.ExpectCommit().WillReturnError(errors.New("connection reset"))
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler, mock := newTest(t)

			tt.setup(mock)

			w := doReset(t, handler, `{"token": "`+token+`", "newPassword": "`+testNewPassword+`"}`)

			assertJSON(t, w, http.StatusInternalServerError, "Internal server error")
		})
	}
}

// -----------------------------------------------------------------------------
// ChangePasswordHandler
// -----------------------------------------------------------------------------

const currentPasswordLookup = `SELECT password_hash, status\s+FROM users\s+WHERE id = \$1`

// userRow builds the row the change-password read scans, with a real bcrypt
// hash so the password check behaves exactly as it does in production.
func userRow(t *testing.T, password, status string) *sqlmock.Rows {
	t.Helper()

	hash, err := utils.PasswordDigest(password)
	if err != nil {
		t.Fatalf("failed to hash test password: %v", err)
	}

	return sqlmock.NewRows([]string{"password_hash", "status"}).AddRow(hash, status)
}

func changePayload(current, replacement string) string {
	return `{"currentPassword": "` + current + `", "newPassword": "` + replacement + `"}`
}

func Test_ChangePasswordHandler_Requires_A_Valid_Access_Token(t *testing.T) {
	userID := uuid.New()
	pair := issueTokens(t, userID)

	tests := []struct {
		name          string
		authorization string
		expected      string
	}{
		{"No header", "", "Authorization required"},
		{"Empty bearer", "Bearer ", "Authorization required"},
		{"Wrong scheme", "Basic " + pair.AccessToken, "Authorization required"},
		{"Raw token with no scheme", pair.AccessToken, "Authorization required"},
		{"Unparseable token", "Bearer not-a-token", "Invalid access token"},
		{"Tampered token", "Bearer " + pair.AccessToken + "x", "Invalid access token"},
		// A refresh token identifies a session, not a request.
		{"Refresh token", "Bearer " + pair.RefreshToken, "Invalid access token"},
		{
			name:          "Expired access token",
			authorization: "Bearer " + signAccessToken(t, userID.String(), -time.Minute),
			expected:      "Invalid access token",
		},
		{
			name:          "Subject is not a user id",
			authorization: "Bearer " + signAccessToken(t, "not-a-uuid", time.Hour),
			expected:      "Invalid access token",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// No expectations: an unauthenticated request never reaches the
			// database, and never reads the body it was sent.
			handler, _ := newTest(t)

			w := doChange(t, handler, tt.authorization, changePayload(testPassword, testNewPassword))

			assertJSON(t, w, http.StatusUnauthorized, tt.expected)
		})
	}
}

func Test_ChangePasswordHandler_Rejects_Bad_Requests(t *testing.T) {
	pair := issueTokens(t, uuid.New())

	tests := []struct {
		name     string
		payload  string
		expected string
	}{
		{"Invalid JSON", `{"currentPassword": `, "Invalid request body"},
		{"Empty body", ``, "Invalid request body"},
		{"Missing current password", `{"newPassword": "` + testNewPassword + `"}`, "Current password is required"},
		{"Missing new password", `{"currentPassword": "` + testPassword + `"}`, "Password must be at least 8 characters"},
		{"Short new password", changePayload(testPassword, "short"), "Password must be at least 8 characters"},
		{
			name:     "New password past the bcrypt limit",
			payload:  changePayload(testPassword, strings.Repeat("a", 73)),
			expected: "Password must be at most 72 bytes",
		},
		{
			name:     "New password is the current one",
			payload:  changePayload(testPassword, testPassword),
			expected: "New password must differ from the current one",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// No expectations: a rejected request must never touch the database.
			handler, _ := newTest(t)

			assertJSON(t, doChange(t, handler, bearer(pair), tt.payload), http.StatusBadRequest, tt.expected)
		})
	}
}

func Test_ChangePasswordHandler_Changes_The_Password(t *testing.T) {
	handler, mock := newTest(t)

	userID := uuid.New()
	pair := issueTokens(t, userID)

	mock.ExpectQuery(currentPasswordLookup).
		WithArgs(userID).
		WillReturnRows(userRow(t, testPassword, "active"))

	mock.ExpectBegin()

	storedHash := &capturedArg{}

	mock.ExpectExec(updatePasswordHash).
		WithArgs(storedHash, userID).
		WillReturnResult(sqlmock.NewResult(0, 1))

	// Sessions opened with the old password, including any an attacker holds,
	// end with the change.
	mock.ExpectExec(revokeUserTokens).
		WithArgs(userID).
		WillReturnResult(sqlmock.NewResult(0, 3))

	mock.ExpectCommit()

	w := doChange(t, handler, bearer(pair), changePayload(testPassword, testNewPassword))

	assertJSON(t, w, http.StatusOK, "Password has been changed")

	stored := storedHash.String(t)

	if stored == testNewPassword {
		t.Fatal("the new password was stored in the clear")
	}

	if !utils.CheckPasswordHash(testNewPassword, stored) {
		t.Error("the stored hash does not verify against the new password")
	}

	if utils.CheckPasswordHash(testPassword, stored) {
		t.Error("the stored hash still verifies against the old password")
	}

	body := w.Body.String()
	if strings.Contains(body, testNewPassword) || strings.Contains(body, testPassword) {
		t.Errorf("the response leaked password material: %s", body)
	}
}

func Test_ChangePasswordHandler_Account_Checks(t *testing.T) {
	userID := uuid.New()
	pair := issueTokens(t, userID)

	tests := []struct {
		name           string
		payload        string
		setup          func(t *testing.T, mock sqlmock.Sqlmock)
		expectedStatus int
		expectedMsg    string
	}{
		{
			name:    "Token names a user who no longer exists",
			payload: changePayload(testPassword, testNewPassword),
			setup: func(t *testing.T, mock sqlmock.Sqlmock) {
				mock.ExpectQuery(currentPasswordLookup).WillReturnError(sql.ErrNoRows)
			},
			expectedStatus: http.StatusUnauthorized,
			expectedMsg:    "Invalid access token",
		},
		{
			name:    "Disabled account",
			payload: changePayload(testPassword, testNewPassword),
			setup: func(t *testing.T, mock sqlmock.Sqlmock) {
				mock.ExpectQuery(currentPasswordLookup).WillReturnRows(userRow(t, testPassword, "disabled"))
			},
			expectedStatus: http.StatusForbidden,
			expectedMsg:    "Account is not active",
		},
		{
			name:    "Wrong current password",
			payload: changePayload("not-the-current-password", testNewPassword),
			setup: func(t *testing.T, mock sqlmock.Sqlmock) {
				mock.ExpectQuery(currentPasswordLookup).WillReturnRows(userRow(t, testPassword, "active"))
			},
			expectedStatus: http.StatusUnauthorized,
			expectedMsg:    "Current password is incorrect",
		},
		{
			name:    "Lookup fails",
			payload: changePayload(testPassword, testNewPassword),
			setup: func(t *testing.T, mock sqlmock.Sqlmock) {
				mock.ExpectQuery(currentPasswordLookup).WillReturnError(errors.New("connection reset"))
			},
			expectedStatus: http.StatusInternalServerError,
			expectedMsg:    "Internal server error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler, mock := newTest(t)

			tt.setup(t, mock)

			w := doChange(t, handler, bearer(pair), tt.payload)

			assertJSON(t, w, tt.expectedStatus, tt.expectedMsg)
		})
	}
}

// A disabled account or a bad current password must stop before any write, so
// a caller cannot end a user's sessions without proving who they are.
func Test_ChangePasswordHandler_Writes_Nothing_When_The_Check_Fails(t *testing.T) {
	handler, mock := newTest(t)

	pair := issueTokens(t, uuid.New())

	// The read is the only statement expected, so any write fails the test.
	mock.ExpectQuery(currentPasswordLookup).WillReturnRows(userRow(t, testPassword, "active"))

	w := doChange(t, handler, bearer(pair), changePayload("not-the-current-password", testNewPassword))

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected status %d, got %d", http.StatusUnauthorized, w.Code)
	}
}

func Test_ChangePasswordHandler_Transaction_Failures(t *testing.T) {
	pair := issueTokens(t, uuid.New())

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
			name: "Password cannot be written",
			setup: func(mock sqlmock.Sqlmock) {
				mock.ExpectBegin()
				mock.ExpectExec(updatePasswordHash).WillReturnError(errors.New("disk full"))
				mock.ExpectRollback()
			},
		},
		{
			name: "Sessions cannot be revoked",
			setup: func(mock sqlmock.Sqlmock) {
				mock.ExpectBegin()
				mock.ExpectExec(updatePasswordHash).WillReturnResult(sqlmock.NewResult(0, 1))
				mock.ExpectExec(revokeUserTokens).WillReturnError(errors.New("deadlock detected"))
				mock.ExpectRollback()
			},
		},
		{
			name: "Commit fails",
			setup: func(mock sqlmock.Sqlmock) {
				mock.ExpectBegin()
				mock.ExpectExec(updatePasswordHash).WillReturnResult(sqlmock.NewResult(0, 1))
				mock.ExpectExec(revokeUserTokens).WillReturnResult(sqlmock.NewResult(0, 1))
				mock.ExpectCommit().WillReturnError(errors.New("connection reset"))
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler, mock := newTest(t)

			mock.ExpectQuery(currentPasswordLookup).WillReturnRows(userRow(t, testPassword, "active"))
			tt.setup(mock)

			w := doChange(t, handler, bearer(pair), changePayload(testPassword, testNewPassword))

			assertJSON(t, w, http.StatusInternalServerError, "Internal server error")
		})
	}
}

// publishedMessage records one call made to a recordingPublisher.
type publishedMessage struct {
	queue   string
	payload any
}

// recordingPublisher stands in for the RabbitMQ channel DeliverPasswordReset
// publishes through, so tests never need a live broker.
type recordingPublisher struct {
	calls  []publishedMessage
	errFor map[string]error // queue name -> error to return for that queue
}

func (p *recordingPublisher) PublishJSON(queue string, payload any) error {
	p.calls = append(p.calls, publishedMessage{queue: queue, payload: payload})
	return p.errFor[queue]
}

func Test_DeliverPasswordReset(t *testing.T) {
	tests := []struct {
		name          string
		email         string
		phone         string
		errFor        map[string]error
		expectedCalls []publishedMessage
		expectErr     bool
	}{
		{
			name:  "Both email and phone publish to their own queue",
			email: testEmail,
			phone: testPhone,
			expectedCalls: []publishedMessage{
				{queue: messaging.PasswordResetEmailQueue, payload: passwordResetMessage{Email: testEmail, Token: "the-token"}},
				{queue: messaging.PasswordResetSMSQueue, payload: passwordResetMessage{Phone: testPhone, Token: "the-token"}},
			},
		},
		{
			name:  "No email only publishes the SMS queue",
			phone: testPhone,
			expectedCalls: []publishedMessage{
				{queue: messaging.PasswordResetSMSQueue, payload: passwordResetMessage{Phone: testPhone, Token: "the-token"}},
			},
		},
		{
			name:  "No phone only publishes the email queue",
			email: testEmail,
			expectedCalls: []publishedMessage{
				{queue: messaging.PasswordResetEmailQueue, payload: passwordResetMessage{Email: testEmail, Token: "the-token"}},
			},
		},
		{
			name:  "Email publish fails but the SMS attempt still happens",
			email: testEmail,
			phone: testPhone,
			errFor: map[string]error{
				messaging.PasswordResetEmailQueue: errors.New("broker unavailable"),
			},
			expectedCalls: []publishedMessage{
				{queue: messaging.PasswordResetEmailQueue, payload: passwordResetMessage{Email: testEmail, Token: "the-token"}},
				{queue: messaging.PasswordResetSMSQueue, payload: passwordResetMessage{Phone: testPhone, Token: "the-token"}},
			},
			expectErr: true,
		},
		{
			name:  "Both publishes fail",
			email: testEmail,
			phone: testPhone,
			errFor: map[string]error{
				messaging.PasswordResetEmailQueue: errors.New("broker unavailable"),
				messaging.PasswordResetSMSQueue:   errors.New("broker unavailable"),
			},
			expectedCalls: []publishedMessage{
				{queue: messaging.PasswordResetEmailQueue, payload: passwordResetMessage{Email: testEmail, Token: "the-token"}},
				{queue: messaging.PasswordResetSMSQueue, payload: passwordResetMessage{Phone: testPhone, Token: "the-token"}},
			},
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pub := &recordingPublisher{errFor: tt.errFor}
			handler := &DBHandler{MQ: pub}

			err := handler.DeliverPasswordReset(tt.email, tt.phone, "the-token")

			if tt.expectErr && err == nil {
				t.Fatal("expected an error, got nil")
			}

			if !tt.expectErr && err != nil {
				t.Fatalf("expected no error, got %v", err)
			}

			if len(pub.calls) != len(tt.expectedCalls) {
				t.Fatalf("expected %d publish calls, got %d: %+v", len(tt.expectedCalls), len(pub.calls), pub.calls)
			}

			for i, want := range tt.expectedCalls {
				got := pub.calls[i]

				if got.queue != want.queue {
					t.Errorf("call %d: expected queue %q, got %q", i, want.queue, got.queue)
				}

				if got.payload != want.payload {
					t.Errorf("call %d: expected payload %+v, got %+v", i, want.payload, got.payload)
				}
			}
		})
	}
}
