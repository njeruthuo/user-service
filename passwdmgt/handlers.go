// github.com/njeruthuo/user-service/passwdmgt

package passwdmgt

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	_ "github.com/lib/pq"
	"github.com/njeruthuo/user-service/utils"
)

const (
	// A reset link is emailed or texted, so it lives long enough for the
	// message to arrive and be acted on, and no longer.
	ResetTokenTTL = time.Hour

	// The row type this package writes to verification_tokens.
	passwordResetType = "password_reset"

	// bcrypt silently ignores everything past its 72 byte input limit, so a
	// longer password would only be as strong as its first 72 bytes.
	minPasswordLength = 8
	maxPasswordLength = 72

	// Answered for every forgot-password request, whether or not the address
	// belongs to an account, so the endpoint cannot be used to discover who
	// has registered.
	resetRequestedMessage = "If the account exists, password reset instructions have been sent"
)

// ResetTokenDeliverer hands a freshly minted reset token to whatever channel
// the account is reachable on. The token is delivered, never stored in the
// clear and never returned to the caller.
type ResetTokenDeliverer interface {
	DeliverPasswordReset(email, phone, token string) error
}

type DBHandler struct {
	DB *sql.DB

	// Optional. With no deliverer configured the token is still minted and
	// stored, and the attempt is logged without the token itself.
	Deliverer ResetTokenDeliverer
}

type JsonResponse struct {
	Message string
}

type ForgotPasswordRequest struct {
	Email string `json:"email"`
	Phone string `json:"phone"`
}

type ResetPasswordRequest struct {
	Token       string `json:"token"`
	NewPassword string `json:"newPassword"`
}

type ChangePasswordRequest struct {
	CurrentPassword string `json:"currentPassword"`
	NewPassword     string `json:"newPassword"`
}

// newResetToken is a variable so tests can drive both the value it returns and
// its failure path. It yields 256 bits of entropy in a URL safe form, which is
// what makes storing only a fast digest of it safe.
var newResetToken = func() (string, error) {
	raw := make([]byte, 32)

	if _, err := rand.Read(raw); err != nil {
		return "", err
	}

	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func writeJSONMessage(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	json.NewEncoder(w).Encode(JsonResponse{
		Message: message,
	})
}

// validatePassword reports why a password is unusable, or an empty string when
// it is fine.
func validatePassword(password string) string {
	if len(password) < minPasswordLength {
		return "Password must be at least 8 characters"
	}

	// Measured in bytes, because that is the limit bcrypt actually imposes.
	if len(password) > maxPasswordLength {
		return "Password must be at most 72 bytes"
	}

	return ""
}

// bearerToken pulls the credential out of an Authorization header, returning
// an empty string when the header is missing or not a bearer scheme.
func bearerToken(r *http.Request) string {
	header := r.Header.Get("Authorization")

	scheme, token, found := strings.Cut(header, " ")
	if !found || !strings.EqualFold(scheme, "Bearer") {
		return ""
	}

	return strings.TrimSpace(token)
}

// revokeUserSessions ends every outstanding session for a user. A password
// change has to invalidate sessions established with the old one, including
// any an attacker opened.
func revokeUserSessions(tx *sql.Tx, userID uuid.UUID) error {
	_, err := tx.Exec(
		`
		UPDATE refresh_tokens
		SET revoked_at = NOW()
		WHERE user_id = $1 AND revoked_at IS NULL`,
		userID,
	)

	return err
}

// setPassword writes a new password hash and drops every session belonging to
// the user, as one unit: a password that changed without the old sessions
// dying would leave the account reachable with the credential being replaced.
func setPassword(tx *sql.Tx, userID uuid.UUID, passwordHash string) error {
	if _, err := tx.Exec(
		`
		UPDATE users
		SET password_hash = $1, updated_at = NOW()
		WHERE id = $2`,
		passwordHash,
		userID,
	); err != nil {
		return err
	}

	return revokeUserSessions(tx, userID)
}

// ForgotPasswordHandler starts a password reset. It answers identically for
// known and unknown accounts, so a caller cannot use it to learn which email
// addresses or phone numbers are registered; only the account owner, who
// receives the delivered token, learns anything.
func (h *DBHandler) ForgotPasswordHandler(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()

	var req ForgotPasswordRequest

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONMessage(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	var query, arg string

	switch {
	case req.Email != "":
		if !utils.IsValidEmail(req.Email) {
			writeJSONMessage(w, http.StatusBadRequest, "Invalid email")
			return
		}

		query = `SELECT id, email, phone FROM users WHERE email = $1`
		arg = req.Email

	case req.Phone != "":
		if !utils.IsValidPhone(req.Phone) {
			writeJSONMessage(w, http.StatusBadRequest, "Invalid phone")
			return
		}

		query = `SELECT id, email, phone FROM users WHERE phone = $1`
		arg = req.Phone

	default:
		writeJSONMessage(w, http.StatusBadRequest, "Email or phone is required")
		return
	}

	var (
		userID uuid.UUID
		email  string
		phone  string
	)

	err := h.DB.QueryRow(query, arg).Scan(&userID, &email, &phone)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeJSONMessage(w, http.StatusOK, resetRequestedMessage)
			return
		}

		writeJSONMessage(w, http.StatusInternalServerError, "Internal server error")
		return
	}

	token, err := newResetToken()
	if err != nil {
		writeJSONMessage(w, http.StatusInternalServerError, "Internal server error")
		return
	}

	// Outstanding resets are retired first, so requesting a new link cannot
	// leave several usable ones in flight.
	if _, err := h.DB.Exec(
		`
		UPDATE verification_tokens
		SET used_at = NOW()
		WHERE user_id = $1 AND type = $2 AND used_at IS NULL`,
		userID,
		passwordResetType,
	); err != nil {
		writeJSONMessage(w, http.StatusInternalServerError, "Internal server error")
		return
	}

	if _, err := h.DB.Exec(
		`
		INSERT INTO verification_tokens (
			user_id,
			type,
			token_hash,
			expires_at
		)
		VALUES ($1, $2, $3, $4)`,
		userID,
		passwordResetType,
		utils.HashToken(token),
		time.Now().Add(ResetTokenTTL),
	); err != nil {
		writeJSONMessage(w, http.StatusInternalServerError, "Internal server error")
		return
	}

	if h.Deliverer == nil {
		// Never log the token: the log would then be as good as the reset link.
		log.Printf("password reset requested for user %s, no deliverer configured", userID)
		writeJSONMessage(w, http.StatusOK, resetRequestedMessage)
		return
	}

	if err := h.Deliverer.DeliverPasswordReset(email, phone, token); err != nil {
		// The token is already stored, so a delivery failure is ours to see
		// and not something to report back differently.
		log.Printf("failed to deliver password reset for user %s: %v", userID, err)
	}

	writeJSONMessage(w, http.StatusOK, resetRequestedMessage)
}

// ResetPasswordHandler completes a reset for a caller holding a token from
// ForgotPasswordHandler. The token is single use, and consuming it also ends
// every session opened with the old password.
func (h *DBHandler) ResetPasswordHandler(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()

	var req ResetPasswordRequest

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONMessage(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if req.Token == "" {
		writeJSONMessage(w, http.StatusBadRequest, "Reset token is required")
		return
	}

	if message := validatePassword(req.NewPassword); message != "" {
		writeJSONMessage(w, http.StatusBadRequest, message)
		return
	}

	var (
		tokenID   uuid.UUID
		userID    uuid.UUID
		expiresAt time.Time
		usedAt    sql.NullTime
	)

	err := h.DB.QueryRow(
		`
		SELECT id, user_id, expires_at, used_at
		FROM verification_tokens
		WHERE token_hash = $1 AND type = $2`,
		utils.HashToken(req.Token),
		passwordResetType,
	).Scan(&tokenID, &userID, &expiresAt, &usedAt)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeJSONMessage(w, http.StatusUnauthorized, "Invalid or expired reset token")
			return
		}

		writeJSONMessage(w, http.StatusInternalServerError, "Internal server error")
		return
	}

	// A spent or lapsed token is answered the same way as an unknown one, so
	// the response says nothing about which tokens have ever existed.
	if usedAt.Valid || time.Now().After(expiresAt) {
		writeJSONMessage(w, http.StatusUnauthorized, "Invalid or expired reset token")
		return
	}

	passwordHash, err := utils.PasswordDigest(req.NewPassword)
	if err != nil {
		writeJSONMessage(w, http.StatusInternalServerError, "Internal server error")
		return
	}

	tx, err := h.DB.Begin()
	if err != nil {
		writeJSONMessage(w, http.StatusInternalServerError, "Internal server error")
		return
	}

	defer tx.Rollback()

	// Spend the token only if it is still unspent, so two requests racing with
	// the same token cannot both reset the password.
	result, err := tx.Exec(
		`
		UPDATE verification_tokens
		SET used_at = NOW()
		WHERE id = $1 AND used_at IS NULL`,
		tokenID,
	)

	if err != nil {
		writeJSONMessage(w, http.StatusInternalServerError, "Internal server error")
		return
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		writeJSONMessage(w, http.StatusInternalServerError, "Internal server error")
		return
	}

	if rowsAffected == 0 {
		writeJSONMessage(w, http.StatusUnauthorized, "Invalid or expired reset token")
		return
	}

	if err := setPassword(tx, userID, passwordHash); err != nil {
		writeJSONMessage(w, http.StatusInternalServerError, "Internal server error")
		return
	}

	if err := tx.Commit(); err != nil {
		writeJSONMessage(w, http.StatusInternalServerError, "Internal server error")
		return
	}

	writeJSONMessage(w, http.StatusOK, "Password has been reset")
}

// ChangePasswordHandler changes the password of the caller identified by the
// access token in the Authorization header, after they prove they know the
// current one.
func (h *DBHandler) ChangePasswordHandler(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()

	token := bearerToken(r)
	if token == "" {
		writeJSONMessage(w, http.StatusUnauthorized, "Authorization required")
		return
	}

	claims, err := utils.ParseToken(token)
	if err != nil {
		writeJSONMessage(w, http.StatusUnauthorized, "Invalid access token")
		return
	}

	// A refresh token identifies a session, not a request, and must not stand
	// in for the access token here.
	if claims.TokenType != utils.AccessTokenType {
		writeJSONMessage(w, http.StatusUnauthorized, "Invalid access token")
		return
	}

	userID, err := uuid.Parse(claims.Subject)
	if err != nil {
		writeJSONMessage(w, http.StatusUnauthorized, "Invalid access token")
		return
	}

	var req ChangePasswordRequest

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONMessage(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if req.CurrentPassword == "" {
		writeJSONMessage(w, http.StatusBadRequest, "Current password is required")
		return
	}

	if message := validatePassword(req.NewPassword); message != "" {
		writeJSONMessage(w, http.StatusBadRequest, message)
		return
	}

	if req.NewPassword == req.CurrentPassword {
		writeJSONMessage(w, http.StatusBadRequest, "New password must differ from the current one")
		return
	}

	var (
		currentHash string
		status      string
	)

	err = h.DB.QueryRow(
		`
		SELECT password_hash, status
		FROM users
		WHERE id = $1`,
		userID,
	).Scan(&currentHash, &status)

	if err != nil {
		// The token parsed but names nobody, so treat it as the stale
		// credential it is rather than as a server fault.
		if errors.Is(err, sql.ErrNoRows) {
			writeJSONMessage(w, http.StatusUnauthorized, "Invalid access token")
			return
		}

		writeJSONMessage(w, http.StatusInternalServerError, "Internal server error")
		return
	}

	if status != "active" {
		writeJSONMessage(w, http.StatusForbidden, "Account is not active")
		return
	}

	if !utils.CheckPasswordHash(req.CurrentPassword, currentHash) {
		writeJSONMessage(w, http.StatusUnauthorized, "Current password is incorrect")
		return
	}

	passwordHash, err := utils.PasswordDigest(req.NewPassword)
	if err != nil {
		writeJSONMessage(w, http.StatusInternalServerError, "Internal server error")
		return
	}

	tx, err := h.DB.Begin()
	if err != nil {
		writeJSONMessage(w, http.StatusInternalServerError, "Internal server error")
		return
	}

	defer tx.Rollback()

	if err := setPassword(tx, userID, passwordHash); err != nil {
		writeJSONMessage(w, http.StatusInternalServerError, "Internal server error")
		return
	}

	if err := tx.Commit(); err != nil {
		writeJSONMessage(w, http.StatusInternalServerError, "Internal server error")
		return
	}

	writeJSONMessage(w, http.StatusOK, "Password has been changed")
}
