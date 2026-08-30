package verification

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/njeruthuo/user-service/datatypes"
	"github.com/njeruthuo/user-service/messaging"
	"github.com/njeruthuo/user-service/utils"
)

const (
	VerificationTokenTTL = time.Hour

	emailVerificationType = "email_verification"
	phoneVerificationType = "phone_verification"

	verificationSentMessage = "If the account exists, a verification code has been sent"
)

var errInvalidVerificationToken = errors.New("invalid or expired verification token")

type DBHandler struct {
	DB *sql.DB
	MQ *messaging.RabbitMQ
}

type VerificationPayload struct {
	Phone string `json:"phone"`
	Email string `json:"email"`
	Type  string `json:"type"` // can be phone or email verification
}

type verificationMessage struct {
	Email string `json:"email,omitempty"`
	Phone string `json:"phone,omitempty"`
	Token string `json:"token"`
}

type ConfirmVerificationPayload struct {
	Token string `json:"token"`
}

var newVerificationToken = func() (string, error) {
	raw := make([]byte, 32)

	if _, err := rand.Read(raw); err != nil {
		return "", err
	}

	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func (db *DBHandler) VerificationHandler(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()

	var req VerificationPayload
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		utils.WriteJSON(w, http.StatusBadRequest, err.Error())
		return
	}

	var (
		query            string
		arg              string
		verificationType string
	)

	if req.Type == "email" {
		if !utils.IsValidEmail(req.Email) {
			utils.WriteJSON(w, http.StatusBadRequest, "Invalid email")
			return
		}

		query = `SELECT id, email, phone, status, phone_verified, email_verified, created_at, updated_at
		FROM users
		WHERE email = $1`
		arg = req.Email
		verificationType = emailVerificationType
	} else {
		if !utils.IsValidPhone(req.Phone) {
			utils.WriteJSON(w, http.StatusBadRequest, "Invalid phone")
			return
		}

		query = `SELECT id, email, phone, status, phone_verified, email_verified, created_at, updated_at
		FROM users
		WHERE phone = $1`
		arg = req.Phone
		verificationType = phoneVerificationType
	}

	var (
		userDetails datatypes.UserResponse
	)

	if err := db.DB.QueryRow(query, arg).Scan(
		&userDetails.ID,
		&userDetails.Email,
		&userDetails.Phone,
		&userDetails.Status,
		&userDetails.PhoneVerified,
		&userDetails.EmailVerified,
		&userDetails.CreatedAt,
		&userDetails.UpdatedAt,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			utils.WriteJSON(w, http.StatusNotFound, "No user found with the given phone or email")
			return
		}

		utils.WriteJSON(w, http.StatusInternalServerError, "There was a problem in the server")
		return
	}

	token, err := newVerificationToken()
	if err != nil {
		utils.WriteJSON(w, http.StatusInternalServerError, "There was a problem in the server")
		return
	}

	// Invalidate any outstanding token of this type before issuing a new one,
	// so only the most recently requested code is redeemable.
	if _, err := db.DB.Exec(
		`
		UPDATE verification_tokens
		SET used_at = NOW()
		WHERE user_id = $1 AND type = $2 AND used_at IS NULL`,
		userDetails.ID,
		verificationType,
	); err != nil {
		utils.WriteJSON(w, http.StatusInternalServerError, "There was a problem in the server")
		return
	}

	if _, err := db.DB.Exec(
		`
		INSERT INTO verification_tokens (
			user_id,
			type,
			token_hash,
			expires_at
		)
		VALUES ($1, $2, $3, $4)`,
		userDetails.ID,
		verificationType,
		utils.HashToken(token),
		time.Now().Add(VerificationTokenTTL),
	); err != nil {
		utils.WriteJSON(w, http.StatusInternalServerError, "There was a problem in the server")
		return
	}

	if err := db.deliver(req.Type, userDetails.Email, userDetails.Phone, token); err != nil {
		utils.WriteJSON(w, http.StatusInternalServerError, "There was a problem in the server")
		return
	}

	utils.WriteJSON(w, http.StatusOK, verificationSentMessage)
}

// deliver publishes the verification token to whichever channel the request
// was for: email or sms.
func (db *DBHandler) deliver(reqType, email, phone, token string) error {
	if reqType == "email" {
		return db.MQ.PublishJSON(messaging.VerificationEmailQueue, verificationMessage{
			Email: email,
			Token: token,
		})
	}

	return db.MQ.PublishJSON(messaging.VerificationSMSQueue, verificationMessage{
		Phone: phone,
		Token: token,
	})
}

func (db *DBHandler) ConfirmVerificationHandler(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()

	var req ConfirmVerificationPayload
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		utils.WriteJSON(w, http.StatusBadRequest, err.Error())
		return
	}

	if req.Token == "" {
		utils.WriteJSON(w, http.StatusBadRequest, "Verification token is required")
		return
	}

	var (
		tokenID          uuid.UUID
		userID           uuid.UUID
		verificationType string
		expiresAt        time.Time
		usedAt           sql.NullTime
	)

	err := db.DB.QueryRow(
		`
		SELECT id, user_id, type, expires_at, used_at
		FROM verification_tokens
		WHERE token_hash = $1 AND type IN ($2, $3)`,
		utils.HashToken(req.Token),
		emailVerificationType,
		phoneVerificationType,
	).Scan(&tokenID, &userID, &verificationType, &expiresAt, &usedAt)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			utils.WriteJSON(w, http.StatusUnauthorized, errInvalidVerificationToken.Error())
			return
		}

		utils.WriteJSON(w, http.StatusInternalServerError, "There was a problem in the server")
		return
	}

	// A spent or lapsed token is answered the same way as an unknown one, so
	// the response says nothing about which tokens have ever existed.
	if usedAt.Valid || time.Now().After(expiresAt) {
		utils.WriteJSON(w, http.StatusUnauthorized, errInvalidVerificationToken.Error())
		return
	}

	tx, err := db.DB.Begin()
	if err != nil {
		utils.WriteJSON(w, http.StatusInternalServerError, "There was a problem in the server")
		return
	}

	defer tx.Rollback()

	// Spend the token only if it is still unspent, so two requests racing
	// with the same token cannot both confirm the account.
	result, err := tx.Exec(
		`
		UPDATE verification_tokens
		SET used_at = NOW()
		WHERE id = $1 AND used_at IS NULL`,
		tokenID,
	)

	if err != nil {
		utils.WriteJSON(w, http.StatusInternalServerError, "There was a problem in the server")
		return
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		utils.WriteJSON(w, http.StatusInternalServerError, "There was a problem in the server")
		return
	}

	if rowsAffected == 0 {
		utils.WriteJSON(w, http.StatusUnauthorized, errInvalidVerificationToken.Error())
		return
	}

	var (
		column  string
		message string
	)

	if verificationType == emailVerificationType {
		column = "email_verified"
		message = "Email has been verified"
	} else {
		column = "phone_verified"
		message = "Phone has been verified"
	}

	if _, err := tx.Exec(
		`UPDATE users SET `+column+` = TRUE, updated_at = NOW() WHERE id = $1`,
		userID,
	); err != nil {
		utils.WriteJSON(w, http.StatusInternalServerError, "There was a problem in the server")
		return
	}

	if err := tx.Commit(); err != nil {
		utils.WriteJSON(w, http.StatusInternalServerError, "There was a problem in the server")
		return
	}

	utils.WriteJSON(w, http.StatusOK, message)
}
