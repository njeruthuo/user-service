// github.com/njeruthuo/user-service/authentication

package authentication

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
	_ "github.com/lib/pq"
	"github.com/njeruthuo/user-service/datatypes"
	"github.com/njeruthuo/user-service/utils"
)

type DBHandler struct {
	DB *sql.DB
}

type RegisterRequest struct {
	Email       string `json:"email"`
	Phone       string `json:"phone"`
	Password    string `json:"password"`
	LoginMethod string `json:"loginMethod"`
}

type UserLoginResponse struct {
	AccessToken  string `json:"accessToken"`
	RefreshToken string `json:"refreshToken"`
}

type RefreshTokenRequest struct {
	RefreshToken string `json:"refreshToken"`
}

type sqlExecutor interface {
	Exec(query string, args ...any) (sql.Result, error)
}

func storeRefreshToken(db sqlExecutor, userID uuid.UUID, refreshToken string) error {
	_, err := db.Exec(
		`
		INSERT INTO refresh_tokens (
			user_id,
			token_hash,
			expires_at
		)
		VALUES ($1, $2, $3)
		`,
		userID,
		utils.HashToken(refreshToken),
		time.Now().Add(utils.RefreshTokenTTL),
	)

	return err
}

func (h *DBHandler) RegisterHandler(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()

	var req RegisterRequest

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		utils.WriteJSON(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if !utils.IsValidEmail(req.Email) || !utils.IsValidPhone(req.Phone) {
		utils.WriteJSON(w, http.StatusBadRequest, "Invalid phone or email")
		return
	}

	if message := utils.ValidatePassword(req.Password); message != "" {
		utils.WriteJSON(w, http.StatusBadRequest, message)
		return
	}

	passwordHash, err := utils.PasswordDigest(req.Password)

	if err != nil {
		utils.WriteJSON(w, http.StatusBadRequest, "Bad password")
		return
	}

	var user datatypes.UserResponse

	err = h.DB.QueryRow(
		`
		INSERT INTO users (
			email,
			phone,
			password_hash
		)
		VALUES ($1, $2, $3)
		RETURNING
			id,
			status,
			phone_verified,
			email_verified,
			created_at,
			updated_at
		`,
		req.Email,
		req.Phone,
		passwordHash,
	).Scan(
		&user.ID,
		&user.Status,
		&user.PhoneVerified,
		&user.EmailVerified,
		&user.CreatedAt,
		&user.UpdatedAt,
	)

	if err != nil {
		// A unique violation names the column the caller has to change; every
		// other failure is ours, and must not be answered with a created user.
		if pqErr, ok := err.(*pq.Error); ok && pqErr.Code == "23505" {
			switch pqErr.Constraint {
			case "users_email_key":
				utils.WriteJSON(w, http.StatusConflict, "Email is already registered")

			case "users_phone_key":
				utils.WriteJSON(w, http.StatusConflict, "Phone number is already registered")

			default:
				utils.WriteJSON(w, http.StatusConflict, "User already exists")
			}

			return
		}

		utils.WriteJSON(w, http.StatusInternalServerError, "Internal server error")
		return
	}

	user.Email = req.Email
	user.Phone = req.Phone

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)

	json.NewEncoder(w).Encode(user)
}

func (h *DBHandler) LoginHandler(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()

	var loginRequest RegisterRequest
	err := json.NewDecoder(r.Body).Decode(&loginRequest)
	if err != nil {
		utils.WriteJSON(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if loginRequest.LoginMethod == "email" {
		if !utils.IsValidEmail(loginRequest.Email) {
			utils.WriteJSON(w, http.StatusBadRequest, "Invalid email")
			return
		}
	} else {
		if !utils.IsValidPhone(loginRequest.Phone) {
			utils.WriteJSON(w, http.StatusBadRequest, "Invalid phone")
			return
		}
	}

	var (
		userUser datatypes.UserResponse
		query    string
		arg      string
	)

	if loginRequest.LoginMethod == "email" {
		query = `
			SELECT id, email, phone, password_hash, status, phone_verified, email_verified, created_at, updated_at 
			FROM users 
			WHERE email = $1`
		arg = loginRequest.Email
	} else {
		query = `
			SELECT id, email, phone, password_hash, status, phone_verified, email_verified, created_at, updated_at 
			FROM users 
			WHERE phone = $1`
		arg = loginRequest.Phone
	}

	var passwordHash string

	err = h.DB.QueryRow(query, arg).Scan(
		&userUser.ID,
		&userUser.Email,
		&userUser.Phone,
		&passwordHash,
		&userUser.Status,
		&userUser.PhoneVerified,
		&userUser.EmailVerified,
		&userUser.CreatedAt,
		&userUser.UpdatedAt,
	)

	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		if errors.Is(err, sql.ErrNoRows) {
			utils.WriteJSON(w, http.StatusUnauthorized, "Invalid credentials")
			return
		}

		utils.WriteJSON(w, http.StatusInternalServerError, "Internal server error")
		return
	}

	if !utils.CheckPasswordHash(loginRequest.Password, passwordHash) {
		utils.WriteJSON(w, http.StatusUnauthorized, "Invalid credentials")
		return
	}

	if userUser.Status != "active" {
		utils.WriteJSON(w, http.StatusForbidden, "Account is not active")
		return
	}

	tokens, err := utils.GenerateTokenPair(
		userUser.ID.String(),
		userUser.Email,
		userUser.Phone,
	)

	if err != nil {
		utils.WriteJSON(w, http.StatusInternalServerError, "Internal server error")
		return
	}

	if err := storeRefreshToken(h.DB, userUser.ID, tokens.RefreshToken); err != nil {
		utils.WriteJSON(w, http.StatusInternalServerError, "Internal server error")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	json.NewEncoder(w).Encode(UserLoginResponse{
		AccessToken:  tokens.AccessToken,
		RefreshToken: tokens.RefreshToken,
	})
}

func (h *DBHandler) RefreshTokenHandler(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()

	var req RefreshTokenRequest

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		utils.WriteJSON(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if req.RefreshToken == "" {
		utils.WriteJSON(w, http.StatusBadRequest, "Refresh token is required")
		return
	}

	claims, err := utils.ParseToken(req.RefreshToken)
	if err != nil {
		utils.WriteJSON(w, http.StatusUnauthorized, "Invalid refresh token")
		return
	}

	// An access token must not be redeemable as a refresh token.
	if claims.TokenType != utils.RefreshTokenType {
		utils.WriteJSON(w, http.StatusUnauthorized, "Invalid refresh token")
		return
	}

	var (
		tokenID   uuid.UUID
		userID    uuid.UUID
		expiresAt time.Time
		revokedAt sql.NullTime
	)

	err = h.DB.QueryRow(
		`
		SELECT id, user_id, expires_at, revoked_at
		FROM refresh_tokens
		WHERE token_hash = $1`,
		utils.HashToken(req.RefreshToken),
	).Scan(&tokenID, &userID, &expiresAt, &revokedAt)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			utils.WriteJSON(w, http.StatusUnauthorized, "Invalid refresh token")
			return
		}

		utils.WriteJSON(w, http.StatusInternalServerError, "Internal server error")
		return
	}

	// A token presented after rotation means it leaked or was replayed, so
	// every outstanding session for that user is revoked.
	if revokedAt.Valid {
		if _, err := h.DB.Exec(
			`
			UPDATE refresh_tokens
			SET revoked_at = NOW()
			WHERE user_id = $1 AND revoked_at IS NULL`,
			userID,
		); err != nil {
			utils.WriteJSON(w, http.StatusInternalServerError, "Internal server error")
			return
		}

		utils.WriteJSON(w, http.StatusUnauthorized, "Invalid refresh token")
		return
	}

	if time.Now().After(expiresAt) {
		utils.WriteJSON(w, http.StatusUnauthorized, "Refresh token has expired")
		return
	}

	// Claims are only as fresh as the token, so identity and status are
	// re-read from the users table before minting a new pair.
	var user datatypes.UserResponse
	user.ID = userID

	err = h.DB.QueryRow(
		`
		SELECT email, phone, status
		FROM users
		WHERE id = $1`,
		userID,
	).Scan(&user.Email, &user.Phone, &user.Status)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			utils.WriteJSON(w, http.StatusUnauthorized, "Invalid refresh token")
			return
		}

		utils.WriteJSON(w, http.StatusInternalServerError, "Internal server error")
		return
	}

	if user.Status != "active" {
		utils.WriteJSON(w, http.StatusForbidden, "Account is not active")
		return
	}

	tokens, err := utils.GenerateTokenPair(user.ID.String(), user.Email, user.Phone)
	if err != nil {
		utils.WriteJSON(w, http.StatusInternalServerError, "Internal server error")
		return
	}

	tx, err := h.DB.Begin()
	if err != nil {
		utils.WriteJSON(w, http.StatusInternalServerError, "Internal server error")
		return
	}

	defer tx.Rollback()

	// Revoke only if still unrevoked, so two concurrent refreshes cannot both
	// rotate the same token.
	result, err := tx.Exec(
		`
		UPDATE refresh_tokens
		SET revoked_at = NOW()
		WHERE id = $1 AND revoked_at IS NULL`,
		tokenID,
	)

	if err != nil {
		utils.WriteJSON(w, http.StatusInternalServerError, "Internal server error")
		return
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		utils.WriteJSON(w, http.StatusInternalServerError, "Internal server error")
		return
	}

	if rowsAffected == 0 {
		utils.WriteJSON(w, http.StatusUnauthorized, "Invalid refresh token")
		return
	}

	if err := storeRefreshToken(tx, userID, tokens.RefreshToken); err != nil {
		utils.WriteJSON(w, http.StatusInternalServerError, "Internal server error")
		return
	}

	if err := tx.Commit(); err != nil {
		utils.WriteJSON(w, http.StatusInternalServerError, "Internal server error")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	json.NewEncoder(w).Encode(UserLoginResponse{
		AccessToken:  tokens.AccessToken,
		RefreshToken: tokens.RefreshToken,
	})
}

func (h *DBHandler) LogoutHandler(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()

	var req RefreshTokenRequest

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		utils.WriteJSON(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if req.RefreshToken == "" {
		utils.WriteJSON(w, http.StatusBadRequest, "Refresh token is required")
		return
	}

	claims, err := utils.ParseToken(req.RefreshToken)
	if err != nil {
		utils.WriteJSON(w, http.StatusUnauthorized, "Invalid refresh token")
		return
	}

	if claims.TokenType != utils.RefreshTokenType {
		utils.WriteJSON(w, http.StatusUnauthorized, "Invalid refresh token")
		return
	}

	if _, err := h.DB.Exec(
		`
		UPDATE refresh_tokens
		SET revoked_at = NOW()
		WHERE token_hash = $1 AND revoked_at IS NULL`,
		utils.HashToken(req.RefreshToken),
	); err != nil {
		utils.WriteJSON(w, http.StatusInternalServerError, "Internal server error")
		return
	}

	utils.WriteJSON(w, http.StatusOK, "Logged out successfully")
}
