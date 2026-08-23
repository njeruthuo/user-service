// github.com/njeruthuo/user-service/authentication

package authentication

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
	_ "github.com/lib/pq"
	"github.com/njeruthuo/user-service/utils"
)

type DBHandler struct {
	DB *sql.DB
}

type AuthJsonResponse struct {
	Message string
}

type RegisterRequest struct {
	Email       string `json:"email"`
	Phone       string `json:"phone"`
	Password    string `json:"password"`
	LoginMethod string `json:"loginMethod"`
}

type UserResponse struct {
	ID            uuid.UUID `json:"id"`
	Email         string    `json:"email"`
	Phone         string    `json:"phone"`
	Status        string    `json:"status"`
	PhoneVerified bool      `json:"phone_verified"`
	EmailVerified bool      `json:"email_verified"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

type UserLoginResponse struct {
	AccessToken  string `json:"accessToken"`
	RefreshToken string `json:"refreshToken"`
}

func (h *DBHandler) RegisterHandler(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()

	var req RegisterRequest

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)

		json.NewEncoder(w).Encode(AuthJsonResponse{
			Message: "Invalid request body",
		})
		return
	}

	if !utils.IsValidEmail(req.Email) || !utils.IsValidPhone(req.Phone) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)

		json.NewEncoder(w).Encode(AuthJsonResponse{
			Message: "Invalid phone or email",
		})
		return
	}

	passwordHash, err := utils.PasswordDigest(req.Password)

	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)

		json.NewEncoder(w).Encode(AuthJsonResponse{
			Message: "Bad password",
		})
		return
	}

	var user UserResponse

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

	if pqErr, ok := err.(*pq.Error); ok {
		if pqErr.Code == "23505" {
			switch pqErr.Constraint {
			case "users_email_key":
				w.WriteHeader(http.StatusConflict)

				json.NewEncoder(w).Encode(AuthJsonResponse{
					Message: "Email is already registered",
				})

			case "users_phone_key":
				w.WriteHeader(http.StatusConflict)

				json.NewEncoder(w).Encode(AuthJsonResponse{
					Message: "Phone number is already registered",
				})

			default:
				w.WriteHeader(http.StatusConflict)

				json.NewEncoder(w).Encode(AuthJsonResponse{
					Message: "User already exists",
				})
			}

			return
		}
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
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	if loginRequest.LoginMethod == "email" {
		if !utils.IsValidEmail(loginRequest.Email) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)

			json.NewEncoder(w).Encode(AuthJsonResponse{
				Message: "Invalid email",
			})
			return
		}
	} else {
		if !utils.IsValidPhone(loginRequest.Phone) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)

			json.NewEncoder(w).Encode(AuthJsonResponse{
				Message: "Invalid phone",
			})
			return
		}
	}

}
func (h *DBHandler) LogoutHandler(w http.ResponseWriter, r *http.Request)         {}
func (h *DBHandler) RefreshTokenHandler(w http.ResponseWriter, r *http.Request)   {}
func (h *DBHandler) ForgotPasswordHandler(w http.ResponseWriter, r *http.Request) {}
func (h *DBHandler) ChangePasswordHandler(w http.ResponseWriter, r *http.Request) {}
func (h *DBHandler) ResetPasswordHandler(w http.ResponseWriter, r *http.Request)  {}
