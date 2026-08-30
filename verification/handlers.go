package verification

import (
	"database/sql"
	"encoding/json"
	"net/http"

	"github.com/njeruthuo/user-service/datatypes"
	"github.com/njeruthuo/user-service/messaging"
)

type DBHandler struct {
	DB *sql.DB
	MQ *messaging.RabbitMQ
}

type VerificationPayload struct {
	Phone string `json:"phone"`
	Email string `json:"email"`
	Type  string `json:"type"` // can be phone or email verification
}

type ResponseType struct {
	Message string
}

func WriteJSON(w http.ResponseWriter, status int, message string) {
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(
		&ResponseType{Message: message},
	)
}

func (db *DBHandler) VerificationHandler(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()

	var req VerificationPayload
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteJSON(w, http.StatusBadRequest, err.Error())
		return
	}

	var (
		query string
		args  string
	)

	if req.Type == "email" {
		query = `SELECT id, email, phone, password_hash, status, phone_verified, email_verified, created_at, updated_at 
		FROM users 
		WHERE email = $1`
		args = req.Email
	} else {
		query = `SELECT id, email, phone, password_hash, status, phone_verified, email_verified, created_at, updated_at 
		FROM users 
		WHERE phone = $1`
		args = req.Phone
	}

	var userDetails datatypes.UserResponse

	if err := db.DB.QueryRow(query, args).Scan(
		&userDetails.ID,
		&userDetails.Email,
		&userDetails.Phone,
		&userDetails.Status,
		&userDetails.PhoneVerified,
		&userDetails.EmailVerified,
		&userDetails.CreatedAt,
		&userDetails.UpdatedAt,
	); err != nil {
		WriteJSON(w, http.StatusInternalServerError, "There was a problem in the server") // add a 404 error if a user with phone or email doesn't exist.
		return
	}

	// if the user exists, send a message to the queue using rabbitmq and create and entry to the database.
	
}
