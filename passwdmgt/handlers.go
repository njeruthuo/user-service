package passwdmgt

import (
	"database/sql"
	"net/http"
)

type DBHandler struct {
	DB *sql.DB
}

func (h *DBHandler) ForgotPasswordHandler(w http.ResponseWriter, r *http.Request) {}
func (h *DBHandler) ChangePasswordHandler(w http.ResponseWriter, r *http.Request) {}
func (h *DBHandler) ResetPasswordHandler(w http.ResponseWriter, r *http.Request)  {}
