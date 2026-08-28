package verification

import (
	"database/sql"
	"net/http"
)

type DBHandler struct {
	DB *sql.DB
}

func (db *DBHandler) VerificationHandler(w http.ResponseWriter, r *http.Request) {}
