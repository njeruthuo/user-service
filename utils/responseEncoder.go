package utils

import (
	"encoding/json"
	"net/http"
)

type ResponseType struct {
	Message string
}

func WriteJSON(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(
		&ResponseType{Message: message},
	)
}
