package main

import (
	"encoding/json"
	"net/http"
)

type HealthResponse struct {
	Status string `json:"status"`
}

func GetHealth(w http.ResponseWriter, r *http.Request) {
	json.NewEncoder(w).Encode(
		&HealthResponse{Status: "system ok"},
	)
}
