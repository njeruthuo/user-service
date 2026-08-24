// github.com/njeruthuo/user-service

package main

import (
	"log"
	"net/http"

	"github.com/gorilla/mux"
	_ "github.com/lib/pq"
	"github.com/njeruthuo/user-service/authentication"
	"github.com/njeruthuo/user-service/passwdmgt"
)

func main() {
	db, err := ConnectDatabase()
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	authHandler := authentication.DBHandler{
		DB: db,
	}
	passwdHandler := passwdmgt.DBHandler{
		DB: db,
	}

	router := mux.NewRouter()

	router.HandleFunc("/health", GetHealth).Methods(http.MethodGet)
	router.HandleFunc("/auth/login", authHandler.LoginHandler).Methods(http.MethodPost)
	router.HandleFunc("/auth/logout", authHandler.LogoutHandler).Methods(http.MethodPost)
	router.HandleFunc("/auth/register", authHandler.RegisterHandler).Methods(http.MethodPost)
	router.HandleFunc("/auth/refresh", authHandler.RefreshTokenHandler).Methods(http.MethodPost)
	router.HandleFunc("/auth/forgot-password", passwdHandler.ForgotPasswordHandler).Methods(http.MethodPost)
	router.HandleFunc("/auth/reset-password", passwdHandler.ResetPasswordHandler).Methods(http.MethodPost)
	router.HandleFunc("/auth/change-password", passwdHandler.ChangePasswordHandler).Methods(http.MethodPost)

	log.Println("System starting at port 8000")
	log.Fatal(http.ListenAndServe(":8000", router))
}
