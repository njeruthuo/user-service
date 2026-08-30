// github.com/njeruthuo/user-service

package main

import (
	"log"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
	"github.com/njeruthuo/user-service/authentication"
	"github.com/njeruthuo/user-service/health"
	"github.com/njeruthuo/user-service/logs"
	"github.com/njeruthuo/user-service/messaging"
	"github.com/njeruthuo/user-service/passwdmgt"
	"github.com/njeruthuo/user-service/verification"
)

func main() {
	if err := godotenv.Load(); err != nil {
		log.Println("no .env file found, using environment variables")
	}

	db, err := ConnectDatabase()
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	mq, err := messaging.NewRabbitMQ()
	if err != nil {
		log.Fatal(err)
	}
	defer mq.Close()

	verification := verification.DBHandler{
		DB: db,
		MQ: mq,
	}

	authHandler := authentication.DBHandler{
		DB: db,
	}

	passwdHandler := passwdmgt.DBHandler{
		DB: db,
		MQ: mq,
	}

	passwdHandler.Deliverer = &passwdHandler

	router := mux.NewRouter()

	// Every request, on every route below, is recorded to the audit log.
	router.Use(logs.Middleware(mq))

	router.HandleFunc("/health", health.GetHealth).Methods(http.MethodGet)

	router.HandleFunc("/verify", verification.VerificationHandler).Methods(http.MethodPost)

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
