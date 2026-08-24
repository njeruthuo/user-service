package main

import (
	"database/sql"
	"fmt"
)

const (
	DatabaseUser     = "postgres"
	DatabasePassword = "mysupersecretpassword"
	DatabaseHost     = "localhost"
	DatabaseName     = "user_service"
)

func ConnectDatabase() (*sql.DB, error) {
	dbInfo := fmt.Sprintf(
		"user=%s password=%s host=%s dbname=%s sslmode=disable",
		DatabaseUser,
		DatabasePassword,
		DatabaseHost,
		DatabaseName,
	)

	var err error
	db, err := sql.Open("postgres", dbInfo)

	if err != nil {
		return nil, err
	}

	if err := db.Ping(); err != nil {
		return nil, err
	}

	return db, nil
}
