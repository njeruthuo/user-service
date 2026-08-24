package main

import (
	"database/sql"
	"fmt"
	"os"
)

var (
	DatabaseName     = os.Getenv("DatabaseName")
	DatabaseUser     = os.Getenv("DatabaseUser")
	DatabaseHost     = os.Getenv("DatabaseHost")
	DatabasePassword = os.Getenv("DatabasePassword")
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
