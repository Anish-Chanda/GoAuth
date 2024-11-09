package main

import (
	"database/sql"
	"log"
	"net/http"

	_ "github.com/mattn/go-sqlite3"

	auths "github.com/anish-chanda/goauth/authS"
	"github.com/anish-chanda/goauth/config"
	sqlite3 "github.com/anish-chanda/goauth/db/sqlite3"
)

func main() {
	db, err := sql.Open("sqlite3", "./test.db")
	if err != nil {
		log.Fatalf("could not open db: %v\n", err)
	}

	authService, err := auths.NewAuthService(config.DefaultConfig(), sqlite3.NewSQLite3DB(db))
	if err != nil {
		log.Fatalf("could not create auth service: %v\n", err)
	}

	http.HandleFunc("/signup", authService.EmailSignup)
	http.HandleFunc("/refresh", authService.HandleRefresh)
	http.HandleFunc("/login", authService.EmailLogin)

	log.Println("Starting server on :8080")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatalf("could not start server: %v\n", err)
	}
}
