package main

import (
	"log"
	"net/http"

	"github.com/anish-chanda/goauth/auths"
	"github.com/anish-chanda/goauth/config"
)

func main() {
	authService := &auths.AuthService{
		Config: config.DefaultConfig(),
	}

	http.HandleFunc("/signup", authService.EmailSignup)

	log.Println("Starting server on :8080")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatalf("could not start server: %v\n", err)
	}
}
