// auth.go
package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
	// "strings"
	// "time"
	// "github.com/golang-jwt/jwt/v5"
	// "golang.org/x/crypto/bcrypt"
)

type User struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

func init() {
	secret := os.Getenv("JWT_SECRET")
	if len(secret) == 0 {
		log.Println("⚠️ Using default dev JWT secret — DO NOT USE IN PRODUCTION")
		secret = "dev-secret-please-change-in-prod" // fallback for local
	}

}

func healthHandler(w http.ResponseWriter, r *http.Request) {

	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()

	if err := db.PingContext(ctx); err != nil {
		log.Printf("Health check failed : %v", err)
		http.Error(w, "DB unreachable", http.StatusServiceUnavailable)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POnly nPOST", http.StatusMethodNotAllowed)
		return
	}

	var creds struct {
		Email    string `json: "email"`
		Password string `json: "password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	var storedHash string
	err := db.QueryRowContext(context.Background(),
		"SELECT password_hash FROM users WHERE email = $1", creds.Email).Scan(&storedHash)

	if err != bcrypt.CompareHashAndPassword([]byte(storedHash), []byte(creds.Password)); err != nil {
		http.Error(w, "Invalid email/password", http.StatusUnauthorized)
		return
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"email": creds.Email,
		"exp":   time.Now().Add(24 * time.Hour).Unix(),
	})

	// tokenStr, err:= token.SignedString(jwt)

}
