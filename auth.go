// auth.go
package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
	"os"
	// "strings"
	// "time"

	// "github.com/golang-jwt/jwt/v5"
	// "golang.org/x/crypto/bcrypt"
)

type User struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

var jwtSecret = []byte(os.Getenv("JWT_SECRET"));

// if len(jwtSecret) == 0 {
// 	jwtSecret = []byte("dev-secret-please-change-in-prod") // fallback for local
// }

func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

func registerHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Only POST", http.StatusMethodNotAllowed)
		return
	}

	var user User
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
	}

	if user.Email == "" || user.Password == "" {
		http.Error(w, "Email and password required", http.StatusBadRequest)
		return
	}

	// Hash password
	// hash, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	// if err != nil {
	// 	http.Error(w, "Internal error", http.StatusInternalServerError)
	// 	return
	// }

	// // Save to DB
	// _, err = db.ExecContext(context.Background(),
	// 	"INSERT INTO users (email, password_hash) VALUES ($1, $2)",
	// 	user.Email, string(hash))
	// if err != nil {
	// 	if strings.Contains(err.Error(), "unique") {
	// 		http.Error(w, "Email already exists", http.StatusConflict)
	// 		return
	// 	}
	// 	http.Error(w, "DB error", http.StatusInternalServerError)
	// 	return
	// }

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"message": "User registered"})
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Only POST", http.StatusMethodNotAllowed)
		return
	}

	var creds struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// Fetch user
	var storedHash string
	err := db.QueryRowContext(context.Background(),
		"SELECT password_hash FROM users WHERE email = $1", creds.Email).
		Scan(&storedHash)
	if err == sql.ErrNoRows {
		http.Error(w, "Invalid email/password", http.StatusUnauthorized)
		return
	} else if err != nil {
		log.Printf("DB error: %v", err)
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}

	// Check password
	// if err := bcrypt.CompareHashAndPassword([]byte(storedHash), []byte(creds.Password)); err != nil {
	// 	http.Error(w, "Invalid email/password", http.StatusUnauthorized)
	// 	return
	// }

	// Issue JWT
	// token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
	// 	"email": creds.Email,
	// 	"exp":   time.Now().Add(24 * time.Hour).Unix(),
	// })

	// tokenStr, err := token.SignedString(jwtSecret)
	// if err != nil {
	// 	http.Error(w, "Token error", http.StatusInternalServerError)
	// 	return
	// }

	// json.NewEncoder(w).Encode(map[string]string{"token": tokenStr})
}