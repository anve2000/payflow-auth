package main

import (
	"database/sql"
	_ "github.com/lib/pq"
	_ "github.com/mattn/go-sqlite3"
	"log"
	"os"
)

var db *sql.DB

func initDB() {
	var err error
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		db, err = sql.Open("sqlite3", "./auth.db")
		log.Println("Using SQLite (local, dev)")
	} else {
		db, err = sql.Open("postgres", dsn)
		log.Println("Using Postgresql (production)")
	}

	if err != nil {
		log.Fatal("DB connection failed : ", err)
	}

	_, err = db.Exec(`
	  CREATE TABLE IF NOT EXISTS users (
		id SERIAL PRIMARY KEY,
		email TEXT UNIQUE NOT NULL,
		password_hash TEXT NOT NULL
	  )
   `)

	if err != nil {
		log.Fatal("Failed to create Table")
	}
}
