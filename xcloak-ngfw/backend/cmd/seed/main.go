package main

import (
	"database/sql"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func main() {
	godotenv.Load()

	dsn := fmt.Sprintf(
		"host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
		env("DB_HOST", "localhost"),
		env("DB_PORT", "5432"),
		env("DB_USER", "xcloak"),
		env("DB_PASSWORD", "xcloak"),
		env("DB_NAME", "ngfw"),
	)

	var db *sql.DB
	var err error
	for i := 1; i <= 30; i++ {
		db, err = sql.Open("postgres", dsn)
		if err == nil {
			if err = db.Ping(); err == nil {
				break
			}
		}
		log.Printf("[seed] waiting for postgres (%d/30)...", i)
		time.Sleep(3 * time.Second)
	}
	if err != nil {
		log.Fatalf("[seed] could not connect to postgres: %v", err)
	}
	defer db.Close()

	// Wait for schema — migrations run inside the backend at startup.
	// Since we depend on backend being healthy, schema is guaranteed ready.
	// Belt-and-suspenders: retry if users table doesn't exist yet.
	for i := 1; i <= 10; i++ {
		var n int
		if scanErr := db.QueryRow(`SELECT COUNT(*) FROM information_schema.tables WHERE table_name='users'`).Scan(&n); scanErr == nil && n == 1 {
			break
		}
		log.Printf("[seed] waiting for schema to be ready (%d/10)...", i)
		time.Sleep(2 * time.Second)
	}

	seedAdmin(db)
	log.Println("[seed] done")
}

func seedAdmin(db *sql.DB) {
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM users WHERE username = 'admin'`).Scan(&count); err != nil {
		log.Fatalf("[seed] check admin: %v", err)
	}
	if count > 0 {
		log.Println("[seed] admin user already exists, skipping")
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte("admin1234"), 12)
	if err != nil {
		log.Fatalf("[seed] bcrypt: %v", err)
	}

	if _, err = db.Exec(`
		INSERT INTO users (username, email, password_hash, role, is_active, is_platform_admin, tenant_id)
		VALUES ('admin', 'admin@xcloak.local', $1, 'admin', true, true, 1)
	`, string(hash)); err != nil {
		log.Fatalf("[seed] insert admin: %v", err)
	}

	log.Println("[seed] ✓ admin user created — login: admin / admin1234")
}
