// Package testenv provides test database setup/teardown for integration tests.
// Tests in this package are gated by the "integration" build tag and require
// docker-compose.test.yml services to be running.
//
// Usage:
//
//	//go:build integration
//
//	func TestFoo(t *testing.T) {
//	    db := testenv.SetupDB(t)
//	    defer testenv.TeardownDB(t, db)
//	    testenv.LoadFixtures(t, db)
//	    // … test with a real database
//	}
package testenv

import (
	"database/sql"
	"os"
	"testing"

	_ "github.com/lib/pq"
)

// DSN returns the test database connection string.
// Set TEST_DB_URL to override for CI environments.
func DSN() string {
	if v := os.Getenv("TEST_DB_URL"); v != "" {
		return v
	}
	return "postgres://xcloak:testpassword@localhost:5433/xcloak_test?sslmode=disable"
}

// RedisURL returns the test Redis URL.
func RedisURL() string {
	if v := os.Getenv("TEST_REDIS_URL"); v != "" {
		return v
	}
	return "redis://localhost:6380"
}

// SetupDB opens a connection to the test database.
// It skips (not fails) the test if the database isn't reachable — this lets
// the unit-test suite pass in environments without Docker.
func SetupDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("postgres", DSN())
	if err != nil {
		t.Fatalf("testenv: open DB: %v", err)
	}
	if err := db.Ping(); err != nil {
		t.Skipf("testenv: postgres not available (%v) — start docker-compose.test.yml first", err)
	}
	return db
}

// TeardownDB closes the database connection.
func TeardownDB(t *testing.T, db *sql.DB) {
	t.Helper()
	if err := db.Close(); err != nil {
		t.Errorf("testenv: close DB: %v", err)
	}
}

// LoadFixtures executes testenv/fixtures/base.sql against the test DB.
func LoadFixtures(t *testing.T, db *sql.DB) {
	t.Helper()
	data, err := os.ReadFile("testenv/fixtures/base.sql")
	if err != nil {
		// Try relative path when called from a service subdirectory test
		data, err = os.ReadFile("../testenv/fixtures/base.sql")
		if err != nil {
			t.Fatalf("testenv: read fixtures: %v", err)
		}
	}
	if _, err := db.Exec(string(data)); err != nil {
		t.Fatalf("testenv: load fixtures: %v", err)
	}
}

// Truncate removes all rows from the named tables (in order) to isolate tests.
func Truncate(t *testing.T, db *sql.DB, tables ...string) {
	t.Helper()
	for _, tbl := range tables {
		if _, err := db.Exec("TRUNCATE TABLE " + tbl + " CASCADE"); err != nil {
			t.Fatalf("testenv: truncate %s: %v", tbl, err)
		}
	}
}
