package services

import (
	"database/sql"

	"xcloak-platform/database"
)

// GetDB exposes the shared DB connection for use in API handlers
// that need direct queries (e.g. hunt query rerun).
func GetDB() *sql.DB {
	return database.DB
}
