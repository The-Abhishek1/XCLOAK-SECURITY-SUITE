package repositories

import (
	"database/sql"
	"errors"
	"time"

	"xcloak-platform/database"
	"xcloak-platform/models"
)

var ErrAPIKeyNotFound = errors.New("api key not found")

// CreateAPIKey inserts a new key row. Only the hash + a short prefix are
// stored — the full key is never persisted anywhere.
func CreateAPIKey(tenantID int, label, keyHash, keyPrefix, role, createdBy string, expiresAt *time.Time) (*models.APIKey, error) {

	var k models.APIKey
	k.TenantID = tenantID
	k.Label = label
	k.KeyPrefix = keyPrefix
	k.Role = role
	k.CreatedBy = createdBy
	k.ExpiresAt = expiresAt

	err := database.DB.QueryRow(`
		INSERT INTO api_keys (tenant_id, label, key_hash, key_prefix, role, created_by, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING id, created_at
	`, tenantID, label, keyHash, keyPrefix, role, createdBy, expiresAt).Scan(&k.ID, &k.CreatedAt)

	if err != nil {
		return nil, err
	}

	return &k, nil
}

// GetAPIKeysByTenant lists every key (active or revoked) for a tenant —
// never returns key_hash; callers only get key_prefix for display.
func GetAPIKeysByTenant(tenantID int) ([]models.APIKey, error) {

	rows, err := database.DB.Query(`
		SELECT id, tenant_id, label, key_prefix, role, created_by, created_at,
		       expires_at, revoked_at, last_used_at
		FROM api_keys
		WHERE tenant_id = $1
		ORDER BY created_at DESC
	`, tenantID)

	if err != nil {
		return nil, err
	}
	defer rows.Close()

	keys := []models.APIKey{}
	for rows.Next() {
		var k models.APIKey
		if err := rows.Scan(&k.ID, &k.TenantID, &k.Label, &k.KeyPrefix, &k.Role, &k.CreatedBy,
			&k.CreatedAt, &k.ExpiresAt, &k.RevokedAt, &k.LastUsedAt); err == nil {
			keys = append(keys, k)
		}
	}

	return keys, nil
}

// GetAPIKeyByHash is the validation-path lookup — called on every API-key
// authenticated request, so it's a single indexed equality lookup, same
// cost as the plaintext agent-token lookup elsewhere in this codebase.
func GetAPIKeyByHash(keyHash string) (*models.APIKey, error) {

	var k models.APIKey

	err := database.DB.QueryRow(`
		SELECT id, tenant_id, label, role, created_by, created_at,
		       expires_at, revoked_at, last_used_at
		FROM api_keys
		WHERE key_hash = $1
	`, keyHash).Scan(&k.ID, &k.TenantID, &k.Label, &k.Role, &k.CreatedBy,
		&k.CreatedAt, &k.ExpiresAt, &k.RevokedAt, &k.LastUsedAt)

	if err == sql.ErrNoRows {
		return nil, ErrAPIKeyNotFound
	}
	if err != nil {
		return nil, err
	}

	return &k, nil
}

// RevokeAPIKey is IDOR-safe — WHERE id=$1 AND tenant_id=$2, same pattern as
// every other tenant-scoped mutation this session.
func RevokeAPIKey(id, tenantID int) error {
	tag, err := database.DB.Exec(`
		UPDATE api_keys SET revoked_at = NOW()
		WHERE id = $1 AND tenant_id = $2 AND revoked_at IS NULL
	`, id, tenantID)
	if err != nil {
		return err
	}
	if n, _ := tag.RowsAffected(); n == 0 {
		return ErrAPIKeyNotFound
	}
	return nil
}

// TouchLastUsed updates last_used_at — called fire-and-forget from the auth
// middleware so it never adds latency to the request it's authenticating.
func TouchLastUsed(id int) {
	database.DB.Exec(`UPDATE api_keys SET last_used_at = NOW() WHERE id = $1`, id)
}
