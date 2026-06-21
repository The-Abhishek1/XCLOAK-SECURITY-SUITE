package services

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"xcloak-ngfw/models"
	"xcloak-ngfw/repositories"
)

var validAPIKeyRoles = map[string]bool{"admin": true, "analyst": true, "viewer": true}

// hashAPIKey is the lookup hash — SHA-256, not bcrypt. bcrypt's slow,
// salted design defends against brute-forcing a low-entropy human password;
// these keys are already 256 bits of crypto/rand, so a fast deterministic
// hash is correct here (and required, since validation needs an indexed
// equality lookup, not a per-row comparison loop).
func hashAPIKey(rawKey string) string {
	sum := sha256.Sum256([]byte(rawKey))
	return hex.EncodeToString(sum[:])
}

// CreateAPIKey generates a new key, returning the full plaintext value
// exactly once — it is never stored or retrievable again afterward, only
// its hash and a short display prefix are.
func CreateAPIKey(tenantID int, createdBy, label, role string, expiresAt *time.Time) (string, *models.APIKey, error) {

	if !validAPIKeyRoles[role] {
		return "", nil, errors.New("invalid role — must be admin, analyst, or viewer")
	}

	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", nil, err
	}
	fullKey := "xck_" + hex.EncodeToString(b)
	prefix := fullKey[:12]

	key, err := repositories.CreateAPIKey(tenantID, label, hashAPIKey(fullKey), prefix, role, createdBy, expiresAt)
	if err != nil {
		return "", nil, err
	}

	LogEvent("CREATE_API_KEY", fmt.Sprintf("%s (%s role)", label, role), createdBy)

	return fullKey, key, nil
}

func GetAPIKeys(tenantID int) ([]models.APIKey, error) {
	return repositories.GetAPIKeysByTenant(tenantID)
}

func RevokeAPIKey(id, tenantID int, revokedBy string) error {
	if err := repositories.RevokeAPIKey(id, tenantID); err != nil {
		return err
	}
	LogEvent("REVOKE_API_KEY", fmt.Sprintf("key id %d", id), revokedBy)
	return nil
}

// ValidateAPIKey is the auth-path lookup, called by middleware.RequireAuth
// on every request bearing an xck_-prefixed token.
func ValidateAPIKey(rawKey string) (*models.APIKey, error) {

	key, err := repositories.GetAPIKeyByHash(hashAPIKey(rawKey))
	if err != nil {
		return nil, err
	}
	if key.RevokedAt != nil {
		return nil, errors.New("api key has been revoked")
	}
	if key.ExpiresAt != nil && time.Now().After(*key.ExpiresAt) {
		return nil, errors.New("api key has expired")
	}

	go repositories.TouchLastUsed(key.ID)

	return key, nil
}
