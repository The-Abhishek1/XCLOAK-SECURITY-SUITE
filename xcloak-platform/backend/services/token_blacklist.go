package services

import (
	"time"
)

const revokedKeyPrefix = "revoked_token:"
const revokedHashKeyPrefix = "revoked_session_hash:"

// RevokeToken blacklists a token in Redis until its natural JWT expiry,
// after which Redis drops the key itself — no manual cleanup needed.
func RevokeToken(token string, expiry time.Time) {
	ttl := time.Until(expiry)
	if ttl <= 0 {
		return
	}
	RDB.Set(ctx, revokedKeyPrefix+token, "1", ttl)
}

// IsRevoked returns true if the token has been blacklisted. Fails open on
// a Redis error — a brief Redis outage should degrade revocation checking,
// not take down all authenticated API access.
func IsRevoked(token string) bool {
	n, err := RDB.Exists(ctx, revokedKeyPrefix+token).Result()
	if err != nil {
		return false
	}
	return n > 0
}

// RevokeTokenHash blacklists a session by its sha256 token hash (the same
// hash stored in sessions.token_hash) until the session's natural expiry.
// This is the enforcement side of admin-initiated revocation (Settings'
// "Revoke Session", force_logout), where only the hash — never the raw
// JWT — is available server-side.
func RevokeTokenHash(hash string, expiry time.Time) {
	ttl := time.Until(expiry)
	if ttl <= 0 {
		return
	}
	RDB.Set(ctx, revokedHashKeyPrefix+hash, "1", ttl)
}

// IsHashRevoked returns true if the given token hash has been blacklisted.
// Fails open on a Redis error, same rationale as IsRevoked.
func IsHashRevoked(hash string) bool {
	n, err := RDB.Exists(ctx, revokedHashKeyPrefix+hash).Result()
	if err != nil {
		return false
	}
	return n > 0
}
