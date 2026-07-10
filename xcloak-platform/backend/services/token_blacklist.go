package services

import (
	"time"
)

const revokedKeyPrefix = "revoked_token:"

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
