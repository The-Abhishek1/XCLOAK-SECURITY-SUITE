package services

import (
	"context"
	"time"
)

const (
	loginFailWindow = 15 * time.Minute
	loginLockWindow = 15 * time.Minute
	loginFailLimit  = 5
)

// RecordLoginFailure increments the per-username failed-attempt counter.
// After loginFailLimit failures within loginFailWindow the account is locked.
// Failures in Redis are non-fatal — if Redis is unavailable the counter is
// skipped and lockout is not enforced (fail-open to avoid locking every user
// out when Redis is down).
func RecordLoginFailure(username string) {
	ctx := context.Background()
	failKey := "login:fail:" + username
	lockKey := "login:locked:" + username

	count, err := RDB.Incr(ctx, failKey).Result()
	if err != nil {
		return
	}
	// Re-set the window on every failure so sustained attacks don't escape
	// the window by spreading attempts across the TTL boundary.
	RDB.Expire(ctx, failKey, loginFailWindow)

	if count >= loginFailLimit {
		RDB.Set(ctx, lockKey, "1", loginLockWindow)
	}
}

// IsUsernameLocked reports whether the given username is currently locked out
// due to repeated failed login attempts. Returns false on Redis errors (fail-
// open) so a Redis outage doesn't deny service to all users.
func IsUsernameLocked(username string) bool {
	ctx := context.Background()
	n, err := RDB.Exists(ctx, "login:locked:"+username).Result()
	return err == nil && n > 0
}

// ClearLoginFailures removes the failure counter and lock for username.
// Call on successful login to prevent accidental lockout after a password
// change or temporary outage.
func ClearLoginFailures(username string) {
	ctx := context.Background()
	RDB.Del(ctx, "login:fail:"+username, "login:locked:"+username)
}
