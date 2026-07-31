package services

import (
	"context"
	"time"
)

// loginFailWindow is fixed (not tenant-configurable — Settings only exposes
// the failure threshold and lockout duration, not this counting window).
const loginFailWindow = 15 * time.Minute

// defaultLoginFailLimit/defaultLoginLockMins back the legacy no-tenant call
// path (RecordLoginFailure/IsUsernameLocked without a policy) so any
// existing caller that hasn't been updated keeps its original behavior.
const (
	defaultLoginFailLimit = 5
	defaultLoginLockMins  = 15
)

// RecordLoginFailure increments the per-username failed-attempt counter.
// After maxFails failures within loginFailWindow the account is locked for
// lockMins. Failures in Redis are non-fatal — if Redis is unavailable the
// counter is skipped and lockout is not enforced (fail-open to avoid
// locking every user out when Redis is down).
func RecordLoginFailure(username string, maxFails, lockMins int) {
	if maxFails <= 0 {
		maxFails = defaultLoginFailLimit
	}
	if lockMins <= 0 {
		lockMins = defaultLoginLockMins
	}
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

	if count >= int64(maxFails) {
		RDB.Set(ctx, lockKey, "1", time.Duration(lockMins)*time.Minute)
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
