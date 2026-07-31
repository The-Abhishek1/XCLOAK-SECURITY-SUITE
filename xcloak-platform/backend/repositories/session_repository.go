package repositories

import (
	"crypto/sha256"
	"database/sql"
	"fmt"
	"time"

	"xcloak-platform/database"
	"xcloak-platform/models"
)

// HashToken is the single source of truth for how a raw JWT is turned into
// the value stored in sessions.token_hash — exported so callers that need
// to blacklist a session's real token in Redis (which only ever stores the
// hash, never the raw JWT) can compute the same hash independently.
func HashToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return fmt.Sprintf("%x", h)
}

func CreateSession(s models.Session) error {
	_, err := database.DB.Exec(`
		INSERT INTO sessions (tenant_id, user_id, username, ip_address, user_agent, token_hash, expires_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7)
		ON CONFLICT (token_hash) DO NOTHING`,
		s.TenantID, s.UserID, s.Username, s.IPAddress, s.UserAgent,
		HashToken(s.TokenHash), s.ExpiresAt)
	return err
}

func TouchSession(tokenRaw string) {
	database.DB.Exec(
		`UPDATE sessions SET last_active_at=NOW() WHERE token_hash=$1 AND NOT revoked`,
		HashToken(tokenRaw))
}

// RevokeSessionByHash marks the sessions row for this raw token as revoked
// and returns its hash/expiry so the caller can also blacklist it in Redis
// (the actual per-request enforcement point) — a DB-only revoke.true would
// leave the session's own JWT valid until it naturally expires.
func RevokeSessionByHash(tokenRaw string) (hash string, expiresAt time.Time) {
	hash = HashToken(tokenRaw)
	database.DB.QueryRow(
		`UPDATE sessions SET revoked=true WHERE token_hash=$1 RETURNING expires_at`, hash).Scan(&expiresAt)
	return hash, expiresAt
}

// RevokeSessionByID marks a single session revoked by its DB id and returns
// its hash/expiry for the same reason as RevokeSessionByHash.
func RevokeSessionByID(id, tenantID int) (hash string, expiresAt time.Time, err error) {
	err = database.DB.QueryRow(
		`UPDATE sessions SET revoked=true WHERE id=$1 AND tenant_id=$2 AND NOT revoked RETURNING token_hash, expires_at`,
		id, tenantID).Scan(&hash, &expiresAt)
	if err == sql.ErrNoRows {
		err = nil // already revoked or doesn't exist — not a failure
	}
	return hash, expiresAt, err
}

// RevokedSession is a revoked session's hash/expiry, returned by the bulk
// revoke functions below so callers can blacklist each one in Redis too —
// the DB row alone doesn't stop the session's live JWT from working.
type RevokedSession struct {
	Hash      string
	ExpiresAt time.Time
}

func scanRevokedSessions(rows *sql.Rows, err error) ([]RevokedSession, error) {
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []RevokedSession
	for rows.Next() {
		var s RevokedSession
		if err := rows.Scan(&s.Hash, &s.ExpiresAt); err == nil {
			out = append(out, s)
		}
	}
	return out, nil
}

// RevokeSessionsByUsername revokes every active session for a user (used by
// UEBA/Insider Threat's force_logout) and returns each revoked session's
// hash/expiry so the caller can blacklist all of them in Redis too.
func RevokeSessionsByUsername(tenantID int, username string) ([]RevokedSession, error) {
	return scanRevokedSessions(database.DB.Query(
		`UPDATE sessions SET revoked=true WHERE tenant_id=$1 AND username=$2 AND NOT revoked
		 RETURNING token_hash, expires_at`, tenantID, username))
}

func GetActiveSessions(tenantID, userID int) ([]models.Session, error) {
	rows, err := database.DB.Query(`
		SELECT id, tenant_id, user_id, username, COALESCE(ip_address,''), COALESCE(user_agent,''),
		       created_at, last_active_at, expires_at, revoked
		FROM sessions
		WHERE tenant_id=$1 AND user_id=$2 AND NOT revoked AND expires_at > NOW()
		ORDER BY last_active_at DESC`, tenantID, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []models.Session{}
	for rows.Next() {
		var s models.Session
		var uid sql.NullInt64
		rows.Scan(&s.ID, &s.TenantID, &uid, &s.Username, &s.IPAddress, &s.UserAgent,
			&s.CreatedAt, &s.LastActiveAt, &s.ExpiresAt, &s.Revoked)
		if uid.Valid {
			id := int(uid.Int64)
			s.UserID = &id
		}
		out = append(out, s)
	}
	return out, nil
}

func GetAllActiveSessions(tenantID int) ([]models.Session, error) {
	rows, err := database.DB.Query(`
		SELECT id, tenant_id, user_id, username, COALESCE(ip_address,''), COALESCE(user_agent,''),
		       created_at, last_active_at, expires_at, revoked
		FROM sessions
		WHERE tenant_id=$1 AND NOT revoked AND expires_at > NOW()
		ORDER BY last_active_at DESC
		LIMIT 200`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []models.Session{}
	for rows.Next() {
		var s models.Session
		var uid sql.NullInt64
		rows.Scan(&s.ID, &s.TenantID, &uid, &s.Username, &s.IPAddress, &s.UserAgent,
			&s.CreatedAt, &s.LastActiveAt, &s.ExpiresAt, &s.Revoked)
		if uid.Valid {
			id := int(uid.Int64)
			s.UserID = &id
		}
		out = append(out, s)
	}
	return out, nil
}

func PurgeExpiredSessions() {
	database.DB.Exec(`DELETE FROM sessions WHERE expires_at < NOW() - INTERVAL '7 days'`)
}

// EnforceConcurrentSessionLimit revokes the oldest sessions beyond
// maxSessions and returns each one's hash/expiry so the caller can also
// blacklist them in Redis.
func EnforceConcurrentSessionLimit(tenantID, userID, maxSessions int) ([]RevokedSession, error) {
	return scanRevokedSessions(database.DB.Query(`
		UPDATE sessions SET revoked=true
		WHERE id IN (
			SELECT id FROM sessions
			WHERE tenant_id=$1 AND user_id=$2 AND NOT revoked
			ORDER BY last_active_at DESC
			OFFSET $3
		)
		RETURNING token_hash, expires_at`, tenantID, userID, maxSessions))
}

func GetSecurityPolicy(tenantID int) (models.TenantSecurityPolicy, error) {
	var p models.TenantSecurityPolicy
	err := database.DB.QueryRow(`
		SELECT tenant_id, session_timeout_mins, max_concurrent_sessions, mfa_required,
		       min_password_length, require_special_chars, require_numbers, password_expiry_days,
		       max_failed_logins, lockout_duration_mins, ip_allowlist, updated_at
		FROM tenant_security_policy WHERE tenant_id=$1`, tenantID).Scan(
		&p.TenantID, &p.SessionTimeoutMins, &p.MaxConcurrentSessions, &p.MFARequired,
		&p.MinPasswordLength, &p.RequireSpecialChars, &p.RequireNumbers, &p.PasswordExpiryDays,
		&p.MaxFailedLogins, &p.LockoutDurationMins, &p.IPAllowlist, &p.UpdatedAt)
	if err == sql.ErrNoRows {
		// Default policy — matches tenant_security_policy's own column
		// DEFAULTs, so a tenant with no row yet behaves identically to one
		// that has an explicit row at the defaults.
		p = models.TenantSecurityPolicy{
			TenantID:              tenantID,
			SessionTimeoutMins:    480,
			MaxConcurrentSessions: 10,
			MFARequired:           false,
			MinPasswordLength:     8,
			RequireSpecialChars:   true,
			RequireNumbers:        true,
			PasswordExpiryDays:    0,
			MaxFailedLogins:       5,
			LockoutDurationMins:   30,
			IPAllowlist:           "",
			UpdatedAt:             time.Now(),
		}
		return p, nil
	}
	return p, err
}

func UpsertSecurityPolicy(p models.TenantSecurityPolicy) error {
	_, err := database.DB.Exec(`
		INSERT INTO tenant_security_policy (tenant_id, session_timeout_mins, max_concurrent_sessions, mfa_required,
			min_password_length, require_special_chars, require_numbers, password_expiry_days,
			max_failed_logins, lockout_duration_mins, ip_allowlist, updated_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,NOW())
		ON CONFLICT (tenant_id) DO UPDATE SET
			session_timeout_mins    = EXCLUDED.session_timeout_mins,
			max_concurrent_sessions = EXCLUDED.max_concurrent_sessions,
			mfa_required            = EXCLUDED.mfa_required,
			min_password_length     = EXCLUDED.min_password_length,
			require_special_chars   = EXCLUDED.require_special_chars,
			require_numbers         = EXCLUDED.require_numbers,
			password_expiry_days    = EXCLUDED.password_expiry_days,
			max_failed_logins       = EXCLUDED.max_failed_logins,
			lockout_duration_mins   = EXCLUDED.lockout_duration_mins,
			ip_allowlist            = EXCLUDED.ip_allowlist,
			updated_at              = NOW()`,
		p.TenantID, p.SessionTimeoutMins, p.MaxConcurrentSessions, p.MFARequired,
		p.MinPasswordLength, p.RequireSpecialChars, p.RequireNumbers, p.PasswordExpiryDays,
		p.MaxFailedLogins, p.LockoutDurationMins, p.IPAllowlist)
	return err
}
