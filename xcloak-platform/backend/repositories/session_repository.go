package repositories

import (
	"crypto/sha256"
	"database/sql"
	"fmt"
	"time"

	"xcloak-platform/database"
	"xcloak-platform/models"
)

func hashToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return fmt.Sprintf("%x", h)
}

func CreateSession(s models.Session) error {
	_, err := database.DB.Exec(`
		INSERT INTO sessions (tenant_id, user_id, username, ip_address, user_agent, token_hash, expires_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7)
		ON CONFLICT (token_hash) DO NOTHING`,
		s.TenantID, s.UserID, s.Username, s.IPAddress, s.UserAgent,
		hashToken(s.TokenHash), s.ExpiresAt)
	return err
}

func TouchSession(tokenRaw string) {
	database.DB.Exec(
		`UPDATE sessions SET last_active_at=NOW() WHERE token_hash=$1 AND NOT revoked`,
		hashToken(tokenRaw))
}

func RevokeSessionByHash(tokenRaw string) {
	database.DB.Exec(
		`UPDATE sessions SET revoked=true WHERE token_hash=$1`, hashToken(tokenRaw))
}

func RevokeSessionByID(id, tenantID int) error {
	_, err := database.DB.Exec(
		`UPDATE sessions SET revoked=true WHERE id=$1 AND tenant_id=$2`, id, tenantID)
	return err
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

	var out []models.Session
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

	var out []models.Session
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

// EnforceConcurrentSessionLimit revokes oldest sessions if count exceeds max.
func EnforceConcurrentSessionLimit(tenantID, userID, maxSessions int) {
	database.DB.Exec(`
		UPDATE sessions SET revoked=true
		WHERE id IN (
			SELECT id FROM sessions
			WHERE tenant_id=$1 AND user_id=$2 AND NOT revoked
			ORDER BY last_active_at DESC
			OFFSET $3
		)`, tenantID, userID, maxSessions)
}

func GetSecurityPolicy(tenantID int) (models.TenantSecurityPolicy, error) {
	var p models.TenantSecurityPolicy
	err := database.DB.QueryRow(`
		SELECT tenant_id, session_timeout_mins, max_concurrent_sessions, mfa_required, updated_at
		FROM tenant_security_policy WHERE tenant_id=$1`, tenantID).Scan(
		&p.TenantID, &p.SessionTimeoutMins, &p.MaxConcurrentSessions, &p.MFARequired, &p.UpdatedAt)
	if err == sql.ErrNoRows {
		// Default policy
		p = models.TenantSecurityPolicy{
			TenantID:              tenantID,
			SessionTimeoutMins:    480,
			MaxConcurrentSessions: 10,
			MFARequired:           false,
			UpdatedAt:             time.Now(),
		}
		return p, nil
	}
	return p, err
}

func UpsertSecurityPolicy(p models.TenantSecurityPolicy) error {
	_, err := database.DB.Exec(`
		INSERT INTO tenant_security_policy (tenant_id, session_timeout_mins, max_concurrent_sessions, mfa_required, updated_at)
		VALUES ($1,$2,$3,$4,NOW())
		ON CONFLICT (tenant_id) DO UPDATE SET
			session_timeout_mins    = EXCLUDED.session_timeout_mins,
			max_concurrent_sessions = EXCLUDED.max_concurrent_sessions,
			mfa_required            = EXCLUDED.mfa_required,
			updated_at              = NOW()`,
		p.TenantID, p.SessionTimeoutMins, p.MaxConcurrentSessions, p.MFARequired)
	return err
}
