package repositories

import (
	"database/sql"
	"time"

	"github.com/lib/pq"

	"xcloak-platform/database"
	"xcloak-platform/models"
)

func UpsertUserRiskProfile(p models.UserRiskProfile) error {
	_, err := database.DB.Exec(`
		INSERT INTO user_risk_profiles
			(tenant_id, username, source, risk_score, total_events, failed_logins,
			 off_hours_events, unique_ips, privilege_escalations, flags, last_seen_ip, last_event_at, analyzed_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,NOW())
		ON CONFLICT (tenant_id, username, source) DO UPDATE SET
			risk_score            = EXCLUDED.risk_score,
			total_events          = EXCLUDED.total_events,
			failed_logins         = EXCLUDED.failed_logins,
			off_hours_events      = EXCLUDED.off_hours_events,
			unique_ips            = EXCLUDED.unique_ips,
			privilege_escalations = EXCLUDED.privilege_escalations,
			flags                 = EXCLUDED.flags,
			last_seen_ip          = EXCLUDED.last_seen_ip,
			last_event_at         = EXCLUDED.last_event_at,
			analyzed_at           = NOW()`,
		p.TenantID, p.Username, p.Source, p.RiskScore, p.TotalEvents, p.FailedLogins,
		p.OffHoursEvents, p.UniqueIPs, p.PrivilegeEscalations, pq.Array(p.Flags),
		p.LastSeenIP, p.LastEventAt,
	)
	return err
}

func GetUserRiskProfiles(tenantID, limit, offset int) ([]models.UserRiskProfile, int, error) {
	var total int
	database.DB.QueryRow(`SELECT COUNT(*) FROM user_risk_profiles WHERE tenant_id=$1`, tenantID).Scan(&total)

	rows, err := database.DB.Query(`
		SELECT id, tenant_id, username, source, risk_score, total_events, failed_logins,
		       off_hours_events, unique_ips, privilege_escalations, flags,
		       COALESCE(last_seen_ip,''), last_event_at, analyzed_at
		FROM user_risk_profiles WHERE tenant_id=$1
		ORDER BY risk_score DESC, analyzed_at DESC
		LIMIT $2 OFFSET $3`, tenantID, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	out := []models.UserRiskProfile{}
	for rows.Next() {
		var p models.UserRiskProfile
		var flags pq.StringArray
		if err := rows.Scan(&p.ID, &p.TenantID, &p.Username, &p.Source, &p.RiskScore,
			&p.TotalEvents, &p.FailedLogins, &p.OffHoursEvents, &p.UniqueIPs,
			&p.PrivilegeEscalations, &flags, &p.LastSeenIP, &p.LastEventAt, &p.AnalyzedAt); err != nil {
			continue
		}
		p.Flags = []string(flags)
		out = append(out, p)
	}
	return out, total, nil
}

func DeleteOldUEBAEvents(tenantID int, before time.Time) error {
	_, err := database.DB.Exec(
		`DELETE FROM ueba_events WHERE tenant_id=$1 AND detected_at < $2`, tenantID, before)
	return err
}

func BulkInsertUEBAEvents(events []models.UEBAEvent) error {
	if len(events) == 0 {
		return nil
	}
	tx, err := database.DB.Begin()
	if err != nil {
		return err
	}
	stmt, err := tx.Prepare(`
		INSERT INTO ueba_events (tenant_id, username, event_type, severity, description, source_ip, agent_id, raw_log, detected_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`)
	if err != nil {
		tx.Rollback()
		return err
	}
	defer stmt.Close()
	for _, e := range events {
		var agentID interface{}
		if e.AgentID != nil {
			agentID = *e.AgentID
		}
		if _, err := stmt.Exec(e.TenantID, e.Username, e.EventType, e.Severity, e.Description,
			e.SourceIP, agentID, e.RawLog, e.DetectedAt); err != nil {
			tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}

func GetUEBAEvents(tenantID int, username string, limit, offset int) ([]models.UEBAEvent, int, error) {
	var total int
	if username != "" {
		database.DB.QueryRow(`SELECT COUNT(*) FROM ueba_events WHERE tenant_id=$1 AND username=$2`, tenantID, username).Scan(&total)
	} else {
		database.DB.QueryRow(`SELECT COUNT(*) FROM ueba_events WHERE tenant_id=$1`, tenantID).Scan(&total)
	}

	q := `SELECT id, tenant_id, username, event_type, severity, description,
	             COALESCE(source_ip,''), agent_id, COALESCE(raw_log,''), detected_at
	      FROM ueba_events WHERE tenant_id=$1`
	args := []interface{}{tenantID}
	if username != "" {
		q += ` AND username=$2 ORDER BY detected_at DESC LIMIT $3 OFFSET $4`
		args = append(args, username, limit, offset)
	} else {
		q += ` ORDER BY detected_at DESC LIMIT $2 OFFSET $3`
		args = append(args, limit, offset)
	}

	rows, err := database.DB.Query(q, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	out := []models.UEBAEvent{}
	for rows.Next() {
		var e models.UEBAEvent
		var agentID sql.NullInt64
		rows.Scan(&e.ID, &e.TenantID, &e.Username, &e.EventType, &e.Severity, &e.Description,
			&e.SourceIP, &agentID, &e.RawLog, &e.DetectedAt)
		if agentID.Valid {
			id := int(agentID.Int64)
			e.AgentID = &id
		}
		out = append(out, e)
	}
	return out, total, nil
}

func CreateFeedSyncLog(l models.FeedSyncLog) error {
	_, err := database.DB.Exec(`
		INSERT INTO feed_sync_log (feed_id, tenant_id, status, iocs_added, error_message)
		VALUES ($1,$2,$3,$4,$5)`,
		l.FeedID, l.TenantID, l.Status, l.IOCsAdded, l.ErrorMessage)
	return err
}

func GetFeedSyncLog(feedID, tenantID, limit int) ([]models.FeedSyncLog, error) {
	rows, err := database.DB.Query(`
		SELECT id, feed_id, tenant_id, status, iocs_added, COALESCE(error_message,''), synced_at
		FROM feed_sync_log WHERE feed_id=$1 AND tenant_id=$2
		ORDER BY synced_at DESC LIMIT $3`, feedID, tenantID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []models.FeedSyncLog{}
	for rows.Next() {
		var l models.FeedSyncLog
		rows.Scan(&l.ID, &l.FeedID, &l.TenantID, &l.Status, &l.IOCsAdded, &l.ErrorMessage, &l.SyncedAt)
		out = append(out, l)
	}
	return out, nil
}
