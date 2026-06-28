package services

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"xcloak-ngfw/database"
	"xcloak-ngfw/models"
)

func GenerateCanaryToken(tenantID int, tokenType, name, description, deployedTo, createdBy string) (models.CanaryToken, error) {
	raw := make([]byte, 24)
	rand.Read(raw)
	tokenValue := fmt.Sprintf("xck-canary-%s-%s", tokenType[:3], hex.EncodeToString(raw))

	var tok models.CanaryToken
	err := database.DB.QueryRow(`
		INSERT INTO canary_tokens (tenant_id, token_type, name, token_value, description, deployed_to, created_by)
		VALUES ($1,$2,$3,$4,$5,$6,$7)
		RETURNING id, tenant_id, token_type, name, token_value, description, deployed_to,
		          created_by, alert_on_trip, is_active, trip_count, last_tripped_at, created_at`,
		tenantID, tokenType, name, tokenValue, description, deployedTo, createdBy,
	).Scan(&tok.ID, &tok.TenantID, &tok.TokenType, &tok.Name, &tok.TokenValue,
		&tok.Description, &tok.DeployedTo, &tok.CreatedBy, &tok.AlertOnTrip,
		&tok.IsActive, &tok.TripCount, &tok.LastTrippedAt, &tok.CreatedAt)
	return tok, err
}

func GetCanaryTokens(tenantID int) ([]models.CanaryToken, error) {
	rows, err := database.DB.Query(`
		SELECT id, tenant_id, token_type, name, token_value, description, deployed_to,
		       created_by, alert_on_trip, is_active, trip_count, last_tripped_at, created_at
		FROM canary_tokens WHERE tenant_id=$1 ORDER BY created_at DESC`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.CanaryToken
	for rows.Next() {
		var t models.CanaryToken
		rows.Scan(&t.ID, &t.TenantID, &t.TokenType, &t.Name, &t.TokenValue,
			&t.Description, &t.DeployedTo, &t.CreatedBy, &t.AlertOnTrip,
			&t.IsActive, &t.TripCount, &t.LastTrippedAt, &t.CreatedAt)
		out = append(out, t)
	}
	return out, nil
}

func DeleteCanaryToken(id, tenantID int) error {
	_, err := database.DB.Exec(`DELETE FROM canary_tokens WHERE id=$1 AND tenant_id=$2`, id, tenantID)
	return err
}

func ToggleCanaryToken(id, tenantID int, active bool) error {
	_, err := database.DB.Exec(`UPDATE canary_tokens SET is_active=$1 WHERE id=$2 AND tenant_id=$3`, active, id, tenantID)
	return err
}

// TripCanaryToken records a trip event and optionally fires an alert.
func TripCanaryToken(tokenValue, sourceIP, userAgent, method string, extraData map[string]any) error {
	var tokID, tenantID int
	var name, tokenType string
	var alertOnTrip, isActive bool
	err := database.DB.QueryRow(`
		SELECT id, tenant_id, name, token_type, alert_on_trip, is_active
		FROM canary_tokens WHERE token_value=$1`, tokenValue,
	).Scan(&tokID, &tenantID, &name, &tokenType, &alertOnTrip, &isActive)
	if err != nil {
		return fmt.Errorf("unknown canary token")
	}
	if !isActive {
		return nil
	}

	extra, _ := json.Marshal(extraData)
	database.DB.Exec(`
		INSERT INTO canary_trips (token_id, tenant_id, source_ip, user_agent, method, extra_data)
		VALUES ($1,$2,$3,$4,$5,$6)`, tokID, tenantID, sourceIP, userAgent, method, string(extra))

	database.DB.Exec(`
		UPDATE canary_tokens SET trip_count=trip_count+1, last_tripped_at=NOW()
		WHERE id=$1`, tokID)

	if alertOnTrip {
		logMsg := fmt.Sprintf("CANARY TOKEN TRIPPED: %s (%s) accessed from %s method=%s", name, tokenType, sourceIP, method)
		var agentID int
		database.DB.QueryRow(`SELECT id FROM agents WHERE tenant_id=$1 AND status='online' LIMIT 1`, tenantID).Scan(&agentID)
		database.DB.Exec(`
			INSERT INTO alerts (tenant_id, agent_id, rule_name, severity, status, log_message,
			                    mitre_tactic, mitre_technique, fingerprint)
			VALUES ($1,$2,'Canary Token Tripped','critical','open',$3,'defense_evasion','T1078',
			        md5($3||$4))`,
			tenantID, agentID, logMsg, time.Now().String())
		log.Printf("[Deception] Canary tripped: %s tenant=%d from=%s", name, tenantID, sourceIP)
	}
	return nil
}

func GetCanaryTrips(tenantID, tokenID, limit int) ([]models.CanaryTrip, error) {
	query := `SELECT ct.id, ct.token_id, ct.tenant_id, ct.source_ip, ct.user_agent,
	                 ct.method, ct.extra_data::text, ct.tripped_at
	          FROM canary_trips ct
	          WHERE ct.tenant_id=$1`
	args := []any{tenantID}
	if tokenID > 0 {
		query += ` AND ct.token_id=$2 ORDER BY ct.tripped_at DESC LIMIT $3`
		args = append(args, tokenID, limit)
	} else {
		query += ` ORDER BY ct.tripped_at DESC LIMIT $2`
		args = append(args, limit)
	}
	rows, err := database.DB.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.CanaryTrip
	for rows.Next() {
		var t models.CanaryTrip
		var extraStr string
		rows.Scan(&t.ID, &t.TokenID, &t.TenantID, &t.SourceIP, &t.UserAgent,
			&t.Method, &extraStr, &t.TrippedAt)
		json.Unmarshal([]byte(extraStr), &t.ExtraData)
		out = append(out, t)
	}
	return out, nil
}

func GetHoneyports(tenantID int) ([]models.Honeyport, error) {
	rows, err := database.DB.Query(`
		SELECT h.id, h.tenant_id, h.agent_id, h.port, h.protocol, h.description,
		       h.alert_severity, h.is_active, h.created_at, COALESCE(a.hostname,'')
		FROM honeyports h
		LEFT JOIN agents a ON a.id=h.agent_id
		WHERE h.tenant_id=$1 ORDER BY h.created_at DESC`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.Honeyport
	for rows.Next() {
		var h models.Honeyport
		rows.Scan(&h.ID, &h.TenantID, &h.AgentID, &h.Port, &h.Protocol,
			&h.Description, &h.AlertSeverity, &h.IsActive, &h.CreatedAt, &h.Hostname)
		out = append(out, h)
	}
	return out, nil
}

func CreateHoneyport(tenantID, agentID, port int, protocol, description, severity string) (models.Honeyport, error) {
	var h models.Honeyport
	err := database.DB.QueryRow(`
		INSERT INTO honeyports (tenant_id, agent_id, port, protocol, description, alert_severity)
		VALUES ($1,$2,$3,$4,$5,$6)
		RETURNING id, tenant_id, agent_id, port, protocol, description, alert_severity, is_active, created_at`,
		tenantID, agentID, port, protocol, description, severity,
	).Scan(&h.ID, &h.TenantID, &h.AgentID, &h.Port, &h.Protocol,
		&h.Description, &h.AlertSeverity, &h.IsActive, &h.CreatedAt)
	return h, err
}

func DeleteHoneyport(id, tenantID int) error {
	_, err := database.DB.Exec(`DELETE FROM honeyports WHERE id=$1 AND tenant_id=$2`, id, tenantID)
	return err
}

// CheckHoneyportTrip is called by the agent connect-event pipeline.
// If destination port matches a honeyport for that agent's tenant, fire an alert.
func CheckHoneyportTrip(agentID, tenantID, dstPort int, srcIP, dstIP string) {
	var hID int
	var severity, description string
	err := database.DB.QueryRow(`
		SELECT id, alert_severity, description FROM honeyports
		WHERE agent_id=$1 AND port=$2 AND is_active=true`, agentID, dstPort,
	).Scan(&hID, &severity, &description)
	if err != nil {
		return
	}
	logMsg := fmt.Sprintf("HONEYPORT SCAN DETECTED: port %d contacted from %s on agent #%d. %s",
		dstPort, srcIP, agentID, description)
	database.DB.Exec(`
		INSERT INTO alerts (tenant_id, agent_id, rule_name, severity, status, log_message,
		                    mitre_tactic, mitre_technique, fingerprint)
		VALUES ($1,$2,'Honeyport Contacted',$3,'open',$4,'discovery','T1046',
		        md5($4||$5))
		ON CONFLICT DO NOTHING`,
		tenantID, agentID, severity, logMsg, time.Now().Format("2006-01-02T15"))
}
