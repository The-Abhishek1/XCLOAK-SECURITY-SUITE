package services

import (
	"fmt"
	"time"

	"xcloak-ngfw/database"
	"xcloak-ngfw/repositories"
)

type AgentHealth struct {
	AgentID          int       `json:"agent_id"`
	Hostname         string    `json:"hostname"`
	HealthScore      int       `json:"health_score"`
	HealthStatus     string    `json:"health_status"`
	LastHeartbeat    *time.Time `json:"last_heartbeat"`
	HeartbeatGapS    int       `json:"heartbeat_gap_s"`
	TaskSuccessRate  float64   `json:"task_success_rate"`
	AlertRate1h      int       `json:"alert_rate_1h"`
	ComputedAt       time.Time `json:"computed_at"`
}

// ComputeAgentHealth calculates a 0-100 health score for every agent.
// Components:
//   - Heartbeat recency  (40 pts) — full score if <35s, degrades to 0 at 5min
//   - Task success rate  (30 pts) — % of recent tasks that completed successfully
//   - Alert rate         (20 pts) — high alert volume lowers score (noise indicator)
//   - Online status      (10 pts) — bonus for agents marked online
func ComputeAgentHealth() {

	agents, err := repositories.GetAllAgents()
	if err != nil {
		return
	}

	for _, agent := range agents {
		health := computeOne(agent.ID, agent.Hostname)
		saveHealth(health)
	}
}

func computeOne(agentID int, hostname string) AgentHealth {

	h := AgentHealth{
		AgentID:    agentID,
		Hostname:   hostname,
		ComputedAt: time.Now(),
	}

	score := 100

	// ── Heartbeat recency (40pts) ─────────────────────────────
	var lastSeen time.Time
	database.DB.QueryRow(
		`SELECT last_seen FROM agents WHERE id=$1`, agentID).Scan(&lastSeen)
	h.LastHeartbeat = &lastSeen

	gapSec := int(time.Since(lastSeen).Seconds())
	h.HeartbeatGapS = gapSec

	heartbeatScore := 40
	if gapSec > 35 {
		// Linear degradation: 0 pts at 5 min (300s)
		pct := float64(300-gapSec) / float64(300-35)
		if pct < 0 {
			pct = 0
		}
		heartbeatScore = int(40.0 * pct)
	}
	score = score - 40 + heartbeatScore

	// ── Task success rate (30pts) ─────────────────────────────
	var total, failed int
	database.DB.QueryRow(`
		SELECT COUNT(*), SUM(CASE WHEN result LIKE '%failed%' OR result LIKE '%error%' OR result LIKE '%unknown%' THEN 1 ELSE 0 END)
		FROM tasks
		WHERE agent_id=$1 AND status='completed' AND created_at > now() - INTERVAL '24 hours'
	`, agentID).Scan(&total, &failed)

	h.TaskSuccessRate = 1.0
	taskScore := 30
	if total > 0 {
		h.TaskSuccessRate = float64(total-failed) / float64(total)
		taskScore = int(30.0 * h.TaskSuccessRate)
	}
	score = score - 30 + taskScore

	// ── Alert rate last 1h (20pts) ────────────────────────────
	var alertRate int
	database.DB.QueryRow(`
		SELECT COUNT(*) FROM alerts
		WHERE agent_id=$1 AND created_at > now() - INTERVAL '1 hour'
	`, agentID).Scan(&alertRate)
	h.AlertRate1h = alertRate

	alertScore := 20
	if alertRate > 50 {
		alertScore = 0
	} else if alertRate > 20 {
		alertScore = 10
	} else if alertRate > 5 {
		alertScore = 15
	}
	score = score - 20 + alertScore

	// Clamp 0-100
	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}
	h.HealthScore = score

	// Status label
	switch {
	case score >= 80:
		h.HealthStatus = "healthy"
	case score >= 50:
		h.HealthStatus = "degraded"
	default:
		h.HealthStatus = "critical"
	}

	return h
}

func saveHealth(h AgentHealth) {
	database.DB.Exec(`
		INSERT INTO agent_health
		(agent_id, health_score, health_status, last_heartbeat,
		 heartbeat_gap_s, task_success_rate, alert_rate_1h, computed_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,now())
		ON CONFLICT (agent_id) DO UPDATE SET
			health_score      = EXCLUDED.health_score,
			health_status     = EXCLUDED.health_status,
			last_heartbeat    = EXCLUDED.last_heartbeat,
			heartbeat_gap_s   = EXCLUDED.heartbeat_gap_s,
			task_success_rate = EXCLUDED.task_success_rate,
			alert_rate_1h     = EXCLUDED.alert_rate_1h,
			computed_at       = now()
	`, h.AgentID, h.HealthScore, h.HealthStatus, h.LastHeartbeat,
		h.HeartbeatGapS, h.TaskSuccessRate, h.AlertRate1h)
}

// GetAgentHealthScores returns health scores for all agents in tenantID.
func GetAgentHealthScores(tenantID int) ([]AgentHealth, error) {
	rows, err := database.DB.Query(`
		SELECT ah.agent_id, a.hostname, ah.health_score, ah.health_status,
		       ah.last_heartbeat, ah.heartbeat_gap_s, ah.task_success_rate,
		       ah.alert_rate_1h, ah.computed_at
		FROM agent_health ah
		JOIN agents a ON a.id = ah.agent_id
		WHERE a.tenant_id = $1
		ORDER BY ah.health_score ASC
	`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []AgentHealth
	for rows.Next() {
		var h AgentHealth
		if err := rows.Scan(&h.AgentID, &h.Hostname, &h.HealthScore, &h.HealthStatus,
			&h.LastHeartbeat, &h.HeartbeatGapS, &h.TaskSuccessRate,
			&h.AlertRate1h, &h.ComputedAt); err == nil {
			results = append(results, h)
		}
	}
	return results, nil
}

// GetAgentHealthByID returns health for a single agent (computes fresh).
func GetAgentHealthByID(agentID int) AgentHealth {
	var hostname string
	database.DB.QueryRow(`SELECT hostname FROM agents WHERE id=$1`, agentID).Scan(&hostname)
	h := computeOne(agentID, hostname)
	saveHealth(h)
	return h
}

// StartHealthScheduler runs health computation every 60s in background.
func StartHealthScheduler() {
	go func() {
		// Initial computation.
		ComputeAgentHealth()
		ticker := time.NewTicker(60 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			ComputeAgentHealth()
		}
	}()
	fmt.Println("Agent health scheduler started")
}
