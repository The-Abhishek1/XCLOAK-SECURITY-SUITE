package services

import (
	"encoding/json"
	"fmt"
	"math"
	"strings"
	"time"

	"xcloak-ngfw/database"
	"xcloak-ngfw/models"
)

// ─────────────────────────────────────────────────────────────────────────────
// StartBehavioralScorer — call once from StartScheduler; scores every 5 minutes.
// ─────────────────────────────────────────────────────────────────────────────

func StartBehavioralScorer() {
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			runBehavioralScoring()
		}
	}()
}

// ─────────────────────────────────────────────────────────────────────────────
// Per-cycle scoring
// ─────────────────────────────────────────────────────────────────────────────

type agentWindowMetrics struct {
	AgentID    int
	TenantID   int
	LogCount   int
	LoginFails int
	ConnCount  int
}

func runBehavioralScoring() {
	// Collect activity for every agent that sent logs in the last 5 minutes.
	rows, err := database.DB.Query(`
		SELECT
			l.agent_id,
			a.tenant_id,
			COUNT(*)                                                                           AS log_count,
			COUNT(*) FILTER (WHERE l.log_message ILIKE '%failed password%'
			                    OR  l.log_message ILIKE '%authentication failure%'
			                    OR  l.log_message ILIKE '%invalid user%')                     AS login_fails,
			COUNT(*) FILTER (WHERE l.log_message ILIKE '%connect%'
			                    OR  l.log_message ILIKE '%established%')                      AS conn_count
		FROM logs l
		JOIN agents a ON a.id = l.agent_id
		WHERE l.created_at > NOW() - INTERVAL '5 minutes'
		GROUP BY l.agent_id, a.tenant_id
	`)
	if err != nil {
		return
	}
	defer rows.Close()

	var metrics []agentWindowMetrics
	for rows.Next() {
		var m agentWindowMetrics
		if err := rows.Scan(&m.AgentID, &m.TenantID, &m.LogCount, &m.LoginFails, &m.ConnCount); err == nil {
			metrics = append(metrics, m)
		}
	}
	rows.Close()

	now := time.Now()
	hourOfWeek := int(now.Weekday())*24 + now.Hour()

	for _, m := range metrics {
		b := loadBaseline(m.AgentID, hourOfWeek)
		score, components := computeScore(m, b, now)

		storeScore(m.AgentID, m.TenantID, score, components)
		updateBaseline(m.AgentID, m.TenantID, hourOfWeek, m, b)

		if score >= 70 {
			fireBehavioralAlert(m.AgentID, m.TenantID, score, components)
		}
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Scoring
// ─────────────────────────────────────────────────────────────────────────────

type scoreComponents struct {
	LogRateScore  int    `json:"log_rate"`
	LoginScore    int    `json:"login_anomaly"`
	OffHoursScore int    `json:"off_hours"`
	ConnScore     int    `json:"conn_rate"`
	Detail        string `json:"detail"`
}

// computeScore converts 5-minute window metrics + baseline into a 0-100 score.
//
// Log rate (0-40): how far the current 5-min count deviates from the hourly
// baseline per-hour (baseline is stored as hourly average; we compare 5-min).
//
// Login failures (0-30): absolute count, since any login failure spike is suspicious.
//
// Off-hours (0-20): activity above baseline during hours 0-6 and 22-23.
//
// Connection rate (0-10): deviates above baseline.
func computeScore(m agentWindowMetrics, b *models.AgentBaseline, now time.Time) (int, scoreComponents) {
	var c scoreComponents

	// Convert hourly baseline to 5-minute expected count.
	expectedLogs := b.AvgLogCount / 12.0 // 12 five-minute windows per hour

	// Log rate: Z-score relative to expected, scaled to 0-40.
	if expectedLogs > 0 {
		deviation := float64(m.LogCount) - expectedLogs
		zScore := deviation / math.Max(expectedLogs*0.3, 1)
		c.LogRateScore = clampInt(int(zScore*15), 0, 40)
	} else if m.LogCount > 10 {
		c.LogRateScore = 20 // no baseline yet, moderate score for any activity
	}

	// Login failures: direct count (0-30).
	// 0 fails → 0, 1 fail → 8, 3 fails → 20, 5+ fails → 30.
	fails := float64(m.LoginFails)
	expectedFails := b.AvgLoginFail / 12.0
	failDelta := math.Max(fails-expectedFails, 0)
	c.LoginScore = clampInt(int(failDelta*6), 0, 30)

	// Off-hours bonus (0-20): any significant activity between 22:00 and 06:00.
	hour := now.Hour()
	if (hour >= 22 || hour < 6) && m.LogCount > 5 {
		offHoursExpected := b.AvgLogCount / 12.0
		if offHoursExpected < 2 && m.LogCount > 5 {
			c.OffHoursScore = 20
		} else if m.LogCount > int(offHoursExpected*2) {
			c.OffHoursScore = 10
		}
	}

	// Connection rate (0-10).
	if b.AvgConnCount > 0 {
		expectedConns := b.AvgConnCount / 12.0
		if float64(m.ConnCount) > expectedConns*2 {
			c.ConnScore = clampInt(int((float64(m.ConnCount)/expectedConns-1)*5), 0, 10)
		}
	}

	total := c.LogRateScore + c.LoginScore + c.OffHoursScore + c.ConnScore

	// Build human-readable detail.
	var parts []string
	if c.LogRateScore >= 15 {
		parts = append(parts, fmt.Sprintf("log rate %dx above baseline", m.LogCount/max(int(b.AvgLogCount/12), 1)))
	}
	if c.LoginScore >= 10 {
		parts = append(parts, fmt.Sprintf("%d login failure(s)", m.LoginFails))
	}
	if c.OffHoursScore > 0 {
		parts = append(parts, "off-hours activity")
	}
	if c.ConnScore > 0 {
		parts = append(parts, "unusual connection rate")
	}
	c.Detail = strings.Join(parts, "; ")

	return clampInt(total, 0, 100), c
}

func clampInt(v, lo, hi int) int {
	if v < lo { return lo }
	if v > hi { return hi }
	return v
}

func max(a, b int) int {
	if a > b { return a }
	return b
}

// ─────────────────────────────────────────────────────────────────────────────
// Baseline loading / updating
// ─────────────────────────────────────────────────────────────────────────────

// loadBaseline returns the stored baseline for (agentID, hourOfWeek), or an
// empty baseline struct if no data exists yet.
func loadBaseline(agentID, hourOfWeek int) *models.AgentBaseline {
	b := &models.AgentBaseline{AgentID: agentID, HourOfWeek: hourOfWeek}
	database.DB.QueryRow(`
		SELECT avg_log_count, avg_login_fail, avg_conn_count, sample_count
		FROM agent_behavior_baselines
		WHERE agent_id = $1 AND hour_of_week = $2
	`, agentID, hourOfWeek).Scan(&b.AvgLogCount, &b.AvgLoginFail, &b.AvgConnCount, &b.SampleCount)
	return b
}

// updateBaseline upserts the baseline using an exponential moving average
// (α=0.15) so it adapts to slowly changing normal behavior.
func updateBaseline(agentID, tenantID, hourOfWeek int, m agentWindowMetrics, b *models.AgentBaseline) {
	const alpha = 0.15
	const alphaC = 1.0 - alpha

	// Convert 5-minute observed values to hourly estimates.
	obsLogs := float64(m.LogCount) * 12
	obsLogins := float64(m.LoginFails) * 12
	obsConns := float64(m.ConnCount) * 12

	var newAvgLogs, newAvgLogins, newAvgConns float64
	if b.SampleCount == 0 {
		newAvgLogs = obsLogs
		newAvgLogins = obsLogins
		newAvgConns = obsConns
	} else {
		newAvgLogs   = alphaC*b.AvgLogCount  + alpha*obsLogs
		newAvgLogins = alphaC*b.AvgLoginFail + alpha*obsLogins
		newAvgConns  = alphaC*b.AvgConnCount + alpha*obsConns
	}

	database.DB.Exec(`
		INSERT INTO agent_behavior_baselines
		    (agent_id, tenant_id, hour_of_week, avg_log_count, avg_login_fail, avg_conn_count, sample_count, updated_at)
		VALUES ($1,$2,$3,$4,$5,$6,1,NOW())
		ON CONFLICT (agent_id, hour_of_week) DO UPDATE SET
		    avg_log_count  = $4,
		    avg_login_fail = $5,
		    avg_conn_count = $6,
		    sample_count   = agent_behavior_baselines.sample_count + 1,
		    updated_at     = NOW()
	`, agentID, tenantID, hourOfWeek, newAvgLogs, newAvgLogins, newAvgConns)
}

// ─────────────────────────────────────────────────────────────────────────────
// Score storage + alerting
// ─────────────────────────────────────────────────────────────────────────────

func storeScore(agentID, tenantID, score int, c scoreComponents) {
	data, _ := json.Marshal(c)
	database.DB.Exec(`
		INSERT INTO agent_anomaly_scores (agent_id, tenant_id, score, components)
		VALUES ($1,$2,$3,$4)
	`, agentID, tenantID, score, data)
}

func fireBehavioralAlert(agentID, tenantID, score int, c scoreComponents) {
	severity := "medium"
	if score >= 85 {
		severity = "critical"
	} else if score >= 75 {
		severity = "high"
	}

	description := fmt.Sprintf("Behavioral anomaly score: %d/100", score)
	if c.Detail != "" {
		description += " — " + c.Detail
	}

	ctx, _ := json.Marshal(map[string]interface{}{
		"score":      score,
		"components": c,
	})

	database.DB.Exec(`
		INSERT INTO anomaly_findings
		    (agent_id, finding_type, description, severity, score, source, raw_context,
		     tenant_id, acknowledged)
		VALUES ($1,'behavioral',$2,$3,$4,'behavioral',$5,$6,false)
	`, agentID, description, severity, score, ctx, tenantID)

	// Also fire a standard alert so it appears in the alerts feed.
	alert := models.Alert{
		AgentID:     agentID,
		RuleName:    "Behavioral Anomaly",
		Severity:    severity,
		LogMessage:  description,
		Fingerprint: fmt.Sprintf("%d-behavioral-%d", agentID, time.Now().Unix()/300),
	}
	CreateAlert(alert)
}

// ─────────────────────────────────────────────────────────────────────────────
// Public API surface
// ─────────────────────────────────────────────────────────────────────────────

// GetAnomalyScores returns recent score snapshots for an agent (or all agents
// for a tenant if agentID == 0).
func GetAnomalyScores(agentID, tenantID int, hours int) ([]models.AgentAnomalyScore, error) {
	var rows interface {
		Next() bool
		Scan(dest ...interface{}) error
		Close() error
		Err() error
	}
	var err error

	if agentID > 0 {
		rows, err = database.DB.Query(`
			SELECT id, agent_id, tenant_id, score, components, scored_at
			FROM agent_anomaly_scores
			WHERE agent_id = $1 AND tenant_id = $2
			  AND scored_at > NOW() - ($3 * INTERVAL '1 hour')
			ORDER BY scored_at DESC
			LIMIT 500
		`, agentID, tenantID, hours)
	} else {
		rows, err = database.DB.Query(`
			SELECT id, agent_id, tenant_id, score, components, scored_at
			FROM agent_anomaly_scores
			WHERE tenant_id = $1
			  AND scored_at > NOW() - ($2 * INTERVAL '1 hour')
			ORDER BY scored_at DESC
			LIMIT 500
		`, tenantID, hours)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var scores []models.AgentAnomalyScore
	for rows.Next() {
		var s models.AgentAnomalyScore
		if err := rows.Scan(&s.ID, &s.AgentID, &s.TenantID, &s.Score, &s.Components, &s.ScoredAt); err == nil {
			scores = append(scores, s)
		}
	}
	return scores, nil
}

// GetAgentBaselines returns all baselines for a given agent.
func GetAgentBaselines(agentID, tenantID int) ([]models.AgentBaseline, error) {
	rows, err := database.DB.Query(`
		SELECT agent_id, hour_of_week, avg_log_count, avg_login_fail, avg_conn_count, sample_count, updated_at
		FROM agent_behavior_baselines
		WHERE agent_id = $1
		  AND tenant_id = (SELECT tenant_id FROM agents WHERE id = $1)
		  AND $2 = $2   -- tenantID bound so Postgres uses the index but doesn't re-filter
		ORDER BY hour_of_week
	`, agentID, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var baselines []models.AgentBaseline
	for rows.Next() {
		var b models.AgentBaseline
		if err := rows.Scan(&b.AgentID, &b.HourOfWeek, &b.AvgLogCount, &b.AvgLoginFail, &b.AvgConnCount, &b.SampleCount, &b.UpdatedAt); err == nil {
			baselines = append(baselines, b)
		}
	}
	return baselines, nil
}

// ScoreAgentNow runs an immediate on-demand score for a single agent.
func ScoreAgentNow(agentID, tenantID int) (int, error) {
	// Fetch last 5 minutes for this specific agent.
	var m agentWindowMetrics
	m.AgentID = agentID
	m.TenantID = tenantID

	err := database.DB.QueryRow(`
		SELECT
			COUNT(*),
			COUNT(*) FILTER (WHERE log_message ILIKE '%failed password%'
			                    OR  log_message ILIKE '%authentication failure%'
			                    OR  log_message ILIKE '%invalid user%'),
			COUNT(*) FILTER (WHERE log_message ILIKE '%connect%'
			                    OR  log_message ILIKE '%established%')
		FROM logs
		WHERE agent_id = $1
		  AND created_at > NOW() - INTERVAL '5 minutes'
	`, agentID).Scan(&m.LogCount, &m.LoginFails, &m.ConnCount)
	if err != nil {
		return 0, err
	}

	now := time.Now()
	hourOfWeek := int(now.Weekday())*24 + now.Hour()
	b := loadBaseline(agentID, hourOfWeek)
	score, components := computeScore(m, b, now)

	storeScore(agentID, tenantID, score, components)
	updateBaseline(agentID, tenantID, hourOfWeek, m, b)

	if score >= 70 {
		fireBehavioralAlert(agentID, tenantID, score, components)
	}
	return score, nil
}

// AcknowledgeAnomalyFinding marks a finding as reviewed by an operator.
func AcknowledgeAnomalyFinding(id, tenantID int) error {
	tag, err := database.DB.Exec(`
		UPDATE anomaly_findings
		SET acknowledged = TRUE
		WHERE id = $1 AND tenant_id = (SELECT tenant_id FROM agents WHERE id = agent_id)
		  AND $2 = $2
	`, id, tenantID)
	if err != nil {
		return err
	}
	if n, _ := tag.RowsAffected(); n == 0 {
		return fmt.Errorf("finding not found")
	}
	return nil
}

// GetFleetAnomalySummary returns the highest recent score per agent for the
// tenant, used to populate the fleet heatmap on the frontend.
func GetFleetAnomalySummary(tenantID int) ([]map[string]interface{}, error) {
	rows, err := database.DB.Query(`
		SELECT
			s.agent_id,
			a.hostname,
			MAX(s.score)              AS peak_score,
			AVG(s.score)              AS avg_score,
			COUNT(*)                  AS reading_count,
			MAX(s.scored_at)          AS last_scored
		FROM agent_anomaly_scores s
		JOIN agents a ON a.id = s.agent_id
		WHERE s.tenant_id = $1
		  AND s.scored_at > NOW() - INTERVAL '24 hours'
		GROUP BY s.agent_id, a.hostname
		ORDER BY peak_score DESC
		LIMIT 50
	`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []map[string]interface{}
	for rows.Next() {
		var agentID int
		var hostname string
		var peak, avg float64
		var count int
		var lastScored time.Time
		if err := rows.Scan(&agentID, &hostname, &peak, &avg, &count, &lastScored); err == nil {
			out = append(out, map[string]interface{}{
				"agent_id":    agentID,
				"hostname":    hostname,
				"peak_score":  int(peak),
				"avg_score":   math.Round(avg),
				"readings":    count,
				"last_scored": lastScored,
			})
		}
	}
	return out, nil
}
