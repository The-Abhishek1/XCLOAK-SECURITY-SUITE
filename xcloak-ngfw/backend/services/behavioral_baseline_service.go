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
	ProcCount  int // distinct process-create / execve events in the window
	PrivEsc    int // sudo/su/privilege-escalation events
}

func runBehavioralScoring() {
	rows, err := database.DB.Query(`
		SELECT
			l.agent_id,
			a.tenant_id,
			COUNT(*)                                                                    AS log_count,
			COUNT(*) FILTER (WHERE l.log_message ILIKE '%failed password%'
			                    OR  l.log_message ILIKE '%authentication failure%'
			                    OR  l.log_message ILIKE '%invalid user%')               AS login_fails,
			COUNT(*) FILTER (WHERE l.log_message ILIKE '%connect%'
			                    OR  l.log_message ILIKE '%established%')                AS conn_count,
			COUNT(*) FILTER (WHERE l.parsed_fields->>'event_type' = 'process_create'
			                    OR  l.log_message ILIKE '%execve%'
			                    OR  l.log_message ILIKE '%process start%'
			                    OR  (l.parsed_fields->>'event_id') = '4688')            AS proc_count,
			COUNT(*) FILTER (WHERE l.log_message ILIKE '%sudo:%'
			                    OR  l.log_message ILIKE '%: su:%'
			                    OR  l.log_message ILIKE '%privilege%'
			                    OR  (l.parsed_fields->>'event_id') IN
			                        ('4672','4673','4674','4697','7045'))               AS priv_esc
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
		if err := rows.Scan(&m.AgentID, &m.TenantID,
			&m.LogCount, &m.LoginFails, &m.ConnCount,
			&m.ProcCount, &m.PrivEsc); err == nil {
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
// EWMA variance helpers
// ─────────────────────────────────────────────────────────────────────────────

const ewmaAlpha = 0.15

// ewmaUpdate advances the EWMA mean and variance by one observation using the
// Welford-EWMA formula. This keeps variance adaptive at the same rate as the
// mean, so quieter agents get tighter thresholds and noisier ones looser ones.
func ewmaUpdate(mean, variance, obs float64) (newMean, newVariance float64) {
	diff := obs - mean
	newMean = mean + ewmaAlpha*diff
	newVariance = (1-ewmaAlpha) * (variance + ewmaAlpha*diff*diff)
	return
}

// metricZScore computes a z-score for one observed value against its baseline.
// The minimum sigma is set to max(10% of mean, 1) to avoid explosive scores
// when a normally silent metric receives its first non-zero reading.
func metricZScore(obs, mean, variance float64) float64 {
	sigma := math.Sqrt(variance)
	minSigma := math.Max(math.Abs(mean)*0.10, 1.0)
	if sigma < minSigma {
		sigma = minSigma
	}
	return (obs - mean) / sigma
}

// ─────────────────────────────────────────────────────────────────────────────
// Scoring
// ─────────────────────────────────────────────────────────────────────────────

type scoreComponents struct {
	LogRateScore  int    `json:"log_rate"`
	LoginScore    int    `json:"login_anomaly"`
	ConnScore     int    `json:"conn_rate"`
	ProcScore     int    `json:"proc_rate"`
	PrivEscScore  int    `json:"priv_esc"`
	OffHoursScore int    `json:"off_hours"`
	Detail        string `json:"detail"`
}

// computeScore converts 5-minute window metrics + baseline into a 0–100 risk
// score. All metric components now use true EWMA z-scores, so the thresholds
// automatically tighten for quiet agents and loosen for chatty ones.
//
// Budget:
//
//	Log rate          (0-35): z > 2 → significant; z > 4 → saturates
//	Login failures    (0-25): z > 1 + raw-count floor
//	Connection rate   (0-15): z > 2 → significant
//	Process spawns    (0-10): z > 2 → significant
//	Privilege escalation (0-10): 4 pts per event above baseline, raw floor of 2 pts/event
//	Off-hours bonus   (0-5):  any above-baseline activity during 22:00–06:00
func computeScore(m agentWindowMetrics, b *models.AgentBaseline, now time.Time) (int, scoreComponents) {
	var c scoreComponents

	// Convert 5-min observed values to hourly scale for comparison with the
	// hourly baseline means.
	obsLogs := float64(m.LogCount) * 12
	obsLogins := float64(m.LoginFails) * 12
	obsConns := float64(m.ConnCount) * 12
	obsProcs := float64(m.ProcCount) * 12
	obsPriv := float64(m.PrivEsc) * 12

	// Log rate (0-35)
	if b.SampleCount > 0 {
		z := metricZScore(obsLogs, b.AvgLogCount, b.VarLogCount)
		if z > 1 {
			c.LogRateScore = clampInt(int(z*8), 0, 35)
		}
	} else if m.LogCount > 10 {
		c.LogRateScore = 15 // no baseline yet — moderate score for any activity
	}

	// Login failures (0-25): z-score plus an absolute floor so even 1 extra
	// failure above baseline registers on a normally clean agent.
	if b.SampleCount > 0 {
		z := metricZScore(obsLogins, b.AvgLoginFail, b.VarLoginFail)
		if z > 0.5 {
			c.LoginScore = clampInt(int(z*8)+m.LoginFails*2, 0, 25)
		}
	} else {
		c.LoginScore = clampInt(m.LoginFails*4, 0, 25)
	}

	// Connection rate (0-15)
	if b.SampleCount > 0 {
		z := metricZScore(obsConns, b.AvgConnCount, b.VarConnCount)
		if z > 2 {
			c.ConnScore = clampInt(int((z-2)*5), 0, 15)
		}
	}

	// Process spawn rate (0-10)
	if b.SampleCount > 0 {
		z := metricZScore(obsProcs, b.AvgProcCount, b.VarProcCount)
		if z > 2 {
			c.ProcScore = clampInt(int((z-2)*4), 0, 10)
		}
	}

	// Privilege escalation (0-10): each event above baseline adds 4 pts;
	// any event at all adds at least 2 pts (even if within baseline).
	if m.PrivEsc > 0 {
		if b.SampleCount > 0 {
			z := metricZScore(obsPriv, b.AvgPrivEsc, b.VarPrivEsc)
			c.PrivEscScore = clampInt(int(z*4)+m.PrivEsc*2, 0, 10)
		} else {
			c.PrivEscScore = clampInt(m.PrivEsc*3, 0, 10)
		}
	}

	// Off-hours bonus (0-5): significant activity between 22:00 and 06:00.
	hour := now.Hour()
	if (hour >= 22 || hour < 6) && m.LogCount > 5 {
		expected := b.AvgLogCount / 12.0
		if expected < 2 || float64(m.LogCount) > expected*2 {
			c.OffHoursScore = 5
		}
	}

	total := c.LogRateScore + c.LoginScore + c.ConnScore +
		c.ProcScore + c.PrivEscScore + c.OffHoursScore

	// Build human-readable detail string.
	var parts []string
	if c.LogRateScore >= 15 {
		parts = append(parts, fmt.Sprintf("log rate spike (%d events/5 min)", m.LogCount))
	}
	if c.LoginScore >= 8 {
		parts = append(parts, fmt.Sprintf("%d login failure(s)", m.LoginFails))
	}
	if c.ConnScore >= 5 {
		parts = append(parts, "connection rate above baseline")
	}
	if c.ProcScore >= 4 {
		parts = append(parts, fmt.Sprintf("process spawn spike (%d procs/5 min)", m.ProcCount))
	}
	if c.PrivEscScore > 0 {
		parts = append(parts, fmt.Sprintf("%d privilege escalation event(s)", m.PrivEsc))
	}
	if c.OffHoursScore > 0 {
		parts = append(parts, "off-hours activity")
	}
	c.Detail = strings.Join(parts, "; ")

	return clampInt(total, 0, 100), c
}

func clampInt(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

// ─────────────────────────────────────────────────────────────────────────────
// Baseline loading / updating
// ─────────────────────────────────────────────────────────────────────────────

func loadBaseline(agentID, hourOfWeek int) *models.AgentBaseline {
	b := &models.AgentBaseline{AgentID: agentID, HourOfWeek: hourOfWeek}
	database.DB.QueryRow(`
		SELECT avg_log_count,  var_log_count,
		       avg_login_fail, var_login_fail,
		       avg_conn_count, var_conn_count,
		       avg_proc_count, var_proc_count,
		       avg_priv_esc,   var_priv_esc,
		       sample_count
		FROM agent_behavior_baselines
		WHERE agent_id = $1 AND hour_of_week = $2
	`, agentID, hourOfWeek).Scan(
		&b.AvgLogCount, &b.VarLogCount,
		&b.AvgLoginFail, &b.VarLoginFail,
		&b.AvgConnCount, &b.VarConnCount,
		&b.AvgProcCount, &b.VarProcCount,
		&b.AvgPrivEsc, &b.VarPrivEsc,
		&b.SampleCount,
	)
	return b
}

// updateBaseline upserts the baseline using EWMA (α=0.15) for both mean and
// variance, so the baseline adapts to slowly changing normal behaviour while
// giving accurate z-scores that reflect each agent's individual noise level.
func updateBaseline(agentID, tenantID, hourOfWeek int, m agentWindowMetrics, b *models.AgentBaseline) {
	// Convert 5-min observed values to hourly scale.
	obsLogs := float64(m.LogCount) * 12
	obsLogins := float64(m.LoginFails) * 12
	obsConns := float64(m.ConnCount) * 12
	obsProcs := float64(m.ProcCount) * 12
	obsPriv := float64(m.PrivEsc) * 12

	var (
		newAvgLogs, newVarLogs     float64
		newAvgLogins, newVarLogins float64
		newAvgConns, newVarConns   float64
		newAvgProcs, newVarProcs   float64
		newAvgPriv, newVarPriv     float64
	)

	if b.SampleCount == 0 {
		// First observation — seed mean from data, variance starts at 0.
		newAvgLogs, newVarLogs = obsLogs, 0
		newAvgLogins, newVarLogins = obsLogins, 0
		newAvgConns, newVarConns = obsConns, 0
		newAvgProcs, newVarProcs = obsProcs, 0
		newAvgPriv, newVarPriv = obsPriv, 0
	} else {
		newAvgLogs, newVarLogs = ewmaUpdate(b.AvgLogCount, b.VarLogCount, obsLogs)
		newAvgLogins, newVarLogins = ewmaUpdate(b.AvgLoginFail, b.VarLoginFail, obsLogins)
		newAvgConns, newVarConns = ewmaUpdate(b.AvgConnCount, b.VarConnCount, obsConns)
		newAvgProcs, newVarProcs = ewmaUpdate(b.AvgProcCount, b.VarProcCount, obsProcs)
		newAvgPriv, newVarPriv = ewmaUpdate(b.AvgPrivEsc, b.VarPrivEsc, obsPriv)
	}

	database.DB.Exec(`
		INSERT INTO agent_behavior_baselines
		    (agent_id, tenant_id, hour_of_week,
		     avg_log_count,  var_log_count,
		     avg_login_fail, var_login_fail,
		     avg_conn_count, var_conn_count,
		     avg_proc_count, var_proc_count,
		     avg_priv_esc,   var_priv_esc,
		     sample_count, updated_at)
		VALUES ($1,$2,$3, $4,$5, $6,$7, $8,$9, $10,$11, $12,$13, 1, NOW())
		ON CONFLICT (agent_id, hour_of_week) DO UPDATE SET
		    avg_log_count  = $4,  var_log_count  = $5,
		    avg_login_fail = $6,  var_login_fail = $7,
		    avg_conn_count = $8,  var_conn_count = $9,
		    avg_proc_count = $10, var_proc_count = $11,
		    avg_priv_esc   = $12, var_priv_esc   = $13,
		    sample_count   = agent_behavior_baselines.sample_count + 1,
		    updated_at     = NOW()
	`, agentID, tenantID, hourOfWeek,
		newAvgLogs, newVarLogs,
		newAvgLogins, newVarLogins,
		newAvgConns, newVarConns,
		newAvgProcs, newVarProcs,
		newAvgPriv, newVarPriv,
	)
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

func GetAnomalyScores(agentID, tenantID int, hours int) ([]models.AgentAnomalyScore, error) {
	var (
		rows interface {
			Next() bool
			Scan(dest ...interface{}) error
			Close() error
			Err() error
		}
		err error
	)

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

func GetAgentBaselines(agentID, tenantID int) ([]models.AgentBaseline, error) {
	rows, err := database.DB.Query(`
		SELECT agent_id, hour_of_week,
		       avg_log_count,  var_log_count,
		       avg_login_fail, var_login_fail,
		       avg_conn_count, var_conn_count,
		       avg_proc_count, var_proc_count,
		       avg_priv_esc,   var_priv_esc,
		       sample_count, updated_at
		FROM agent_behavior_baselines
		WHERE agent_id = $1
		  AND tenant_id = (SELECT tenant_id FROM agents WHERE id = $1)
		  AND $2 = $2
		ORDER BY hour_of_week
	`, agentID, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var baselines []models.AgentBaseline
	for rows.Next() {
		var b models.AgentBaseline
		if err := rows.Scan(
			&b.AgentID, &b.HourOfWeek,
			&b.AvgLogCount, &b.VarLogCount,
			&b.AvgLoginFail, &b.VarLoginFail,
			&b.AvgConnCount, &b.VarConnCount,
			&b.AvgProcCount, &b.VarProcCount,
			&b.AvgPrivEsc, &b.VarPrivEsc,
			&b.SampleCount, &b.UpdatedAt,
		); err == nil {
			baselines = append(baselines, b)
		}
	}
	return baselines, nil
}

func ScoreAgentNow(agentID, tenantID int) (int, error) {
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
			                    OR  log_message ILIKE '%established%'),
			COUNT(*) FILTER (WHERE parsed_fields->>'event_type' = 'process_create'
			                    OR  log_message ILIKE '%execve%'
			                    OR  log_message ILIKE '%process start%'
			                    OR  (parsed_fields->>'event_id') = '4688'),
			COUNT(*) FILTER (WHERE log_message ILIKE '%sudo:%'
			                    OR  log_message ILIKE '%: su:%'
			                    OR  log_message ILIKE '%privilege%'
			                    OR  (parsed_fields->>'event_id') IN ('4672','4673','4674','4697','7045'))
		FROM logs
		WHERE agent_id = $1
		  AND created_at > NOW() - INTERVAL '5 minutes'
	`, agentID).Scan(&m.LogCount, &m.LoginFails, &m.ConnCount, &m.ProcCount, &m.PrivEsc)
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

func GetFleetAnomalySummary(tenantID int) ([]map[string]interface{}, error) {
	rows, err := database.DB.Query(`
		SELECT
			s.agent_id,
			a.hostname,
			MAX(s.score)     AS peak_score,
			AVG(s.score)     AS avg_score,
			COUNT(*)         AS reading_count,
			MAX(s.scored_at) AS last_scored
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
