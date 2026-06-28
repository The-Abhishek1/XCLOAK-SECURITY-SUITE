package services

import (
	"time"

	"xcloak-ngfw/database"
	"xcloak-ngfw/models"
)

type AnalystMetrics struct {
	Username         string        `json:"username"`
	Triaged          int           `json:"triaged"`
	Resolved         int           `json:"resolved"`
	AvgTriageMinutes float64       `json:"avg_triage_minutes"`
	OpenBacklog      int           `json:"open_backlog"`
	LastActive       *time.Time    `json:"last_active"`
}

type SOCMetrics struct {
	Analysts       []AnalystMetrics `json:"analysts"`
	TotalOpen      int              `json:"total_open"`
	TotalAcked     int              `json:"total_acked"`
	TotalResolved  int              `json:"total_resolved"`
	AvgMTTR        float64          `json:"avg_mttr_minutes"`
	BacklogTrend   []models.DailyCount `json:"backlog_trend"`
	AlertsByDay    []models.DailyCount `json:"alerts_by_day"`
}

// GetSOCMetrics builds analyst performance metrics from the alerts table.
func GetSOCMetrics(tenantID int) (SOCMetrics, error) {
	var m SOCMetrics

	// Per-analyst metrics from acknowledged alerts
	rows, err := database.DB.Query(`
		SELECT
			acknowledged_by,
			COUNT(*) FILTER (WHERE status != 'open') as triaged,
			COUNT(*) FILTER (WHERE status = 'resolved') as resolved,
			AVG(EXTRACT(EPOCH FROM (acknowledged_at - created_at))/60)
				FILTER (WHERE acknowledged_at IS NOT NULL) as avg_triage_mins,
			MAX(acknowledged_at) as last_active
		FROM alerts
		WHERE tenant_id=$1
		  AND acknowledged_by IS NOT NULL
		  AND acknowledged_by != ''
		GROUP BY acknowledged_by
		ORDER BY triaged DESC`, tenantID)
	if err != nil {
		return m, err
	}
	defer rows.Close()

	for rows.Next() {
		var a AnalystMetrics
		var avgMins *float64
		var lastActive *time.Time
		rows.Scan(&a.Username, &a.Triaged, &a.Resolved, &avgMins, &lastActive)
		if avgMins != nil {
			a.AvgTriageMinutes = *avgMins
		}
		a.LastActive = lastActive
		m.Analysts = append(m.Analysts, a)
	}

	// Per-analyst open backlog
	backlog, err := database.DB.Query(`
		SELECT acknowledged_by, COUNT(*) FROM alerts
		WHERE tenant_id=$1 AND status='open' AND acknowledged_by IS NOT NULL AND acknowledged_by != ''
		GROUP BY acknowledged_by`, tenantID)
	if err == nil {
		defer backlog.Close()
		bl := map[string]int{}
		for backlog.Next() {
			var u string
			var n int
			backlog.Scan(&u, &n)
			bl[u] = n
		}
		for i := range m.Analysts {
			m.Analysts[i].OpenBacklog = bl[m.Analysts[i].Username]
		}
	}

	// Totals
	database.DB.QueryRow(`SELECT COUNT(*) FROM alerts WHERE tenant_id=$1 AND status='open'`, tenantID).Scan(&m.TotalOpen)
	database.DB.QueryRow(`SELECT COUNT(*) FROM alerts WHERE tenant_id=$1 AND status IN ('acknowledged','resolved')`, tenantID).Scan(&m.TotalAcked)
	database.DB.QueryRow(`SELECT COUNT(*) FROM alerts WHERE tenant_id=$1 AND status='resolved'`, tenantID).Scan(&m.TotalResolved)
	database.DB.QueryRow(`
		SELECT COALESCE(AVG(EXTRACT(EPOCH FROM (acknowledged_at - created_at))/60), 0)
		FROM alerts WHERE tenant_id=$1 AND acknowledged_at IS NOT NULL`, tenantID).Scan(&m.AvgMTTR)

	// Daily alert volume (last 14 days)
	alertRows, err := database.DB.Query(`
		SELECT DATE(created_at) as day, COUNT(*)
		FROM alerts WHERE tenant_id=$1 AND created_at > NOW() - INTERVAL '14 days'
		GROUP BY day ORDER BY day`, tenantID)
	if err == nil {
		defer alertRows.Close()
		for alertRows.Next() {
			var d models.DailyCount
			var day time.Time
			alertRows.Scan(&day, &d.Count)
			d.Date = day.Format("01/02")
			m.AlertsByDay = append(m.AlertsByDay, d)
		}
	}

	// Backlog trend by day (open alerts created each day that haven't been resolved)
	backlogRows, err := database.DB.Query(`
		SELECT DATE(created_at) as day, COUNT(*)
		FROM alerts WHERE tenant_id=$1 AND status='open' AND created_at > NOW() - INTERVAL '14 days'
		GROUP BY day ORDER BY day`, tenantID)
	if err == nil {
		defer backlogRows.Close()
		for backlogRows.Next() {
			var d models.DailyCount
			var day time.Time
			backlogRows.Scan(&day, &d.Count)
			d.Date = day.Format("01/02")
			m.BacklogTrend = append(m.BacklogTrend, d)
		}
	}

	return m, nil
}
