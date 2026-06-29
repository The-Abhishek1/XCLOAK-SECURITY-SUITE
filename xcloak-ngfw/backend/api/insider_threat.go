package api

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"

	"xcloak-ngfw/database"
)

// GetInsiderThreatScores returns the last N days of insider threat scores
// for the authenticated tenant, ordered by score desc.
func GetInsiderThreatScores(c *gin.Context) {
	tenantID := tenantIDFromContext(c)

	days := 7
	if d, err := strconv.Atoi(c.DefaultQuery("days", "7")); err == nil && d >= 1 && d <= 90 {
		days = d
	}
	minScore := 0
	if s, err := strconv.Atoi(c.DefaultQuery("min_score", "0")); err == nil {
		minScore = s
	}

	rows, err := database.DB.Query(`
		SELECT username, score_date, score, risk_level, contributors, alert_fired, updated_at
		FROM insider_threat_scores
		WHERE tenant_id = $1
		  AND score_date >= CURRENT_DATE - $2
		  AND score >= $3
		ORDER BY score_date DESC, score DESC
		LIMIT 500
	`, tenantID, days, minScore)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()

	type scoreRow struct {
		Username     string         `json:"username"`
		ScoreDate    string         `json:"score_date"`
		Score        int            `json:"score"`
		RiskLevel    string         `json:"risk_level"`
		Contributors map[string]any `json:"contributors"`
		AlertFired   bool           `json:"alert_fired"`
		UpdatedAt    time.Time      `json:"updated_at"`
	}

	var result []scoreRow
	for rows.Next() {
		var r scoreRow
		var contribRaw []byte
		var scoreDate time.Time
		if err := rows.Scan(&r.Username, &scoreDate, &r.Score, &r.RiskLevel, &contribRaw, &r.AlertFired, &r.UpdatedAt); err != nil {
			continue
		}
		r.ScoreDate = scoreDate.Format("2006-01-02")
		if err := json.Unmarshal(contribRaw, &r.Contributors); err != nil {
			r.Contributors = map[string]any{}
		}
		result = append(result, r)
	}
	if result == nil {
		result = []scoreRow{}
	}
	c.JSON(http.StatusOK, result)
}

// GetInsiderThreatSummary returns today's top-risk users for dashboard widgets.
func GetInsiderThreatSummary(c *gin.Context) {
	tenantID := tenantIDFromContext(c)

	rows, err := database.DB.Query(`
		SELECT username, score, risk_level
		FROM insider_threat_scores
		WHERE tenant_id  = $1
		  AND score_date = CURRENT_DATE
		  AND score      >= 30
		ORDER BY score DESC
		LIMIT 20
	`, tenantID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()

	type summary struct {
		Username  string `json:"username"`
		Score     int    `json:"score"`
		RiskLevel string `json:"risk_level"`
	}
	var result []summary
	for rows.Next() {
		var s summary
		if rows.Scan(&s.Username, &s.Score, &s.RiskLevel) == nil {
			result = append(result, s)
		}
	}
	if result == nil {
		result = []summary{}
	}
	c.JSON(http.StatusOK, result)
}
