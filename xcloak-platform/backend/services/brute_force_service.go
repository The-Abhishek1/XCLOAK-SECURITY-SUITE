package services

import (
	"fmt"
	"time"

	"xcloak-platform/database"
	"xcloak-platform/models"
)

const (
	bruteForceThreshold = 5               // failures before alert
	bruteForceWindow    = 2 * time.Minute // rolling window
	bruteForceAlertCooldown = 10 * time.Minute
)

// TrackFailedLogin records a failed authentication and fires an alert if
// the brute-force threshold is exceeded within the rolling window.
// Call this from the log processing pipeline when a "failed password" log arrives.
func TrackFailedLogin(agentID int, logMessage string) {

	now := time.Now()

	// Fetch or initialise state for this agent.
	var failCount int
	var windowStart time.Time
	var lastAlert *time.Time

	err := database.DB.QueryRow(`
		SELECT fail_count, window_start, last_alert
		FROM brute_force_state WHERE agent_id = $1
	`, agentID).Scan(&failCount, &windowStart, &lastAlert)

	if err != nil {
		// No record yet — insert initial state.
		database.DB.Exec(`
			INSERT INTO brute_force_state (agent_id, fail_count, window_start)
			VALUES ($1, 1, $2)
		`, agentID, now)
		return
	}

	// Reset counter if outside the rolling window.
	if now.Sub(windowStart) > bruteForceWindow {
		failCount   = 0
		windowStart = now
	}

	failCount++

	database.DB.Exec(`
		UPDATE brute_force_state
		SET fail_count = $1, window_start = $2
		WHERE agent_id = $3
	`, failCount, windowStart, agentID)

	// Fire alert if threshold exceeded and not in cooldown.
	if failCount >= bruteForceThreshold {
		inCooldown := lastAlert != nil && now.Sub(*lastAlert) < bruteForceAlertCooldown
		if !inCooldown {
			CreateAlert(models.Alert{
				AgentID:        agentID,
				Severity:       "high",
				RuleName:       "Brute Force Attack",
				LogMessage:     fmt.Sprintf("%d failed logins in %s — %s", failCount, bruteForceWindow, logMessage),
				MitreTactic:    "Credential Access",
				MitreTechnique: "T1110",
				MitreName:      "Brute Force",
				Fingerprint:    fmt.Sprintf("bruteforce-%d", agentID),
			})
			database.DB.Exec(`
				UPDATE brute_force_state SET last_alert = $1, fail_count = 0 WHERE agent_id = $2
			`, now, agentID)
		}
	}
}

// ResetBruteForceState clears the counter on successful login.
func ResetBruteForceState(agentID int) {
	database.DB.Exec(`
		UPDATE brute_force_state SET fail_count = 0, window_start = now() WHERE agent_id = $1
	`, agentID)
}
