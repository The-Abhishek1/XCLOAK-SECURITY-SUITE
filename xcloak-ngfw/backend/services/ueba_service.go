package services

import (
	"fmt"
	"log"
	"regexp"
	"strings"
	"time"

	"xcloak-ngfw/database"
	"xcloak-ngfw/models"
	"xcloak-ngfw/repositories"
)

// Regex patterns for auth.log event classification
var (
	reFailedPassword   = regexp.MustCompile(`Failed password for (?:invalid user )?(\S+) from ([\d.a-f:]+)`)
	reAcceptedPassword = regexp.MustCompile(`Accepted (?:password|publickey) for (\S+) from ([\d.a-f:]+)`)
	reSessionOpened    = regexp.MustCompile(`session opened for user (\S+)`)
	reSudo             = regexp.MustCompile(`sudo:\s+(\S+)\s*:.*COMMAND=(\S+)`)
	rePrivEsc          = regexp.MustCompile(`(?:su\[|newgrp\[|usermod).*(?:for|to|root)`)
	reSyslog           = regexp.MustCompile(`^\S+\s+\S+\s+\S+:\s+`)
)

type userStats struct {
	failedLogins    int
	successLogins   int
	offHours        int
	privEsc         int
	ips             map[string]struct{}
	lastIP          string
	lastEvent       time.Time
	flags           []string
}

// AnalyzeTenant scans logs + audit trail for one tenant and updates risk profiles.
func AnalyzeTenant(tenantID int) {
	pruneTime := time.Now().Add(-30 * 24 * time.Hour)
	repositories.DeleteOldUEBAEvents(tenantID, pruneTime)

	events := analyzeEndpointLogs(tenantID)
	platformEvents := analyzePlatformAuditLogs(tenantID)
	events = append(events, platformEvents...)

	if len(events) > 0 {
		repositories.BulkInsertUEBAEvents(events)
	}

	buildAndSaveProfiles(tenantID, events, "endpoint")
	buildAndSaveProfiles(tenantID, platformEvents, "platform")
}

func analyzeEndpointLogs(tenantID int) []models.UEBAEvent {
	cutoff := time.Now().Add(-7 * 24 * time.Hour)
	rows, err := database.DB.Query(`
		SELECT l.id, l.agent_id, l.log_message, l.collected_at
		FROM endpoint_logs l
		WHERE l.tenant_id=$1 AND l.log_source='auth.log' AND l.collected_at > $2
		ORDER BY l.collected_at ASC
		LIMIT 50000`, tenantID, cutoff)
	if err != nil {
		return nil
	}
	defer rows.Close()

	var events []models.UEBAEvent
	for rows.Next() {
		var id, agentID int
		var msg string
		var ts time.Time
		if err := rows.Scan(&id, &agentID, &msg, &ts); err != nil {
			continue
		}
		// Strip syslog prefix if present
		stripped := reSyslog.ReplaceAllString(msg, "")

		agentRef := &agentID

		if m := reFailedPassword.FindStringSubmatch(stripped); len(m) >= 3 {
			sev := "low"
			events = append(events, models.UEBAEvent{
				TenantID: tenantID, Username: m[1], EventType: "failed_login",
				Severity: sev, Description: fmt.Sprintf("Failed login from %s", m[2]),
				SourceIP: m[2], AgentID: agentRef, RawLog: uebaSnip(msg, 300), DetectedAt: ts,
			})
		} else if m := reAcceptedPassword.FindStringSubmatch(stripped); len(m) >= 3 {
			sev := "info"
			if isOffHours(ts) {
				sev = "medium"
			}
			events = append(events, models.UEBAEvent{
				TenantID: tenantID, Username: m[1], EventType: "login",
				Severity: sev, Description: fmt.Sprintf("Login from %s%s", m[2], offHoursSuffix(ts)),
				SourceIP: m[2], AgentID: agentRef, RawLog: uebaSnip(msg, 300), DetectedAt: ts,
			})
		} else if m := reSudo.FindStringSubmatch(stripped); len(m) >= 3 {
			sev := "medium"
			if strings.Contains(m[2], "/bin/bash") || strings.Contains(m[2], "/bin/sh") {
				sev = "high"
			}
			events = append(events, models.UEBAEvent{
				TenantID: tenantID, Username: m[1], EventType: "sudo",
				Severity: sev, Description: fmt.Sprintf("Sudo command: %s", m[2]),
				AgentID: agentRef, RawLog: uebaSnip(msg, 300), DetectedAt: ts,
			})
		} else if rePrivEsc.MatchString(stripped) {
			events = append(events, models.UEBAEvent{
				TenantID: tenantID, Username: "unknown", EventType: "priv_escalation",
				Severity: "high", Description: "Potential privilege escalation: " + uebaSnip(stripped, 100),
				AgentID: agentRef, RawLog: uebaSnip(msg, 300), DetectedAt: ts,
			})
		} else if m := reSessionOpened.FindStringSubmatch(stripped); len(m) >= 2 && isOffHours(ts) {
			events = append(events, models.UEBAEvent{
				TenantID: tenantID, Username: m[1], EventType: "off_hours_login",
				Severity: "medium", Description: "Session opened outside business hours",
				AgentID: agentRef, RawLog: uebaSnip(msg, 300), DetectedAt: ts,
			})
		}
	}
	return events
}

func analyzePlatformAuditLogs(tenantID int) []models.UEBAEvent {
	cutoff := time.Now().Add(-7 * 24 * time.Hour)
	rows, err := database.DB.Query(`
		SELECT action, details, username, created_at
		FROM audit_logs
		WHERE tenant_id=$1 AND created_at > $2
		ORDER BY created_at ASC
		LIMIT 20000`, tenantID, cutoff)
	if err != nil {
		return nil
	}
	defer rows.Close()

	var events []models.UEBAEvent
	failCounts := map[string]int{}

	for rows.Next() {
		var action, details, username string
		var ts time.Time
		rows.Scan(&action, &details, &username, &ts)
		if username == "" {
			continue
		}

		switch action {
		case "LOGIN_FAILED":
			failCounts[username]++
			if failCounts[username] >= 5 {
				events = append(events, models.UEBAEvent{
					TenantID: tenantID, Username: username, EventType: "brute_force",
					Severity: "high", Description: fmt.Sprintf("Platform brute-force: %d failed logins", failCounts[username]),
					DetectedAt: ts,
				})
			}
		case "ROLE_CHANGE", "INVITE_USER":
			events = append(events, models.UEBAEvent{
				TenantID: tenantID, Username: username, EventType: "priv_change",
				Severity: "medium", Description: fmt.Sprintf("Platform privilege action: %s — %s", action, uebaSnip(details, 80)),
				DetectedAt: ts,
			})
		}
	}
	return events
}

func buildAndSaveProfiles(tenantID int, events []models.UEBAEvent, source string) {
	stats := map[string]*userStats{}

	for _, e := range events {
		u := e.Username
		if _, ok := stats[u]; !ok {
			stats[u] = &userStats{ips: map[string]struct{}{}}
		}
		s := stats[u]
		s.lastEvent = e.DetectedAt
		if e.SourceIP != "" {
			s.ips[e.SourceIP] = struct{}{}
			s.lastIP = e.SourceIP
		}
		switch e.EventType {
		case "failed_login", "brute_force":
			s.failedLogins++
		case "login":
			s.successLogins++
		case "off_hours_login":
			s.offHours++
		case "sudo", "priv_escalation", "priv_change":
			s.privEsc++
		}
	}

	for username, s := range stats {
		score := s.failedLogins*10 + s.offHours*5 + s.privEsc*20 + (len(s.ips)-1)*15
		if score < 0 {
			score = 0
		}
		if score > 100 {
			score = 100
		}

		var flags []string
		if s.failedLogins >= 10 {
			flags = append(flags, "high_failure_rate")
		}
		if s.offHours >= 3 {
			flags = append(flags, "off_hours_activity")
		}
		if s.privEsc >= 2 {
			flags = append(flags, "privilege_escalation")
		}
		if len(s.ips) >= 3 {
			flags = append(flags, "multiple_source_ips")
		}

		var lastEvent *time.Time
		if !s.lastEvent.IsZero() {
			lastEvent = &s.lastEvent
		}

		p := models.UserRiskProfile{
			TenantID: tenantID, Username: username, Source: source,
			RiskScore: score, TotalEvents: s.failedLogins + s.successLogins + s.offHours + s.privEsc,
			FailedLogins: s.failedLogins, OffHoursEvents: s.offHours,
			UniqueIPs: len(s.ips), PrivilegeEscalations: s.privEsc,
			Flags: flags, LastSeenIP: s.lastIP, LastEventAt: lastEvent,
		}
		repositories.UpsertUserRiskProfile(p)
	}
}

// StartUEBAAnalyzer runs a background analysis every 30 minutes.
func StartUEBAAnalyzer() {
	go func() {
		run := func() {
			rows, err := database.DB.Query(`SELECT id FROM tenants WHERE is_active=true`)
			if err != nil {
				return
			}
			defer rows.Close()
			for rows.Next() {
				var id int
				rows.Scan(&id)
				AnalyzeTenant(id)
			}
		}
		run()
		ticker := time.NewTicker(30 * time.Minute)
		for range ticker.C {
			run()
		}
	}()
	log.Println("[UEBA] background analyzer started (30min interval)")
}

func isOffHours(t time.Time) bool {
	h := t.Hour()
	wd := t.Weekday()
	if wd == time.Saturday || wd == time.Sunday {
		return true
	}
	return h < 8 || h >= 20
}

func offHoursSuffix(t time.Time) string {
	if isOffHours(t) {
		return " (off-hours)"
	}
	return ""
}

func uebaSnip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
