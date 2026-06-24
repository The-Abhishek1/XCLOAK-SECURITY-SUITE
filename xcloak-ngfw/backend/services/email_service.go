package services

import (
	"crypto/tls"
	"fmt"
	"net/smtp"
	"os"
	"strings"
	"time"

	"xcloak-ngfw/database"
	"xcloak-ngfw/models"
	"xcloak-ngfw/secrets"
)

// SMTPConfig holds connection details loaded from env.
type SMTPConfig struct {
	Host     string
	Port     string
	Username string
	Password string
	From     string
	TLS      bool
}

func loadSMTPConfig() *SMTPConfig {
	host := os.Getenv("SMTP_HOST")
	if host == "" {
		return nil // SMTP not configured
	}
	port := os.Getenv("SMTP_PORT")
	if port == "" {
		port = "587"
	}
	return &SMTPConfig{
		Host:     host,
		Port:     port,
		Username: secrets.Resolve("SMTP_USER", "xcloak/backend", "smtp_user"),
		Password: secrets.Resolve("SMTP_PASS", "xcloak/backend", "smtp_password"),
		From:     os.Getenv("SMTP_FROM"),
		TLS:      os.Getenv("SMTP_TLS") == "true",
	}
}

// SendAlertEmail delivers a critical/high alert notification email.
func SendAlertEmail(alert models.Alert, recipients []string) error {
	cfg := loadSMTPConfig()
	if cfg == nil {
		return fmt.Errorf("SMTP not configured — set SMTP_HOST in .env")
	}
	if len(recipients) == 0 {
		return nil
	}

	severityIcon := map[string]string{
		"critical": "🔴",
		"high":     "🟠",
		"medium":   "🟡",
		"low":      "🟢",
	}
	icon := severityIcon[alert.Severity]
	if icon == "" {
		icon = "⚠️"
	}

	subject := fmt.Sprintf("%s [XCloak %s] %s", icon, strings.ToUpper(alert.Severity), alert.RuleName)

	body := fmt.Sprintf(`XCloak Security Alert
=====================

Severity:   %s
Rule:       %s
Agent ID:   %d
Time:       %s

Log Message:
%s

MITRE ATT&CK:
  Tactic:    %s
  Technique: %s (%s)

---
View in XCloak: http://localhost:3000/alerts
This alert was generated automatically by XCloak Security Suite.
`,
		strings.ToUpper(alert.Severity),
		alert.RuleName,
		alert.AgentID,
		alert.CreatedAt.Format("2006-01-02 15:04:05 UTC"),
		alert.LogMessage,
		alert.MitreTactic,
		alert.MitreName,
		alert.MitreTechnique,
	)

	return sendEmail(cfg, recipients, subject, body)
}

// SendCriticalIncidentEmail delivers an incident notification email.
func SendCriticalIncidentEmail(incident models.Incident, recipients []string) error {
	cfg := loadSMTPConfig()
	if cfg == nil {
		return nil // silently skip if SMTP not configured
	}
	if len(recipients) == 0 {
		return nil
	}

	subject := fmt.Sprintf("🔴 [XCloak INCIDENT] %s", incident.Title)
	body := fmt.Sprintf(`XCloak Critical Incident
========================

Title:      %s
Severity:   %s
Status:     %s
Agent ID:   %d
Opened:     %s

%s

---
View in XCloak: http://localhost:3000/incidents
`,
		incident.Title,
		strings.ToUpper(incident.Severity),
		incident.Status,
		incident.AgentID,
		incident.CreatedAt.Format("2006-01-02 15:04:05 UTC"),
		incident.Description,
	)

	return sendEmail(cfg, recipients, subject, body)
}

// SendTestEmail sends a one-off test message to verify SMTP configuration
// from the Settings UI.
func SendTestEmail(recipient string) error {
	cfg := loadSMTPConfig()
	if cfg == nil {
		return fmt.Errorf("SMTP not configured — set SMTP_HOST in .env")
	}
	subject := "✅ [XCloak] Test Email"
	body := fmt.Sprintf(`This is a test email from XCloak Security Suite.

If you're reading this, your SMTP configuration (host: %s) is working correctly.
`, cfg.Host)
	return sendEmail(cfg, []string{recipient}, subject, body)
}

// sendEmail is the low-level SMTP sender.
func sendEmail(cfg *SMTPConfig, to []string, subject, body string) error {
	from := cfg.From
	if from == "" {
		from = cfg.Username
	}

	msg := fmt.Sprintf("From: XCloak Security <%s>\r\nTo: %s\r\nSubject: %s\r\nDate: %s\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n%s",
		from,
		strings.Join(to, ", "),
		subject,
		time.Now().Format(time.RFC1123Z),
		body,
	)

	addr := cfg.Host + ":" + cfg.Port

	if cfg.TLS {
		// TLS (port 465)
		tlsCfg := &tls.Config{ServerName: cfg.Host}
		conn, err := tls.Dial("tcp", addr, tlsCfg)
		if err != nil {
			return fmt.Errorf("SMTP TLS dial failed: %w", err)
		}
		client, err := smtp.NewClient(conn, cfg.Host)
		if err != nil {
			return err
		}
		defer client.Close()
		if cfg.Username != "" {
			if err := client.Auth(smtp.PlainAuth("", cfg.Username, cfg.Password, cfg.Host)); err != nil {
				return fmt.Errorf("SMTP auth failed: %w", err)
			}
		}
		if err := client.Mail(from); err != nil { return err }
		for _, r := range to {
			if err := client.Rcpt(r); err != nil { return err }
		}
		w, err := client.Data()
		if err != nil { return err }
		fmt.Fprint(w, msg)
		return w.Close()
	}

	// STARTTLS (port 587) or plain (port 25)
	var auth smtp.Auth
	if cfg.Username != "" {
		auth = smtp.PlainAuth("", cfg.Username, cfg.Password, cfg.Host)
	}
	return smtp.SendMail(addr, auth, from, to, []byte(msg))
}

// GetEmailRecipients returns enabled recipients for a given severity, scoped
// to the tenant that owns agentID — without this, every tenant's configured
// recipients would be notified about every other tenant's alerts. Resolved
// from agentID rather than taking a tenantID directly since the only caller
// (the alert pipeline) has no per-request tenant context of its own.
func GetEmailRecipients(severity string, agentID int) []string {
	rows, err := database.DB.Query(`
		SELECT recipient FROM email_alert_rules
		WHERE enabled = TRUE
		  AND (severity = $1 OR severity = 'any')
		  AND tenant_id = (SELECT tenant_id FROM agents WHERE id = $2)
	`, severity, agentID)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var recipients []string
	for rows.Next() {
		var r string
		if rows.Scan(&r) == nil {
			recipients = append(recipients, r)
		}
	}
	return recipients
}
