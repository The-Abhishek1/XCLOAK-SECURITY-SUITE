package services

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"net/smtp"
	"os"
	"strings"
	"text/template"
	"time"

	"xcloak-platform/database"
	"xcloak-platform/models"
	"xcloak-platform/secrets"
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
		return nil
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

func appURL() string {
	// Check both APP_URL and the legacy APP_BASE_URL env var.
	for _, key := range []string{"APP_URL", "APP_BASE_URL"} {
		if u := os.Getenv(key); u != "" {
			return strings.TrimRight(u, "/")
		}
	}
	return "http://localhost:3000"
}

// SendInviteEmail delivers an account invitation with a password-set link.
func SendInviteEmail(cfg *SMTPConfig, recipient, username, role, token string) error {
	if cfg == nil {
		return fmt.Errorf("SMTP not configured — set SMTP_HOST in .env")
	}
	base := appURL()
	ts := time.Now().UTC().Format("02 Jan 2006 at 15:04 UTC")
	subject := "[XCloak] You've been invited"

	d := emailData{
		Subject:   subject,
		TypeLabel: "Account Invitation",
		Title:     "You've been added to XCloak Security Suite",
		SevColor:  "#ffffff",
		SevBg:     "#388bfd",
		SevLabel:  "INVITE",
		Rows: []emailRow{
			{"Username", username},
			{"Role", strings.ToTitle(role)},
			{"Expires", "24 hours from now"},
		},
		Body:      "Use the button below to set your password and access the platform. This link expires in 24 hours.",
		CTALink:   base + "/reset-password?token=" + token,
		CTAText:   "Set Your Password",
		AppURL:    base,
		Timestamp: ts,
	}
	return sendMultipart(cfg, []string{recipient}, subject, renderText(d), renderHTML(d))
}

// SendPasswordResetEmail delivers a password reset link.
func SendPasswordResetEmail(cfg *SMTPConfig, recipient, username, token string) error {
	if cfg == nil {
		return fmt.Errorf("SMTP not configured — set SMTP_HOST in .env")
	}
	base := appURL()
	ts := time.Now().UTC().Format("02 Jan 2006 at 15:04 UTC")
	subject := "[XCloak] Password Reset Request"

	d := emailData{
		Subject:   subject,
		TypeLabel: "Password Reset",
		Title:     "Reset your XCloak password",
		SevColor:  "#ffffff",
		SevBg:     "#6e40c9",
		SevLabel:  "RESET",
		Rows: []emailRow{
			{"Account", username},
			{"Requested", ts},
			{"Expires", "1 hour from now"},
		},
		Body:      "If you did not request this reset, you can safely ignore this email — your password will not change.",
		CTALink:   base + "/reset-password?token=" + token,
		CTAText:   "Reset Password",
		AppURL:    base,
		Timestamp: ts,
	}
	return sendMultipart(cfg, []string{recipient}, subject, renderText(d), renderHTML(d))
}

// messageID generates a unique RFC 5322 Message-ID.
func messageID(host string) string {
	b := make([]byte, 12)
	rand.Read(b)
	return fmt.Sprintf("<%s.%s@%s>", time.Now().Format("20060102150405"), hex.EncodeToString(b), host)
}

// severityStyle returns the hex color and label for a given severity level.
func severityStyle(sev string) (color, bg, label string) {
	switch strings.ToLower(sev) {
	case "critical":
		return "#ffffff", "#d73a49", "CRITICAL"
	case "high":
		return "#ffffff", "#e36209", "HIGH"
	case "medium":
		return "#1a1a1a", "#dbab09", "MEDIUM"
	default:
		return "#1a1a1a", "#28a745", "LOW"
	}
}

// ─── HTML template ────────────────────────────────────────────────────────────

var alertHTMLTmpl = template.Must(template.New("alert").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{{.Subject}}</title>
</head>
<body style="margin:0;padding:0;background:#0d1117;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;">
<table width="100%" cellpadding="0" cellspacing="0" style="background:#0d1117;padding:32px 16px;">
  <tr><td align="center">
    <table width="600" cellpadding="0" cellspacing="0" style="max-width:600px;width:100%;">

      <!-- Header -->
      <tr>
        <td style="background:#161b22;border-radius:8px 8px 0 0;padding:24px 32px;border-bottom:1px solid #30363d;">
          <table width="100%" cellpadding="0" cellspacing="0">
            <tr>
              <td>
                <span style="font-size:18px;font-weight:700;color:#e6edf3;letter-spacing:-0.3px;">XCloak</span>
                <span style="font-size:12px;color:#7d8590;margin-left:8px;">Security Suite</span>
              </td>
              <td align="right">
                <span style="display:inline-block;padding:4px 12px;border-radius:20px;font-size:11px;font-weight:700;letter-spacing:0.5px;color:{{.SevColor}};background:{{.SevBg}};">
                  {{.SevLabel}}
                </span>
              </td>
            </tr>
          </table>
        </td>
      </tr>

      <!-- Body -->
      <tr>
        <td style="background:#161b22;padding:28px 32px;">

          <p style="margin:0 0 6px;font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:0.8px;color:#7d8590;">
            {{.TypeLabel}}
          </p>
          <h1 style="margin:0 0 24px;font-size:20px;font-weight:700;color:#e6edf3;line-height:1.3;">
            {{.Title}}
          </h1>

          <!-- Detail table -->
          <table width="100%" cellpadding="0" cellspacing="0"
            style="background:#0d1117;border:1px solid #30363d;border-radius:6px;margin-bottom:24px;">
            {{range .Rows}}
            <tr style="border-bottom:1px solid #21262d;">
              <td style="padding:10px 16px;font-size:12px;font-weight:600;color:#7d8590;white-space:nowrap;width:120px;">
                {{.Label}}
              </td>
              <td style="padding:10px 16px;font-size:13px;color:#e6edf3;word-break:break-word;">
                {{.Value}}
              </td>
            </tr>
            {{end}}
          </table>

          {{if .Body}}
          <div style="background:#0d1117;border:1px solid #30363d;border-left:3px solid #388bfd;
                      border-radius:0 6px 6px 0;padding:12px 16px;margin-bottom:24px;">
            <p style="margin:0 0 4px;font-size:11px;font-weight:600;color:#7d8590;text-transform:uppercase;letter-spacing:0.5px;">
              Details
            </p>
            <p style="margin:0;font-size:13px;color:#c9d1d9;line-height:1.6;white-space:pre-wrap;word-break:break-word;">{{.Body}}</p>
          </div>
          {{end}}

          <!-- CTA -->
          <table cellpadding="0" cellspacing="0">
            <tr>
              <td style="border-radius:6px;background:#238636;">
                <a href="{{.CTALink}}" target="_blank"
                   style="display:inline-block;padding:10px 20px;font-size:13px;font-weight:600;
                          color:#ffffff;text-decoration:none;border-radius:6px;">
                  {{.CTAText}} &rarr;
                </a>
              </td>
            </tr>
          </table>

        </td>
      </tr>

      <!-- Footer -->
      <tr>
        <td style="background:#0d1117;border-radius:0 0 8px 8px;padding:16px 32px;border-top:1px solid #21262d;">
          <p style="margin:0;font-size:11px;color:#484f58;line-height:1.6;">
            Generated by <strong style="color:#7d8590;">XCloak Security Suite</strong> &middot;
            {{.Timestamp}} &middot;
            <a href="{{.AppURL}}/settings" style="color:#388bfd;text-decoration:none;">Manage alerts</a>
          </p>
        </td>
      </tr>

    </table>
  </td></tr>
</table>
</body>
</html>`))

type emailRow struct {
	Label string
	Value string
}

type emailData struct {
	Subject   string
	TypeLabel string
	Title     string
	SevColor  string
	SevBg     string
	SevLabel  string
	Rows      []emailRow
	Body      string
	CTALink   string
	CTAText   string
	AppURL    string
	Timestamp string
}

func renderHTML(d emailData) string {
	var buf bytes.Buffer
	if err := alertHTMLTmpl.Execute(&buf, d); err != nil {
		return "<p>" + d.Title + "</p>"
	}
	return buf.String()
}

// renderText produces a clean plain-text fallback for the same email data.
func renderText(d emailData) string {
	var b strings.Builder
	b.WriteString(strings.ToUpper(d.TypeLabel) + "\n")
	b.WriteString(strings.Repeat("─", 50) + "\n")
	b.WriteString(d.Title + "\n\n")
	for _, r := range d.Rows {
		b.WriteString(fmt.Sprintf("%-18s %s\n", r.Label+":", r.Value))
	}
	if d.Body != "" {
		b.WriteString("\nDetails:\n")
		b.WriteString(d.Body + "\n")
	}
	b.WriteString("\n" + d.CTAText + ": " + d.CTALink + "\n\n")
	b.WriteString("─────────────────────────────────────────────────\n")
	b.WriteString("XCloak Security Suite · " + d.Timestamp + "\n")
	b.WriteString("Manage email alerts: " + d.AppURL + "/settings\n")
	return b.String()
}

// ─── Public send functions ────────────────────────────────────────────────────

// SendAlertEmail delivers a critical/high alert notification email.
func SendAlertEmail(alert models.Alert, recipients []string) error {
	cfg := loadSMTPConfig()
	if cfg == nil {
		return fmt.Errorf("SMTP not configured — set SMTP_HOST in .env")
	}
	if len(recipients) == 0 {
		return nil
	}

	sevColor, sevBg, sevLabel := severityStyle(alert.Severity)
	base := appURL()
	ts := alert.CreatedAt.UTC().Format("02 Jan 2006 at 15:04 UTC")

	rows := []emailRow{
		{"Rule", alert.RuleName},
		{"Agent", fmt.Sprintf("#%d", alert.AgentID)},
		{"Detected", ts},
	}
	if alert.MitreTechnique != "" {
		rows = append(rows, emailRow{"MITRE", fmt.Sprintf("%s — %s (%s)", alert.MitreTactic, alert.MitreName, alert.MitreTechnique)})
	}

	subject := fmt.Sprintf("[XCloak Alert] %s: %s", sevLabel, alert.RuleName)

	d := emailData{
		Subject:   subject,
		TypeLabel: "Security Alert",
		Title:     alert.RuleName,
		SevColor:  sevColor,
		SevBg:     sevBg,
		SevLabel:  sevLabel,
		Rows:      rows,
		Body:      alert.LogMessage,
		CTALink:   base + "/alerts",
		CTAText:   "Investigate in XCloak",
		AppURL:    base,
		Timestamp: ts,
	}

	return sendMultipart(cfg, recipients, subject, renderText(d), renderHTML(d))
}

// SendCriticalIncidentEmail delivers an incident escalation email.
func SendCriticalIncidentEmail(incident models.Incident, recipients []string) error {
	cfg := loadSMTPConfig()
	if cfg == nil {
		return nil
	}
	if len(recipients) == 0 {
		return nil
	}

	sevColor, sevBg, sevLabel := severityStyle(incident.Severity)
	base := appURL()
	ts := incident.CreatedAt.UTC().Format("02 Jan 2006 at 15:04 UTC")

	rows := []emailRow{
		{"Severity", strings.ToUpper(incident.Severity)},
		{"Status", strings.ToTitle(incident.Status)},
		{"Agent", fmt.Sprintf("#%d", incident.AgentID)},
		{"Opened", ts},
	}

	subject := fmt.Sprintf("[XCloak Incident] %s: %s", sevLabel, incident.Title)

	d := emailData{
		Subject:   subject,
		TypeLabel: "Critical Incident",
		Title:     incident.Title,
		SevColor:  sevColor,
		SevBg:     sevBg,
		SevLabel:  sevLabel,
		Rows:      rows,
		Body:      incident.Description,
		CTALink:   base + "/incidents",
		CTAText:   "View Incident in XCloak",
		AppURL:    base,
		Timestamp: ts,
	}

	return sendMultipart(cfg, recipients, subject, renderText(d), renderHTML(d))
}

// SendTestEmail sends a one-off test message to verify SMTP configuration.
func SendTestEmail(recipient string) error {
	cfg := loadSMTPConfig()
	if cfg == nil {
		return fmt.Errorf("SMTP not configured — set SMTP_HOST in .env")
	}

	base := appURL()
	ts := time.Now().UTC().Format("02 Jan 2006 at 15:04 UTC")
	subject := "[XCloak] SMTP Configuration Test"

	d := emailData{
		Subject:   subject,
		TypeLabel: "Configuration Test",
		Title:     "SMTP configuration is working",
		SevColor:  "#ffffff",
		SevBg:     "#238636",
		SevLabel:  "OK",
		Rows: []emailRow{
			{"SMTP Host", cfg.Host + ":" + cfg.Port},
			{"From",      cfg.From},
			{"Sent",      ts},
		},
		Body:      "Your XCloak SMTP integration is configured correctly. Alert and incident emails will be delivered to this address.",
		CTALink:   base + "/settings",
		CTAText:   "Go to Settings",
		AppURL:    base,
		Timestamp: ts,
	}

	return sendMultipart(cfg, []string{recipient}, subject, renderText(d), renderHTML(d))
}

// ─── Low-level SMTP ───────────────────────────────────────────────────────────

// sendMultipart composes and sends a multipart/alternative email (text + HTML).
func sendMultipart(cfg *SMTPConfig, to []string, subject, textBody, htmlBody string) error {
	from := cfg.From
	if from == "" {
		from = cfg.Username
	}

	boundary := "xcloak_" + fmt.Sprintf("%d", time.Now().UnixNano())
	msgID := messageID(cfg.Host)

	var msg strings.Builder
	msg.WriteString("From: XCloak Security <" + from + ">\r\n")
	msg.WriteString("To: " + strings.Join(to, ", ") + "\r\n")
	msg.WriteString("Subject: " + subject + "\r\n")
	msg.WriteString("Date: " + time.Now().Format(time.RFC1123Z) + "\r\n")
	msg.WriteString("Message-ID: " + msgID + "\r\n")
	msg.WriteString("MIME-Version: 1.0\r\n")
	msg.WriteString("Content-Type: multipart/alternative; boundary=\"" + boundary + "\"\r\n")
	msg.WriteString("X-Mailer: XCloak Security Suite\r\n")
	msg.WriteString("X-Priority: 1\r\n")
	msg.WriteString("\r\n")

	// Plain text part
	msg.WriteString("--" + boundary + "\r\n")
	msg.WriteString("Content-Type: text/plain; charset=UTF-8\r\n")
	msg.WriteString("Content-Transfer-Encoding: quoted-printable\r\n")
	msg.WriteString("\r\n")
	msg.WriteString(toQP(textBody))
	msg.WriteString("\r\n")

	// HTML part (preferred — mail clients pick this when supported)
	msg.WriteString("--" + boundary + "\r\n")
	msg.WriteString("Content-Type: text/html; charset=UTF-8\r\n")
	msg.WriteString("Content-Transfer-Encoding: quoted-printable\r\n")
	msg.WriteString("\r\n")
	msg.WriteString(toQP(htmlBody))
	msg.WriteString("\r\n")

	msg.WriteString("--" + boundary + "--\r\n")

	return transmit(cfg, from, to, []byte(msg.String()))
}

// toQP applies minimal quoted-printable encoding (lines >76 chars, non-ASCII).
// A full QP encoder would use mime/quotedprintable; this lightweight version
// handles the common cases without adding an external dependency.
func toQP(s string) string {
	var b strings.Builder
	lineLen := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c > 126 || (c < 32 && c != '\t' && c != '\n' && c != '\r') {
			enc := fmt.Sprintf("=%02X", c)
			if lineLen+3 > 75 {
				b.WriteString("=\r\n")
				lineLen = 0
			}
			b.WriteString(enc)
			lineLen += 3
		} else if c == '=' {
			if lineLen+3 > 75 {
				b.WriteString("=\r\n")
				lineLen = 0
			}
			b.WriteString("=3D")
			lineLen += 3
		} else if c == '\n' {
			b.WriteString("\r\n")
			lineLen = 0
		} else if c == '\r' {
			// skip bare CR
		} else {
			if lineLen >= 75 {
				b.WriteString("=\r\n")
				lineLen = 0
			}
			b.WriteByte(c)
			lineLen++
		}
	}
	return b.String()
}

// transmit connects to SMTP and delivers the raw message bytes.
func transmit(cfg *SMTPConfig, from string, to []string, msg []byte) error {
	addr := cfg.Host + ":" + cfg.Port

	if cfg.TLS {
		tlsCfg := &tls.Config{ServerName: cfg.Host}
		conn, err := tls.Dial("tcp", addr, tlsCfg)
		if err != nil {
			return fmt.Errorf("SMTP TLS dial: %w", err)
		}
		client, err := smtp.NewClient(conn, cfg.Host)
		if err != nil {
			return fmt.Errorf("SMTP client: %w", err)
		}
		defer client.Close()
		if cfg.Username != "" {
			if err := client.Auth(smtp.PlainAuth("", cfg.Username, cfg.Password, cfg.Host)); err != nil {
				return fmt.Errorf("SMTP auth: %w", err)
			}
		}
		if err := client.Mail(from); err != nil {
			return err
		}
		for _, r := range to {
			if err := client.Rcpt(r); err != nil {
				return err
			}
		}
		w, err := client.Data()
		if err != nil {
			return err
		}
		if _, err = w.Write(msg); err != nil {
			return err
		}
		return w.Close()
	}

	var auth smtp.Auth
	if cfg.Username != "" {
		auth = smtp.PlainAuth("", cfg.Username, cfg.Password, cfg.Host)
	}
	return smtp.SendMail(addr, auth, from, to, msg)
}

// GetEmailRecipients returns enabled recipients for a given severity, scoped
// to the tenant that owns agentID.
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
