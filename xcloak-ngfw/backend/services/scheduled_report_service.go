package services

import (
	"bytes"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"xcloak-ngfw/repositories"
)

// StartScheduledReportRunner checks every hour whether any report schedule
// has fired since the last send and delivers the report PDF via email.
func StartScheduledReportRunner() {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()
	// Run immediately on startup.
	runScheduledReports()
	for range ticker.C {
		runScheduledReports()
	}
}

func runScheduledReports() {
	reports, err := repositories.GetAllEnabledScheduledReports()
	if err != nil {
		return
	}
	now := time.Now()
	for _, r := range reports {
		if !scheduleFired(r.Schedule, r.LastSentAt, now) {
			continue
		}
		if len(r.Recipients) == 0 {
			continue
		}
		metrics, err := BuildExecutiveMetrics(r.TenantID)
		if err != nil {
			slog.Error("scheduled-report: metrics error", "report_id", r.ID, "err", err)
			continue
		}

		var buf bytes.Buffer
		if err := GenerateExecutivePDF(&buf, metrics, r.Name); err != nil {
			slog.Error("scheduled-report: PDF error", "report_id", r.ID, "err", err)
			continue
		}

		cfg := loadSMTPConfig()
		if cfg == nil || cfg.Host == "" {
			slog.Warn("scheduled-report: SMTP not configured, skipping", "report_id", r.ID)
			continue
		}

		subject := fmt.Sprintf("[XCLOAK] %s — %s", r.Name, now.Format("2006-01-02"))
		body := buildReportEmailBody(metrics)
		if err := sendEmailWithAttachment(cfg, r.Recipients, subject, body, "executive-report.pdf", buf.Bytes()); err != nil {
			slog.Error("scheduled-report: email error", "report_id", r.ID, "err", err)
			continue
		}
		repositories.MarkReportSent(r.ID)
		slog.Info("scheduled-report: sent", "report_id", r.ID, "recipients", r.Recipients)
	}
}

// scheduleFired returns true if the cron-like schedule should fire between
// lastSent (or epoch if nil) and now. Supports simple patterns:
//
//	"0 8 * * 1"  → Mondays at 08:00
//	"0 8 * * *"  → Daily at 08:00
//	"0 8 1 * *"  → Monthly on the 1st at 08:00
func scheduleFired(schedule string, lastSent *time.Time, now time.Time) bool {
	parts := strings.Fields(schedule)
	if len(parts) != 5 {
		return false
	}

	var since time.Time
	if lastSent != nil {
		since = *lastSent
	}

	// Walk each hour in [since+1h, now] and check if any matches the pattern.
	check := since.Truncate(time.Hour).Add(time.Hour)
	for !check.After(now) {
		if matchCronField(parts[1], check.Hour()) && // hour
			matchCronField(parts[2], check.Day()) && // day of month
			matchCronField(parts[3], int(check.Month())) && // month
			matchCronField(parts[4], int(check.Weekday())) { // day of week (0=Sun)
			return true
		}
		check = check.Add(time.Hour)
	}
	return false
}

func matchCronField(expr string, val int) bool {
	if expr == "*" {
		return true
	}
	var n int
	if _, err := fmt.Sscanf(expr, "%d", &n); err == nil {
		return n == val
	}
	return false
}

func buildReportEmailBody(m interface{}) string {
	return fmt.Sprintf(`XCLOAK Executive Security Report

This is your scheduled security posture summary.

Please find the full PDF report attached.

Generated: %s

---
XCLOAK Security Suite
`, time.Now().Format(time.RFC1123))
}

// sendEmailWithAttachment sends a MIME email with a PDF attachment.
func sendEmailWithAttachment(cfg *SMTPConfig, to []string, subject, body string, filename string, data []byte) error {
	boundary := "XCLOAKboundary42"
	var msg strings.Builder
	msg.WriteString(fmt.Sprintf("From: XCLOAK <%s>\r\n", cfg.Username))
	msg.WriteString(fmt.Sprintf("To: %s\r\n", strings.Join(to, ", ")))
	msg.WriteString(fmt.Sprintf("Subject: %s\r\n", subject))
	msg.WriteString("MIME-Version: 1.0\r\n")
	msg.WriteString(fmt.Sprintf("Content-Type: multipart/mixed; boundary=\"%s\"\r\n", boundary))
	msg.WriteString("\r\n")

	// Text part
	msg.WriteString(fmt.Sprintf("--%s\r\n", boundary))
	msg.WriteString("Content-Type: text/plain; charset=UTF-8\r\n\r\n")
	msg.WriteString(body)
	msg.WriteString("\r\n")

	// PDF attachment
	msg.WriteString(fmt.Sprintf("--%s\r\n", boundary))
	msg.WriteString(fmt.Sprintf("Content-Type: application/pdf; name=\"%s\"\r\n", filename))
	msg.WriteString("Content-Transfer-Encoding: base64\r\n")
	msg.WriteString(fmt.Sprintf("Content-Disposition: attachment; filename=\"%s\"\r\n\r\n", filename))

	import64 := encodeBase64Chunked(data)
	msg.WriteString(import64)
	msg.WriteString("\r\n")
	msg.WriteString(fmt.Sprintf("--%s--\r\n", boundary))

	return sendEmail(cfg, to, subject, msg.String())
}

func encodeBase64Chunked(data []byte) string {
	const lineLen = 76
	encoded := make([]byte, ((len(data)+2)/3)*4)
	n := encodeToBase64(encoded, data)
	encoded = encoded[:n]

	var out strings.Builder
	for i := 0; i < len(encoded); i += lineLen {
		end := i + lineLen
		if end > len(encoded) {
			end = len(encoded)
		}
		out.Write(encoded[i:end])
		out.WriteString("\r\n")
	}
	return out.String()
}

func encodeToBase64(dst, src []byte) int {
	const table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	n := 0
	for i := 0; i < len(src); i += 3 {
		b0 := src[i]
		var b1, b2 byte
		if i+1 < len(src) {
			b1 = src[i+1]
		}
		if i+2 < len(src) {
			b2 = src[i+2]
		}
		dst[n] = table[b0>>2]
		dst[n+1] = table[((b0&3)<<4)|(b1>>4)]
		dst[n+2] = table[((b1&0xf)<<2)|(b2>>6)]
		dst[n+3] = table[b2&0x3f]
		if i+1 >= len(src) {
			dst[n+2] = '='
			dst[n+3] = '='
		} else if i+2 >= len(src) {
			dst[n+3] = '='
		}
		n += 4
	}
	return n
}
