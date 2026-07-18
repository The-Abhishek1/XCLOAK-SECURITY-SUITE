package api

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"xcloak-platform/models"
	"xcloak-platform/repositories"
	"xcloak-platform/services"
)

const maxIngestBytes = 10 << 20 // 10 MiB per request
const maxEventsPerRequest = 5000

// IngestLogs — POST /api/ingest
// Accepts syslog, CEF, LEEF, JSON, or NDJSON log streams from external systems.
// Authenticated via X-Api-Key header (plaintext key, SHA-256'd for lookup).
//
// Supported Content-Types:
//
//	application/json              → single JSON object or JSON array
//	application/x-ndjson         → newline-delimited JSON (one object per line)
//	text/plain                   → one raw log message per line (syslog / CEF / LEEF)
//	(absent)                     → auto-detect format
func IngestLogs(c *gin.Context) {
	src, ok := logSourceFromContext(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid or missing X-Api-Key"})
		return
	}
	if !src.Enabled {
		c.JSON(http.StatusForbidden, gin.H{"error": "log source is disabled"})
		return
	}

	body, err := io.ReadAll(io.LimitReader(c.Request.Body, maxIngestBytes))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "reading body"})
		return
	}

	ct := c.ContentType()
	rawMessages := []string{}

	switch {
	case strings.Contains(ct, "application/json"):
		rawMessages = parseJSONBody(body)
	case strings.Contains(ct, "application/x-ndjson"):
		rawMessages = parseNDJSON(body)
	case strings.Contains(ct, "text/plain"):
		rawMessages = parseTextLines(body)
	default:
		rawMessages = autoDetect(body)
	}

	if len(rawMessages) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "no log events parsed from body"})
		return
	}
	if len(rawMessages) > maxEventsPerRequest {
		rawMessages = rawMessages[:maxEventsPerRequest]
	}

	agentID := 0
	if src.AgentID != nil {
		agentID = *src.AgentID
	}

	logs := make([]models.Log, 0, len(rawMessages))
	for _, msg := range rawMessages {
		if msg == "" {
			continue
		}
		logs = append(logs, models.Log{
			AgentID:     agentID,
			LogSource:   src.Name,
			LogMessage:  msg,
			CollectedAt: time.Now(),
		})
	}

	if err := services.SaveLogs(logs); err != nil {
		slog.Error("ingest: save error", "source", src.Name, "err", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "storing logs"})
		return
	}

	go repositories.BumpLogSourceEvent(src.ID)

	c.JSON(http.StatusOK, gin.H{"received": len(logs)})
}

// ── middleware ────────────────────────────────────────────────────────────────

const logSourceCtxKey = "log_source"

// RequireLogSourceAuth validates X-Api-Key and injects the LogSource into the
// Gin context. Use on the /api/ingest route (not RequireAuth — no user JWT here).
func RequireLogSourceAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		key := c.GetHeader("X-Api-Key")
		if key == "" {
			// Also accept Bearer token for tools that always send Authorization.
			auth := c.GetHeader("Authorization")
			key = strings.TrimPrefix(auth, "Bearer ")
		}
		if key == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "X-Api-Key header required"})
			c.Abort()
			return
		}
		hash := repositories.HashAPIKey(key)
		src := repositories.GetLogSourceByAPIKey(hash)
		if src == nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid API key"})
			c.Abort()
			return
		}
		c.Set(logSourceCtxKey, src)
		c.Set("tenant_id", src.TenantID)
		c.Next()
	}
}

func logSourceFromContext(c *gin.Context) (*models.LogSource, bool) {
	v, ok := c.Get(logSourceCtxKey)
	if !ok {
		return nil, false
	}
	src, ok := v.(*models.LogSource)
	return src, ok
}

// ── body parsers ──────────────────────────────────────────────────────────────

// parseJSONBody handles a single JSON object {"message":"..."} or a JSON array
// of objects. Each object is re-serialised to a single-line string so the
// normaliser receives it as a JSON log message.
func parseJSONBody(body []byte) []string {
	body = bytes.TrimSpace(body)
	if len(body) == 0 {
		return nil
	}
	if body[0] == '[' {
		arr := []json.RawMessage{}
		if json.Unmarshal(body, &arr) != nil {
			return nil
		}
		out := make([]string, 0, len(arr))
		for _, raw := range arr {
			out = append(out, string(raw))
		}
		return out
	}
	return []string{string(body)}
}

// parseNDJSON handles newline-delimited JSON (one JSON object per line).
func parseNDJSON(body []byte) []string {
	out := []string{}
	scanner := bufio.NewScanner(bytes.NewReader(body))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			out = append(out, line)
		}
	}
	return out
}

// parseTextLines splits a plain-text body on newlines. Each line is one log
// message (syslog, CEF, LEEF, or arbitrary text).
func parseTextLines(body []byte) []string {
	out := []string{}
	scanner := bufio.NewScanner(bytes.NewReader(body))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.TrimSpace(line) != "" {
			out = append(out, line)
		}
	}
	return out
}

// autoDetect picks a parser based on the content of the body.
func autoDetect(body []byte) []string {
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 {
		return nil
	}
	if trimmed[0] == '[' || trimmed[0] == '{' {
		if trimmed[0] == '[' {
			return parseJSONBody(trimmed)
		}
		// Could be NDJSON (multiple objects) or single object.
		if bytes.Contains(trimmed, []byte("\n{")) {
			return parseNDJSON(trimmed)
		}
		return parseJSONBody(trimmed)
	}
	// CEF, LEEF, syslog, or raw text — treat each line as one event.
	return parseTextLines(trimmed)
}
