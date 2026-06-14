package api

import (
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"

	"xcloak-ngfw/database"
)

// LiveLogsSSE streams new log entries to the browser via Server-Sent Events.
// GET /api/agents/:id/logs/stream
//
// The client connects and receives log lines as they arrive.
// Uses long-polling over SSE so it works without WebSocket infra.
func LiveLogsSSE(c *gin.Context) {

	agentID := c.Param("id")
	if _, err := strconv.Atoi(agentID); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid agent id"})
		return
	}

	// SSE headers.
	c.Header("Content-Type", "text/event-stream")
	c.Header("Cache-Control", "no-cache")
	c.Header("Connection", "keep-alive")
	c.Header("X-Accel-Buffering", "no") // nginx: disable proxy buffering

	flusher, ok := c.Writer.(http.Flusher)
	if !ok {
		c.JSON(500, gin.H{"error": "streaming unsupported"})
		return
	}

	// Send a heartbeat comment every 15s to keep the connection alive.
	ticker  := time.NewTicker(15 * time.Second)
	logPoll := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	defer logPoll.Stop()

	// Track the last log ID we've sent so we only send new ones.
	var lastID int
	database.DB.QueryRow(`
		SELECT COALESCE(MAX(id), 0) FROM endpoint_logs WHERE agent_id = $1
	`, agentID).Scan(&lastID)

	ctx := c.Request.Context()

	for {
		select {

		case <-ctx.Done():
			return

		case <-ticker.C:
			fmt.Fprintf(c.Writer, ": heartbeat\n\n")
			flusher.Flush()

		case <-logPoll.C:
			rows, err := database.DB.Query(`
				SELECT id, log_source, log_message
				FROM endpoint_logs
				WHERE agent_id = $1 AND id > $2
				ORDER BY id ASC
				LIMIT 50
			`, agentID, lastID)

			if err != nil {
				continue
			}

			for rows.Next() {
				var id int
				var source, message string
				if err := rows.Scan(&id, &source, &message); err == nil {
					// Escape newlines so SSE data field stays on one line.
					safe := escapeSSE(message)
					fmt.Fprintf(c.Writer, "data: {\"id\":%d,\"source\":%q,\"message\":%q}\n\n",
						id, source, safe)
					lastID = id
				}
			}
			rows.Close()
			flusher.Flush()
		}
	}
}

func escapeSSE(s string) string {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			out = append(out, '\\', 'n')
		} else if s[i] == '\r' {
			// skip
		} else {
			out = append(out, s[i])
		}
	}
	return string(out)
}
