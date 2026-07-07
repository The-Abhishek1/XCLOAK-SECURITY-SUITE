package api

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"

	"xcloak-ngfw/database"
	"xcloak-ngfw/services"
)

var wsUpgrader = websocket.Upgrader{
	CheckOrigin:     func(r *http.Request) bool { return true }, // CORS handled by main.go middleware
	ReadBufferSize:  1024,
	WriteBufferSize: 4096,
}

type wsLogEntry struct {
	ID           int    `json:"id"`
	Source       string `json:"source"`
	Message      string `json:"message"`
	TS           string `json:"ts"`
	ParsedFields string `json:"parsed_fields,omitempty"`
}

// LiveLogsWS — GET /api/agents/:id/logs/stream?ticket=<uuid>
// WebSocket endpoint for live log streaming.
// Sends last 50 historical logs on connect, then streams new entries every 2s.
// Automatically dispatches a collect_auth_logs task if endpoint_logs is empty.
//
// Auth: caller must first POST /api/ws/ticket (via the Next.js proxy, so the
// httpOnly session cookie is included) to obtain a short-lived single-use
// ticket, then pass it as ?ticket= on this URL. We can't use the session
// cookie here because WS connections bypass the proxy and go directly to the
// backend port, putting them on a different origin from the cookie.
func LiveLogsWS(c *gin.Context) {

	agentID := c.Param("id")
	agentIDInt, err := strconv.Atoi(agentID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid agent id"})
		return
	}

	// Validate the single-use ticket and populate auth context so the normal
	// tenant-scoped helpers (agentOwnedBy404, etc.) work unchanged.
	ticket := c.Query("ticket")
	if ticket == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "missing ws ticket"})
		return
	}
	claims, err := services.ConsumeWSTicket(ticket)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid or expired ws ticket"})
		return
	}
	c.Set("tenant_id", claims.TenantID)
	c.Set("user_id",   claims.UserID)
	c.Set("username",  claims.Username)
	c.Set("role",      claims.Role)

	// Verify the agent belongs to the caller's tenant before upgrading.
	if !agentOwnedBy404(c, agentID) {
		return
	}

	conn, err := wsUpgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		slog.Error("live-logs: WS upgrade failed", "err", err)
		return
	}
	defer conn.Close()

	// Send connect confirmation.
	conn.WriteJSON(map[string]string{"type": "connected", "agent_id": agentID})

	// Check if there are any logs; if not, auto-dispatch collect_auth_logs.
	var logCount int
	if err := database.DB.QueryRow(`SELECT COUNT(*) FROM endpoint_logs WHERE agent_id = $1`, agentID).Scan(&logCount); err != nil {
		slog.Error("live-logs: log count query failed", "agent_id", agentID, "err", err)
	}

	if logCount == 0 {
		services.CreateTaskForAgent(agentIDInt, "collect_auth_logs")
		conn.WriteJSON(map[string]string{
			"type":    "info",
			"message": "No logs yet — dispatched collect_auth_logs task to agent. Logs will appear shortly.",
		})
	}

	// Send last 50 historical logs immediately.
	var lastID int
	histRows, err := database.DB.Query(`
		SELECT id, log_source, log_message, COALESCE(parsed_fields::text, '{}')
		FROM endpoint_logs
		WHERE agent_id = $1
		ORDER BY id DESC
		LIMIT 50
	`, agentID)

	if err == nil {
		var hist []wsLogEntry
		for histRows.Next() {
			var e wsLogEntry
			if scanErr := histRows.Scan(&e.ID, &e.Source, &e.Message, &e.ParsedFields); scanErr == nil {
				e.TS = time.Now().Format(time.RFC3339)
				hist = append(hist, e)
			}
		}
		histRows.Close()

		// Send oldest-first.
		for i := len(hist) - 1; i >= 0; i-- {
			conn.WriteJSON(hist[i])
			if hist[i].ID > lastID {
				lastID = hist[i].ID
			}
		}
	}

	// Poll for new logs every 2s, heartbeat every 20s.
	logTicker  := time.NewTicker(2 * time.Second)
	pingTicker := time.NewTicker(20 * time.Second)
	defer logTicker.Stop()
	defer pingTicker.Stop()

	// Read pump — detect client disconnect.
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			_, _, err := conn.ReadMessage()
			if err != nil {
				return
			}
		}
	}()

	for {
		select {

		case <-done:
			return

		case <-pingTicker.C:
			if err := conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}

		case <-logTicker.C:
			rows, err := database.DB.Query(`
				SELECT id, log_source, log_message, COALESCE(parsed_fields::text, '{}')
				FROM endpoint_logs
				WHERE agent_id = $1 AND id > $2
				ORDER BY id ASC
				LIMIT 50
			`, agentID, lastID)

			if err != nil {
				continue
			}

			for rows.Next() {
				var e wsLogEntry
				if scanErr := rows.Scan(&e.ID, &e.Source, &e.Message, &e.ParsedFields); scanErr == nil {
					e.TS = time.Now().Format(time.RFC3339)
					if err := conn.WriteJSON(e); err != nil {
						rows.Close()
						return
					}
					lastID = e.ID
				}
			}
			rows.Close()
		}
	}
}

// suppress unused
var _ = json.Marshal
