package api

import (
	"encoding/json"
	"fmt"
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
	ID      int    `json:"id"`
	Source  string `json:"source"`
	Message string `json:"message"`
	TS      string `json:"ts"`
}

// LiveLogsWS — GET /api/agents/:id/logs/stream
// WebSocket endpoint for live log streaming.
// Sends last 50 historical logs on connect, then streams new entries every 2s.
// Automatically dispatches a collect_auth_logs task if endpoint_logs is empty.
func LiveLogsWS(c *gin.Context) {

	agentID := c.Param("id")
	agentIDInt, err := strconv.Atoi(agentID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid agent id"})
		return
	}

	conn, err := wsUpgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		fmt.Printf("WS upgrade failed: %v\n", err)
		return
	}
	defer conn.Close()

	// Send connect confirmation.
	conn.WriteJSON(map[string]string{"type": "connected", "agent_id": agentID})

	// Check if there are any logs; if not, auto-dispatch collect_auth_logs.
	var logCount int
	database.DB.QueryRow(`SELECT COUNT(*) FROM endpoint_logs WHERE agent_id = $1`, agentID).Scan(&logCount)

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
		SELECT id, log_source, log_message
		FROM endpoint_logs
		WHERE agent_id = $1
		ORDER BY id DESC
		LIMIT 50
	`, agentID)

	if err == nil {
		var hist []wsLogEntry
		for histRows.Next() {
			var e wsLogEntry
			if scanErr := histRows.Scan(&e.ID, &e.Source, &e.Message); scanErr == nil {
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
				var e wsLogEntry
				if scanErr := rows.Scan(&e.ID, &e.Source, &e.Message); scanErr == nil {
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
