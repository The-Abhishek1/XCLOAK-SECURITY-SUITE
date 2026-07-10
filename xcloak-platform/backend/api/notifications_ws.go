package api

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"

	"xcloak-platform/models"
	"xcloak-platform/services"
)

// notifHub manages all connected browser WebSocket clients.
// When a new critical/high alert fires, BroadcastAlert() pushes it to all clients.
var notifHub = &NotificationHub{
	clients: make(map[*notifClient]bool),
}

type NotificationHub struct {
	mu      sync.RWMutex
	clients map[*notifClient]bool
}

type notifClient struct {
	conn *websocket.Conn
	send chan []byte
}

type NotifPayload struct {
	Type      string    `json:"type"`     // "alert" | "incident" | "ping"
	ID        int       `json:"id"`
	Severity  string    `json:"severity"`
	RuleName  string    `json:"rule_name"`
	AgentID   int       `json:"agent_id"`
	Message   string    `json:"message"`
	Timestamp time.Time `json:"timestamp"`
}

// BroadcastAlert is called by alert_service.go when a new alert is created.
// It publishes to Redis so all replicas deliver the alert to their local clients.
// With Redis unavailable it falls back to local-only delivery.
func BroadcastAlert(alert models.Alert) {
	services.PublishAlertBroadcast(alert)
}

// BroadcastRaw delivers an already-marshalled payload to all WebSocket clients
// connected to THIS replica. Registered with services.RegisterLocalBroadcastFn
// so the Redis subscriber loop can call back into the hub without an import cycle.
//
// Two payload shapes are accepted:
//   - Pre-built NotifPayload (has a non-empty "type" field) — broadcast directly.
//     Used by Kafka consumers for incident/task/fim/yara events.
//   - Raw models.Alert JSON (no "type" field) — wrapped into a NotifPayload{Type:"alert"}.
func BroadcastRaw(data []byte) {
	var probe struct {
		Type string `json:"type"`
	}
	if json.Unmarshal(data, &probe) == nil && probe.Type != "" {
		notifHub.broadcast(data)
		return
	}

	var alert models.Alert
	if err := json.Unmarshal(data, &alert); err != nil {
		return
	}
	payload := NotifPayload{
		Type:      "alert",
		ID:        alert.ID,
		Severity:  alert.Severity,
		RuleName:  alert.RuleName,
		AgentID:   alert.AgentID,
		Message:   alert.LogMessage,
		Timestamp: time.Now(),
	}
	out, _ := json.Marshal(payload)
	notifHub.broadcast(out)
}

func (h *NotificationHub) broadcast(data []byte) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	for c := range h.clients {
		select {
		case c.send <- data:
		default:
			// Client too slow — skip this message
		}
	}
}

func (h *NotificationHub) register(c *notifClient) {
	h.mu.Lock()
	h.clients[c] = true
	h.mu.Unlock()
}

func (h *NotificationHub) unregister(c *notifClient) {
	h.mu.Lock()
	delete(h.clients, c)
	h.mu.Unlock()
	close(c.send)
}

var notifUpgrader = websocket.Upgrader{
	CheckOrigin:     func(r *http.Request) bool { return true },
	ReadBufferSize:  256,
	WriteBufferSize: 1024,
}

// NotificationsWS — GET /api/notifications/stream?ticket=<uuid>
// Browser connects here to receive real-time alert pushes.
// Auth: same ticket scheme as LiveLogsWS — see that handler for rationale.
func NotificationsWS(c *gin.Context) {

	ticket := c.Query("ticket")
	if ticket == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "missing ws ticket"})
		return
	}
	if _, err := services.ConsumeWSTicket(ticket); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid or expired ws ticket"})
		return
	}

	conn, err := notifUpgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		slog.Error("notifications-ws: upgrade failed", "err", err)
		return
	}

	client := &notifClient{
		conn: conn,
		send: make(chan []byte, 32),
	}

	notifHub.register(client)
	defer notifHub.unregister(client)

	// Send welcome ping.
	ping, _ := json.Marshal(NotifPayload{Type: "ping", Timestamp: time.Now()})
	client.send <- ping

	// Write pump.
	ping20 := time.NewTicker(20 * time.Second)
	defer ping20.Stop()

	done := make(chan struct{})

	// Read pump (detect disconnect).
	go func() {
		defer close(done)
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				return
			}
		}
	}()

	for {
		select {
		case <-done:
			return
		case <-ping20.C:
			p, _ := json.Marshal(NotifPayload{Type: "ping"})
			if err := conn.WriteMessage(websocket.TextMessage, p); err != nil {
				return
			}
		case msg, ok := <-client.send:
			if !ok {
				return
			}
			if err := conn.WriteMessage(websocket.TextMessage, msg); err != nil {
				return
			}
		}
	}
}
