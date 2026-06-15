package services

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/segmentio/kafka-go"
)

// ── Topic names ───────────────────────────────────────────────
const (
	TopicAlerts    = "xcloak.alerts"
	TopicIncidents = "xcloak.incidents"
	TopicTasks     = "xcloak.agent_tasks"
	TopicAudit     = "xcloak.audit"
	TopicFIM       = "xcloak.fim_alerts"
	TopicYARA      = "xcloak.yara_matches"
)

// KafkaEvent is the envelope written to every topic.
type KafkaEvent struct {
	Topic     string          `json:"topic"`
	EventType string          `json:"event_type"`
	Timestamp time.Time       `json:"timestamp"`
	Platform  string          `json:"platform"`
	Payload   json.RawMessage `json:"payload"`
}

var (
	kafkaWriters   = map[string]*kafka.Writer{}
	kafkaMu        sync.RWMutex
	kafkaEnabled   bool
	kafkaBrokers   []string
)

// InitKafka reads env vars and opens writers for all topics.
// Call once from main.go after env is loaded.
func InitKafka() {
	broker := os.Getenv("KAFKA_BROKER")
	if broker == "" {
		broker = "localhost:9092"
	}

	// Check if Kafka is enabled
	if os.Getenv("KAFKA_ENABLED") != "true" {
		fmt.Println("[Kafka] KAFKA_ENABLED != true — event bus disabled")
		return
	}

	kafkaBrokers = []string{broker}
	kafkaEnabled = true

	topics := []string{
		TopicAlerts, TopicIncidents, TopicTasks,
		TopicAudit, TopicFIM, TopicYARA,
	}

	kafkaMu.Lock()
	defer kafkaMu.Unlock()

	for _, topic := range topics {
		kafkaWriters[topic] = &kafka.Writer{
			Addr:                   kafka.TCP(kafkaBrokers...),
			Topic:                  topic,
			Balancer:               &kafka.LeastBytes{},
			WriteTimeout:           5 * time.Second,
			RequiredAcks:           kafka.RequireOne,
			AllowAutoTopicCreation: true,
		}
	}

	fmt.Printf("[Kafka] Connected to %s — topics: %v\n", broker, topics)
}

// CloseKafka flushes and closes all writers. Call from main defer.
func CloseKafka() {
	kafkaMu.Lock()
	defer kafkaMu.Unlock()
	for topic, w := range kafkaWriters {
		if err := w.Close(); err != nil {
			fmt.Printf("[Kafka] Close error on %s: %v\n", topic, err)
		}
	}
}

// publish sends an event to a Kafka topic asynchronously.
// Silently no-ops if Kafka is disabled.
func publish(topic, eventType string, payload any) {
	if !kafkaEnabled {
		return
	}

	go func() {
		payloadJSON, err := json.Marshal(payload)
		if err != nil {
			return
		}

		envelope := KafkaEvent{
			Topic:     topic,
			EventType: eventType,
			Timestamp: time.Now(),
			Platform:  "xcloak",
			Payload:   payloadJSON,
		}

		data, err := json.Marshal(envelope)
		if err != nil {
			return
		}

		kafkaMu.RLock()
		w, ok := kafkaWriters[topic]
		kafkaMu.RUnlock()
		if !ok {
			return
		}

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		err = w.WriteMessages(ctx, kafka.Message{
			Key:   []byte(eventType),
			Value: data,
		})
		if err != nil {
			fmt.Printf("[Kafka] Write error topic=%s event=%s: %v\n", topic, eventType, err)
		}
	}()
}

// ── Public publish functions — called from service layer ──────

// PublishAlert sends a new alert event to xcloak.alerts.
func PublishAlert(alert any) {
	publish(TopicAlerts, "alert.created", alert)
}

// PublishIncident sends a new incident event to xcloak.incidents.
func PublishIncident(incident any) {
	publish(TopicIncidents, "incident.created", incident)
}

// PublishTaskDispatched sends a task dispatch event to xcloak.agent_tasks.
func PublishTaskDispatched(task any) {
	publish(TopicTasks, "task.dispatched", task)
}

// PublishTaskCompleted sends a task completion event to xcloak.agent_tasks.
func PublishTaskCompleted(taskID int, agentID int, taskType, result string) {
	publish(TopicTasks, "task.completed", map[string]any{
		"task_id":   taskID,
		"agent_id":  agentID,
		"task_type": taskType,
		"result":    result,
	})
}

// PublishAuditEvent sends an audit log entry to xcloak.audit.
func PublishAuditEvent(action, details, username string) {
	publish(TopicAudit, "audit.logged", map[string]any{
		"action":   action,
		"details":  details,
		"username": username,
	})
}

// PublishFIMAlert sends a FIM violation to xcloak.fim_alerts.
func PublishFIMAlert(agentID int, path, changeType, hash string) {
	publish(TopicFIM, "fim.violation", map[string]any{
		"agent_id":    agentID,
		"path":        path,
		"change_type": changeType,
		"hash":        hash,
	})
}

// PublishYARAMatch sends a YARA match event to xcloak.yara_matches.
func PublishYARAMatch(agentID int, ruleName, filePath string) {
	publish(TopicYARA, "yara.match", map[string]any{
		"agent_id":  agentID,
		"rule_name": ruleName,
		"file_path": filePath,
	})
}

// IsKafkaEnabled returns true if Kafka is configured and running.
func IsKafkaEnabled() bool {
	return kafkaEnabled
}
