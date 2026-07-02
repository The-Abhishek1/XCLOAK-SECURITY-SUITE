package services

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/segmentio/kafka-go"
)

// ── Topic names ───────────────────────────────────────────────
const (
	TopicAlerts       = "xcloak.alerts"
	TopicIncidents    = "xcloak.incidents"
	TopicTasks        = "xcloak.agent_tasks"
	TopicAudit        = "xcloak.audit"
	TopicFIM          = "xcloak.fim_alerts"
	TopicYARA         = "xcloak.yara_matches"
	TopicIOCMatchJobs = "xcloak.ioc_match_jobs"
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
	kafkaWriters = map[string]*kafka.Writer{}
	kafkaMu      sync.RWMutex
	kafkaEnabled bool
	kafkaBrokers []string
)

// InitKafka reads env vars and opens writers for all topics.
// Call once from main.go after env is loaded.
//
// Production hardening:
//   KAFKA_BROKERS — comma-separated broker list (3 for HA; single allowed)
//   KAFKA_REQUIRE_ALL_ACKS=true — use RequireAll (wait for min.insync.replicas)
//     instead of RequireOne; set alongside min.insync.replicas=2 on the broker
func InitKafka() {
	if os.Getenv("KAFKA_ENABLED") != "true" {
		slog.Info("Kafka: disabled (KAFKA_ENABLED != true)")
		return
	}

	// Support comma-separated broker list for 3-node clusters.
	brokersEnv := os.Getenv("KAFKA_BROKERS")
	if brokersEnv == "" {
		brokersEnv = os.Getenv("KAFKA_BROKER") // backwards compat
	}
	if brokersEnv == "" {
		brokersEnv = "localhost:9092"
	}
	for _, b := range strings.Split(brokersEnv, ",") {
		if b = strings.TrimSpace(b); b != "" {
			kafkaBrokers = append(kafkaBrokers, b)
		}
	}

	// RequireAll blocks until all in-sync replicas have acknowledged.
	// Required when min.insync.replicas=2 is set on the cluster.
	acks := kafka.RequireOne
	if os.Getenv("KAFKA_REQUIRE_ALL_ACKS") == "true" {
		acks = kafka.RequireAll
	}

	kafkaEnabled = true

	topics := []string{
		TopicAlerts, TopicIncidents, TopicTasks,
		TopicAudit, TopicFIM, TopicYARA, TopicIOCMatchJobs,
	}

	kafkaMu.Lock()
	defer kafkaMu.Unlock()

	for _, topic := range topics {
		kafkaWriters[topic] = &kafka.Writer{
			Addr:                   kafka.TCP(kafkaBrokers...),
			Topic:                  topic,
			Balancer:               &kafka.LeastBytes{},
			WriteTimeout:           10 * time.Second,
			RequiredAcks:           acks,
			AllowAutoTopicCreation: true,
			// Async batching: improves throughput for high-volume topics.
			// Batch size and flush interval are intentionally conservative;
			// tune KAFKA_BATCH_BYTES and KAFKA_BATCH_TIMEOUT for the cluster.
			BatchSize:    100,
			BatchTimeout: 10 * time.Millisecond,
		}
	}

	slog.Info("Kafka: connected", "brokers", kafkaBrokers, "acks", acks)
}

// CloseKafka flushes and closes all writers. Call from main defer.
func CloseKafka() {
	kafkaMu.Lock()
	defer kafkaMu.Unlock()
	for topic, w := range kafkaWriters {
		if err := w.Close(); err != nil {
			slog.Warn("kafka: close error", "topic", topic, "err", err)
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
			slog.Warn("kafka: write error", "topic", topic, "event_type", eventType, "err", err)
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

// PublishFileHashMatchJob queues a file hash for async IOC matching
// (consumed by StartIOCMatchConsumer) instead of matching it inline on the
// ingest request path.
func PublishFileHashMatchJob(hash any) {
	publish(TopicIOCMatchJobs, "filehash", hash)
}

// PublishConnectionMatchJob queues a connection for async IOC matching.
func PublishConnectionMatchJob(conn any) {
	publish(TopicIOCMatchJobs, "connection", conn)
}

// IsKafkaEnabled returns true if Kafka is configured and running.
func IsKafkaEnabled() bool {
	return kafkaEnabled
}
