package services

import (
	"context"
	"encoding/json"
	"log/slog"
	"strings"

	"github.com/segmentio/kafka-go"

	"xcloak-ngfw/models"
	"xcloak-ngfw/repositories"
)

// criticalFIMPaths defines path prefixes for files that should trigger an
// automatic quarantine task when modified or deleted. These are high-value
// attacker targets: modifying /bin/* usually means a trojanised binary;
// modifying /etc/passwd or /etc/sudoers usually means privilege escalation.
var criticalFIMPaths = []string{
	"/bin/",
	"/sbin/",
	"/usr/bin/",
	"/usr/sbin/",
	"/usr/local/bin/",
	"/etc/passwd",
	"/etc/shadow",
	"/etc/sudoers",
	"/etc/sudoers.d/",
	"/etc/ssh/",
	"/etc/crontab",
	"/etc/cron.d/",
	"/etc/cron.daily/",
	"/etc/cron.weekly/",
	"/etc/ld.so.preload",
}

// StartFIMConsumer reads from xcloak.fim_alerts and auto-dispatches a
// quarantine_file task (pending_approval) for changes on critical system paths.
// The task goes through the approval queue (quarantine_file is a destructive
// action) so an analyst must review before the agent acts.
func StartFIMConsumer() {
	defer logRecover("StartFIMConsumer")
	if !kafkaEnabled {
		return
	}

	reader := kafka.NewReader(kafka.ReaderConfig{
		Brokers: kafkaBrokers,
		Topic:   TopicFIM,
		GroupID: "xcloak-fim-consumer",
	})
	defer reader.Close()

	slog.Info("kafka: FIM consumer started", "topic", TopicFIM)

	for {
		msg, err := reader.ReadMessage(context.Background())
		KafkaFIMConsumerLag.Set(float64(reader.Stats().Lag))
		if err != nil {
			slog.Error("kafka: FIM consumer read error", "err", err)
			continue
		}
		processFIMEvent(msg.Value)
	}
}

func processFIMEvent(raw []byte) {
	defer logRecover("processFIMEvent")

	var envelope KafkaEvent
	if err := json.Unmarshal(raw, &envelope); err != nil {
		slog.Error("kafka: FIM consumer bad envelope", "err", err)
		return
	}
	if envelope.EventType != "fim.violation" {
		return
	}
	var payload map[string]any
	if err := json.Unmarshal(envelope.Payload, &payload); err != nil {
		slog.Error("kafka: FIM consumer bad payload", "err", err)
		return
	}

	agentID := int(jsonFloat(payload, "agent_id"))
	path, _ := payload["path"].(string)
	changeType, _ := payload["change_type"].(string)

	if changeType == "created" || !isCriticalFIMPath(path) {
		return
	}

	slog.Info("kafka: FIM critical path violation — queuing quarantine task",
		"agent_id", agentID, "path", path, "change_type", changeType)

	taskPayload, _ := json.Marshal(map[string]any{"file_path": path})
	if err := repositories.CreateTaskPendingApproval(models.AgentTask{
		AgentID:  agentID,
		TaskType: "quarantine_file",
		Payload:  taskPayload,
	}); err != nil {
		slog.Error("kafka: FIM consumer failed to create quarantine task",
			"agent_id", agentID, "path", path, "err", err)
	}
}

func isCriticalFIMPath(path string) bool {
	for _, prefix := range criticalFIMPaths {
		if strings.HasPrefix(path, prefix) || path == prefix {
			return true
		}
	}
	return false
}
