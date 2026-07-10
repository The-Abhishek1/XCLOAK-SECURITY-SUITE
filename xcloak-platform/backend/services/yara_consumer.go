package services

import (
	"context"
	"encoding/json"
	"log/slog"

	"github.com/segmentio/kafka-go"

	"xcloak-platform/models"
	"xcloak-platform/repositories"
)

// StartYARAConsumer reads from xcloak.yara_matches and auto-dispatches a
// quarantine_file task (pending_approval) for the matched file. YARA matches
// are high-confidence detections — placing the matched file in quarantine
// prevents further execution/access while an analyst reviews the hit.
//
// The task goes through the approval queue (quarantine_file is a destructive
// action per task_expiry.go) so it is NOT dispatched to the agent until an
// admin approves it.
func StartYARAConsumer() {
	defer logRecover("StartYARAConsumer")
	if !kafkaEnabled {
		return
	}

	reader := kafka.NewReader(kafka.ReaderConfig{
		Brokers: kafkaBrokers,
		Topic:   TopicYARA,
		GroupID: "xcloak-yara-consumer",
	})
	defer reader.Close()

	slog.Info("kafka: YARA consumer started", "topic", TopicYARA)

	for {
		msg, err := reader.ReadMessage(context.Background())
		KafkaYARAConsumerLag.Set(float64(reader.Stats().Lag))
		if err != nil {
			slog.Error("kafka: YARA consumer read error", "err", err)
			continue
		}
		processYARAEvent(msg.Value)
	}
}

func processYARAEvent(raw []byte) {
	defer logRecover("processYARAEvent")

	var envelope KafkaEvent
	if err := json.Unmarshal(raw, &envelope); err != nil {
		slog.Error("kafka: YARA consumer bad envelope", "err", err)
		return
	}
	if envelope.EventType != "yara.match" {
		return
	}
	var payload map[string]any
	if err := json.Unmarshal(envelope.Payload, &payload); err != nil {
		slog.Error("kafka: YARA consumer bad payload", "err", err)
		return
	}

	agentID := int(jsonFloat(payload, "agent_id"))
	ruleName, _ := payload["rule_name"].(string)
	filePath, _ := payload["file_path"].(string)

	if filePath == "" {
		return
	}

	slog.Info("kafka: YARA match — queuing quarantine task",
		"agent_id", agentID, "rule", ruleName, "file", filePath)

	taskPayload, _ := json.Marshal(map[string]any{"file_path": filePath})
	if err := repositories.CreateTaskPendingApproval(models.AgentTask{
		AgentID:  agentID,
		TaskType: "quarantine_file",
		Payload:  taskPayload,
	}); err != nil {
		slog.Error("kafka: YARA consumer failed to create quarantine task",
			"agent_id", agentID, "file", filePath, "err", err)
	}
}
