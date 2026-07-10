package services

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/segmentio/kafka-go"
)

// StartTaskConsumer reads from xcloak.agent_tasks and handles:
//   - task.dispatched  — increments AgentTasksPending gauge so Prometheus
//     reflects queued work immediately (not just on the 30s metrics refresh).
//   - task.completed   — decrements AgentTasksPending, pushes a WS notification
//     so the operator UI highlights the finished task in real time.
func StartTaskConsumer() {
	defer logRecover("StartTaskConsumer")
	if !kafkaEnabled {
		return
	}

	reader := kafka.NewReader(kafka.ReaderConfig{
		Brokers: kafkaBrokers,
		Topic:   TopicTasks,
		GroupID: "xcloak-task-consumer",
	})
	defer reader.Close()

	slog.Info("kafka: task consumer started", "topic", TopicTasks)

	for {
		msg, err := reader.ReadMessage(context.Background())
		KafkaTaskConsumerLag.Set(float64(reader.Stats().Lag))
		if err != nil {
			slog.Error("kafka: task consumer read error", "err", err)
			continue
		}
		processTaskEvent(msg.Value)
	}
}

func processTaskEvent(raw []byte) {
	defer logRecover("processTaskEvent")

	var envelope KafkaEvent
	if err := json.Unmarshal(raw, &envelope); err != nil {
		slog.Error("kafka: task consumer bad envelope", "err", err)
		return
	}
	var payload map[string]any
	if err := json.Unmarshal(envelope.Payload, &payload); err != nil {
		slog.Error("kafka: task consumer bad payload", "err", err)
		return
	}

	switch envelope.EventType {
	case "task.dispatched":
		AgentTasksPending.Inc()

	case "task.completed":
		AgentTasksPending.Dec()
		taskID := int(jsonFloat(payload, "task_id"))
		agentID := int(jsonFloat(payload, "agent_id"))
		taskType, _ := payload["task_type"].(string)
		result, _ := payload["result"].(string)
		PublishEventBroadcast(
			"task_completed",
			taskID,
			"info",
			taskType,
			agentID,
			fmt.Sprintf("Task %s completed: %s", taskType, truncate(result, 80)),
		)

	default:
		slog.Warn("kafka: task consumer unknown event_type", "event_type", envelope.EventType)
	}
}

// jsonFloat extracts a float64 from a decoded JSON map (JSON numbers unmarshal
// to float64 when the target is map[string]any).
func jsonFloat(m map[string]any, key string) float64 {
	v, _ := m[key].(float64)
	return v
}
