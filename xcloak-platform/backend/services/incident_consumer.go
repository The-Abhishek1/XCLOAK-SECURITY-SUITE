package services

import (
	"context"
	"encoding/json"
	"log/slog"

	"github.com/segmentio/kafka-go"

	"xcloak-platform/models"
)

// StartIncidentConsumer reads from xcloak.incidents and, for each new incident:
//   - Calls FireIncidentWebhook (webhook + Slack delivery). FireIncidentWebhook
//     was defined but never wired before this consumer existed.
//   - Broadcasts a real-time WS notification so dashboard panels refresh
//     without polling.
func StartIncidentConsumer() {
	defer logRecover("StartIncidentConsumer")
	if !kafkaEnabled {
		return
	}

	reader := kafka.NewReader(kafka.ReaderConfig{
		Brokers: kafkaBrokers,
		Topic:   TopicIncidents,
		GroupID: "xcloak-incident-consumer",
	})
	defer reader.Close()

	slog.Info("kafka: incident consumer started", "topic", TopicIncidents)

	for {
		msg, err := reader.ReadMessage(context.Background())
		KafkaIncidentConsumerLag.Set(float64(reader.Stats().Lag))
		if err != nil {
			slog.Error("kafka: incident consumer read error", "err", err)
			continue
		}
		processIncidentEvent(msg.Value)
	}
}

func processIncidentEvent(raw []byte) {
	defer logRecover("processIncidentEvent")

	var envelope KafkaEvent
	if err := json.Unmarshal(raw, &envelope); err != nil {
		slog.Error("kafka: incident consumer bad envelope", "err", err)
		return
	}
	if envelope.EventType != "incident.created" {
		return
	}
	var incident models.Incident
	if err := json.Unmarshal(envelope.Payload, &incident); err != nil {
		slog.Error("kafka: incident consumer bad payload", "err", err)
		return
	}

	FireIncidentWebhook(incident)
	PublishEventBroadcast(
		"incident",
		incident.ID,
		incident.Severity,
		incident.Title,
		incident.AgentID,
		"New incident: "+incident.Title,
	)
}
