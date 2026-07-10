package services

import (
	"context"
	"encoding/json"
	"log/slog"

	"github.com/segmentio/kafka-go"

	"xcloak-platform/models"
)

// StartAlertConsumer reads from xcloak.alerts and, for each new alert:
//   - Indexes the alert into Elasticsearch (xcloak-alerts-<tenantID>) so it is
//     searchable independently of endpoint logs.
//
// The actual WS broadcast and webhook delivery are already triggered
// synchronously inside CreateAlert → alert_service.go, so they are NOT
// repeated here — this consumer owns only the async ES write path.
func StartAlertConsumer() {
	defer logRecover("StartAlertConsumer")
	if !kafkaEnabled {
		return
	}

	reader := kafka.NewReader(kafka.ReaderConfig{
		Brokers: kafkaBrokers,
		Topic:   TopicAlerts,
		GroupID: "xcloak-alert-consumer",
	})
	defer reader.Close()

	slog.Info("kafka: alert consumer started", "topic", TopicAlerts)

	for {
		msg, err := reader.ReadMessage(context.Background())
		KafkaAlertConsumerLag.Set(float64(reader.Stats().Lag))
		if err != nil {
			slog.Error("kafka: alert consumer read error", "err", err)
			continue
		}
		processAlertEvent(msg.Value)
	}
}

func processAlertEvent(raw []byte) {
	defer logRecover("processAlertEvent")

	var envelope KafkaEvent
	if err := json.Unmarshal(raw, &envelope); err != nil {
		slog.Error("kafka: alert consumer bad envelope", "err", err)
		return
	}
	if envelope.EventType != "alert.created" {
		return
	}
	var alert models.Alert
	if err := json.Unmarshal(envelope.Payload, &alert); err != nil {
		slog.Error("kafka: alert consumer bad payload", "err", err)
		return
	}
	IndexAlertToES(alert)
}
