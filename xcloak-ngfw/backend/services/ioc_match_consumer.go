package services

import (
	"context"
	"encoding/json"
	"log/slog"

	"github.com/segmentio/kafka-go"

	"xcloak-ngfw/models"
)

// StartIOCMatchConsumer reads file hash / connection IOC-matching jobs off
// xcloak.ioc_match_jobs and runs the same matching logic that used to run
// inline on the ingest request path (CheckFileHashIOC / CheckConnectionIOC).
// This moves O(hashes × IOCs) and O(connections × IOCs) work off the
// request/response cycle so ingest latency stays flat as the IOC list and
// fleet size grow. No-ops if Kafka isn't enabled — callers fall back to
// synchronous matching in that case (see SaveFileHashes / SaveConnections).
func StartIOCMatchConsumer() {
	defer logRecover("StartIOCMatchConsumer")
	if !kafkaEnabled {
		return
	}

	reader := kafka.NewReader(kafka.ReaderConfig{
		Brokers: kafkaBrokers,
		Topic:   TopicIOCMatchJobs,
		GroupID: "xcloak-ioc-matcher",
	})
	defer reader.Close()

	slog.Info("kafka: IOC match consumer started", "topic", TopicIOCMatchJobs)

	for {
		msg, err := reader.ReadMessage(context.Background())
		KafkaIOCConsumerLag.Set(float64(reader.Stats().Lag))
		if err != nil {
			slog.Error("kafka: IOC consumer read error", "err", err)
			continue
		}
		processIOCMatchEvent(msg.Value)
	}
}

func processIOCMatchEvent(raw []byte) {
	defer logRecover("processIOCMatchEvent")

	var envelope KafkaEvent
	if err := json.Unmarshal(raw, &envelope); err != nil {
		slog.Error("kafka: IOC consumer bad envelope", "err", err)
		return
	}

	switch envelope.EventType {
	case "filehash":
		var hash models.FileHash
		if err := json.Unmarshal(envelope.Payload, &hash); err != nil {
			slog.Error("kafka: IOC consumer bad filehash payload", "err", err)
			return
		}
		CheckFileHashIOC(hash)

	case "connection":
		var conn models.Connection
		if err := json.Unmarshal(envelope.Payload, &conn); err != nil {
			slog.Error("kafka: IOC consumer bad connection payload", "err", err)
			return
		}
		CheckConnectionIOC(conn)

	default:
		slog.Warn("kafka: IOC consumer unknown event_type", "event_type", envelope.EventType)
	}
}
