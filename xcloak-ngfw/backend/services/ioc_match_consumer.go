package services

import (
	"context"
	"encoding/json"
	"fmt"

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
	if !kafkaEnabled {
		return
	}

	reader := kafka.NewReader(kafka.ReaderConfig{
		Brokers: kafkaBrokers,
		Topic:   TopicIOCMatchJobs,
		GroupID: "xcloak-ioc-matcher",
	})
	defer reader.Close()

	fmt.Println("[Kafka] IOC match consumer started — topic:", TopicIOCMatchJobs)

	for {
		msg, err := reader.ReadMessage(context.Background())
		KafkaIOCConsumerLag.Set(float64(reader.Stats().Lag))
		if err != nil {
			fmt.Println("[Kafka] IOC match consumer read error:", err)
			continue
		}

		var envelope KafkaEvent
		if err := json.Unmarshal(msg.Value, &envelope); err != nil {
			fmt.Println("[Kafka] IOC match consumer: bad envelope:", err)
			continue
		}

		switch envelope.EventType {

		case "filehash":
			var hash models.FileHash
			if err := json.Unmarshal(envelope.Payload, &hash); err != nil {
				fmt.Println("[Kafka] IOC match consumer: bad filehash payload:", err)
				continue
			}
			CheckFileHashIOC(hash)

		case "connection":
			var conn models.Connection
			if err := json.Unmarshal(envelope.Payload, &conn); err != nil {
				fmt.Println("[Kafka] IOC match consumer: bad connection payload:", err)
				continue
			}
			CheckConnectionIOC(conn)

		default:
			fmt.Println("[Kafka] IOC match consumer: unknown event_type:", envelope.EventType)
		}
	}
}
