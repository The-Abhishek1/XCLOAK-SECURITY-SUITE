package services

// Redis pub/sub broadcaster for real-time WebSocket alerts.
//
// Problem: with multiple API replicas, each replica only holds a subset of
// all connected browser WebSocket clients. An alert created on replica A
// would only notify clients connected to A; clients on replicas B and C
// would see nothing until their next poll.
//
// Solution: every alert publish goes to a Redis channel. Each replica
// subscribes to that channel and forwards every message to its local
// in-process hub. All clients across all replicas receive the alert.
//
// The broadcastLocalFn is injected from api/notifications_ws.go to avoid
// import cycles (services → api is forbidden).

import (
	"context"
	"encoding/json"
	"log/slog"

	"xcloak-ngfw/models"
)

const wsBroadcastChannel = "xcloak:ws:alerts"

// broadcastLocalFn delivers an already-marshalled payload to all WebSocket
// clients connected to THIS replica. Injected from api/notifications_ws.go.
var broadcastLocalFn func([]byte)

// RegisterLocalBroadcastFn is called once from main.go (or api init) to wire
// the in-process hub's send path into the Redis subscriber loop.
func RegisterLocalBroadcastFn(fn func([]byte)) {
	broadcastLocalFn = fn
}

// PublishAlertBroadcast publishes a new-alert notification to the Redis channel
// so that ALL replicas forward it to their local WebSocket clients.
// Called by alert_service.go's broadcastFn (the old RegisterBroadcastFn
// callback now delegates here instead of calling api.BroadcastAlert directly).
func PublishAlertBroadcast(alert models.Alert) {
	if RDB == nil {
		// Redis not available — fall back to local-only broadcast.
		if broadcastLocalFn != nil {
			data, _ := json.Marshal(alert)
			broadcastLocalFn(data)
		}
		return
	}

	data, err := json.Marshal(alert)
	if err != nil {
		return
	}
	if err := RDB.Publish(context.Background(), wsBroadcastChannel, data).Err(); err != nil {
		slog.Warn("ws broadcast: Redis publish failed, falling back to local", "err", err)
		if broadcastLocalFn != nil {
			broadcastLocalFn(data)
		}
	}
}

// StartWSBroadcastSubscriber subscribes to the Redis alert channel and calls
// broadcastLocalFn for every message received. Runs in a goroutine for the
// lifetime of the process. Call once from main.go after InitRedis().
func StartWSBroadcastSubscriber() {
	if RDB == nil {
		slog.Warn("ws broadcast: Redis unavailable, multi-replica broadcast disabled")
		return
	}

	go func() {
		ctx := context.Background()
		sub := RDB.Subscribe(ctx, wsBroadcastChannel)
		defer sub.Close()

		ch := sub.Channel()
		for msg := range ch {
			if broadcastLocalFn == nil {
				continue
			}
			broadcastLocalFn([]byte(msg.Payload))
		}
	}()
}
