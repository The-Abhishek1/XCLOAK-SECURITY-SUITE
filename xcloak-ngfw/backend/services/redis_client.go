package services

import (
	"context"
	"os"

	"github.com/redis/go-redis/v9"

	"xcloak-ngfw/secrets"
)

// RDB is the shared Redis client used for state that must survive a backend
// restart and stay consistent across replicas (rate limiting, token
// revocation). Defaults to localhost:6379 for local dev.
var RDB *redis.Client

var ctx = context.Background()

func InitRedis() {
	addr := os.Getenv("REDIS_ADDR")
	if addr == "" {
		addr = "localhost:6379"
	}

	RDB = redis.NewClient(&redis.Options{
		Addr:     addr,
		Password: secrets.Resolve("REDIS_PASSWORD", "xcloak/backend", "redis_password"),
	})
}
