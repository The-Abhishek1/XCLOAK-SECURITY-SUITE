package agent

import (
	"log/slog"
	"os"
	"strings"
)

// InitLogger configures the default slog handler based on environment.
// LOG_FORMAT=json → JSON handler (production).
// LOG_LEVEL sets the minimum level (debug/info/warn/error, default: info).
func InitLogger() {
	level := slog.LevelInfo
	if v := strings.ToLower(os.Getenv("LOG_LEVEL")); v != "" {
		switch v {
		case "debug":
			level = slog.LevelDebug
		case "warn":
			level = slog.LevelWarn
		case "error":
			level = slog.LevelError
		}
	}

	opts := &slog.HandlerOptions{Level: level}
	var h slog.Handler
	if strings.ToLower(os.Getenv("LOG_FORMAT")) == "json" {
		h = slog.NewJSONHandler(os.Stderr, opts)
	} else {
		h = slog.NewTextHandler(os.Stderr, opts)
	}
	slog.SetDefault(slog.New(h))
}
