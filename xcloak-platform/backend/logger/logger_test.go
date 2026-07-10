package logger

import (
	"log/slog"
	"os"
	"testing"
)

func TestParseLevel(t *testing.T) {
	tests := []struct {
		input string
		want  slog.Level
	}{
		{"debug", slog.LevelDebug},
		{"DEBUG", slog.LevelDebug},
		{"warn", slog.LevelWarn},
		{"warning", slog.LevelWarn},
		{"WARN", slog.LevelWarn},
		{"WARNING", slog.LevelWarn},
		{"error", slog.LevelError},
		{"ERROR", slog.LevelError},
		{"info", slog.LevelInfo},
		{"INFO", slog.LevelInfo},
		{"", slog.LevelInfo},
		{"unknown", slog.LevelInfo},
		{"trace", slog.LevelInfo},
	}

	for _, tc := range tests {
		got := parseLevel(tc.input)
		if got != tc.want {
			t.Errorf("parseLevel(%q) = %v, want %v", tc.input, got, tc.want)
		}
	}
}

func TestInit_TextFormat(t *testing.T) {
	os.Setenv("LOG_FORMAT", "text")
	os.Setenv("LOG_LEVEL", "debug")
	defer os.Unsetenv("LOG_FORMAT")
	defer os.Unsetenv("LOG_LEVEL")
	Init() // must not panic
	slog.Info("test logger init text")
}

func TestInit_JSONFormat(t *testing.T) {
	os.Setenv("LOG_FORMAT", "json")
	os.Setenv("LOG_LEVEL", "warn")
	defer os.Unsetenv("LOG_FORMAT")
	defer os.Unsetenv("LOG_LEVEL")
	Init()
	slog.Warn("test logger init json")
}

func TestInit_DefaultFormat(t *testing.T) {
	os.Unsetenv("LOG_FORMAT")
	os.Unsetenv("LOG_LEVEL")
	Init()
	slog.Info("test logger init default")
}
