package config

import (
	"bufio"
	"os"
	"strings"
)

const ServerURL = "http://localhost:8080"

func init() {
	// Load .env file from current directory if it exists.
	// This lets the agent be configured without exporting env vars.
	loadDotEnv(".env")
}

func loadDotEnv(path string) {
	f, err := os.Open(path)
	if err != nil {
		return // no .env file is fine
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		val := strings.TrimSpace(parts[1])
		// Only set if not already set in environment
		if os.Getenv(key) == "" {
			os.Setenv(key, val)
		}
	}
}

// InstallToken returns the one-time install token for first registration.
// Loaded from XCLOAK_INSTALL_TOKEN env var or .env file.
func InstallToken() string {
	return os.Getenv("XCLOAK_INSTALL_TOKEN")
}
