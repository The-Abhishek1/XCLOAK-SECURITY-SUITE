package config

import (
	"bufio"
	"os"
	"strings"
)

func init() {
	// Load .env file from current directory if it exists.
	// This lets the agent be configured without exporting env vars.
	loadDotEnv(".env")
}

// ServerURL is the backend base URL. Despite build_windows.sh's deployment
// instructions already telling Windows users to `setx SERVER_URL ...`
// before running the agent, this was never actually read anywhere — every
// agent silently kept hitting its own localhost regardless of this env var,
// so it only ever worked when co-located with the backend. Falls back to
// that original hardcoded default if unset.
func ServerURL() string {
	if v := os.Getenv("SERVER_URL"); v != "" {
		return v
	}
	return "http://localhost:8080"
}

// CACertPath optionally points at a PEM file for a private CA the backend's
// TLS cert chains to (e.g. a self-signed cert) — lets the agent verify it
// without disabling verification entirely.
func CACertPath() string {
	return os.Getenv("XCLOAK_CA_CERT_PATH")
}

// DisableSelfUpdate opts an agent out of the periodic self-update checker
// entirely — e.g. for a host where binary updates must go through a
// separate change-control process instead of being pulled automatically.
func DisableSelfUpdate() bool {
	return os.Getenv("XCLOAK_DISABLE_SELF_UPDATE") == "true"
}

// InsecureSkipVerify disables TLS certificate verification. Off by default;
// named loudly so it isn't reached for casually — only for development
// against a self-signed cert with no CA bundle handy.
func InsecureSkipVerify() bool {
	return os.Getenv("XCLOAK_INSECURE_SKIP_VERIFY") == "true"
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
