package agent

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// tokenPath returns a persistent path for the agent token.
// Uses ~/.config/xcloak-agent-desktop/token — survives reboots.
func tokenPath() string {
	// Prefer XDG config dir
	configDir := os.Getenv("XDG_CONFIG_HOME")
	if configDir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			// Fallback to /etc if no home dir (running as root service)
			return "/etc/xcloak-agent-desktop/token"
		}
		configDir = filepath.Join(home, ".config")
	}
	return filepath.Join(configDir, "xcloak-agent-desktop", "token")
}

func SaveToken(token string) {
	path := tokenPath()
	// Ensure directory exists
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		fmt.Printf("[agent] Warning: could not create token dir: %v\n", err)
		return
	}
	if err := os.WriteFile(path, []byte(strings.TrimSpace(token)), 0600); err != nil {
		fmt.Printf("[agent] Warning: could not save token: %v\n", err)
		return
	}
	fmt.Printf("[agent] Token saved to %s\n", path)
}

func LoadToken() string {
	data, err := os.ReadFile(tokenPath())
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

func ClearToken() {
	path := tokenPath()
	os.Remove(path)
	fmt.Printf("[agent] Cleared saved token at %s\n", path)
}
