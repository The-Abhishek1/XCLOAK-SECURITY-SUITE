package agent

import (
	"os"
	"strings"
)

const tokenFile = "/tmp/xcloak-agent.token"

// SaveToken persists the bearer token to a temp file so it survives
// between poll iterations (the agent is a long-running process, so an
// in-memory variable would also work, but a file lets us inspect it
// for debugging and survives a goroutine restart).
func SaveToken(token string) {
	os.WriteFile(tokenFile, []byte(strings.TrimSpace(token)), 0600)
}

// LoadToken reads the saved token. Returns empty string if not found.
func LoadToken() string {
	data, err := os.ReadFile(tokenFile)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}
