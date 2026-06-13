package agent

import (
	"os"
	"strings"
)

const tokenPath = "./agent.token"

func LoadToken() string {

	b, err := os.ReadFile(tokenPath)
	if err != nil {
		return ""
	}

	return strings.TrimSpace(string(b))
}

func SaveToken(token string) error {
	return os.WriteFile(tokenPath, []byte(token), 0600)
}
