package agent

import (
	"bytes"
	"net/http"

	"xcloak-agent/config"
)

// authPost is a drop-in replacement for http.Post that attaches the agent's
// saved bearer token. Use this for ALL agent->server data submission endpoints
// (processes, connections, services, packages, users, logs, file, quarantine),
// since these routes now require RequireAgentAuth() on the backend.
//
// Usage:
//   OLD: http.Post(config.ServerURL+"/api/agents/packages", "application/json", bytes.NewBuffer(body))
//   NEW: authPost("/api/agents/packages", body)
func authPost(path string, body []byte) (*http.Response, error) {

	req, err := http.NewRequest(
		"POST",
		config.ServerURL+path,
		bytes.NewBuffer(body),
	)

	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+LoadToken())

	return http.DefaultClient.Do(req)
}
