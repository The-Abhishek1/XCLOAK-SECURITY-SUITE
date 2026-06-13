package agent

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
)

// AuthClient is an HTTP client that attaches the agent's bearer token
// to every request. All agent senders should use this instead of http.Post.
type AuthClient struct {
	Token     string
	ServerURL string
}

// Post sends a JSON POST with Bearer auth.
func (c *AuthClient) Post(path string, payload any) (*http.Response, error) {

	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal error: %w", err)
	}

	req, err := http.NewRequest("POST", c.ServerURL+path, bytes.NewBuffer(body))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.Token)

	return http.DefaultClient.Do(req)
}

// Get sends an authenticated GET request.
func (c *AuthClient) Get(path string) (*http.Response, error) {

	req, err := http.NewRequest("GET", c.ServerURL+path, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+c.Token)

	return http.DefaultClient.Do(req)
}
