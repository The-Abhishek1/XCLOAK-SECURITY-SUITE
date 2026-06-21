package agent

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sync"

	"xcloak-agent/config"
)

// Client is the shared HTTP client every agent->server request goes
// through, built once with whatever TLS trust config the operator set
// (XCLOAK_CA_CERT_PATH / XCLOAK_INSECURE_SKIP_VERIFY) — replaces the
// scattered http.DefaultClient.Do / ad-hoc &http.Client{} call sites that
// previously had no TLS configuration at all.
var (
	clientOnce sync.Once
	sharedClient *http.Client
)

func Client() *http.Client {
	clientOnce.Do(func() {
		tlsConfig := &tls.Config{
			InsecureSkipVerify: config.InsecureSkipVerify(),
		}

		if caPath := config.CACertPath(); caPath != "" {
			if pemBytes, err := os.ReadFile(caPath); err == nil {
				pool := x509.NewCertPool()
				if pool.AppendCertsFromPEM(pemBytes) {
					tlsConfig.RootCAs = pool
				} else {
					fmt.Println("[agent] XCLOAK_CA_CERT_PATH did not contain a valid PEM certificate — ignoring")
				}
			} else {
				fmt.Printf("[agent] failed to read XCLOAK_CA_CERT_PATH (%s): %v\n", caPath, err)
			}
		}

		sharedClient = &http.Client{
			Transport: &http.Transport{TLSClientConfig: tlsConfig},
		}
	})
	return sharedClient
}

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

	return Client().Do(req)
}

// Get sends an authenticated GET request.
func (c *AuthClient) Get(path string) (*http.Response, error) {

	req, err := http.NewRequest("GET", c.ServerURL+path, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+c.Token)

	return Client().Do(req)
}
