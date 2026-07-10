package agent

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"

	"xcloak-agent-desktop/config"
	"golang.org/x/term"
)

// ErrInvalidToken is returned when the install token is missing or rejected by the server.
// Callers should switch to interactive prompting instead of retrying.
var ErrInvalidToken = errors.New("invalid install token")

type registrationResponse struct {
	AgentID int    `json:"agent_id"`
	Message string `json:"message"`
	Token   string `json:"token"`
}

// Register tries the install token from config (env var / .env file).
// Returns ErrInvalidToken if no token is configured or the server rejects it (401).
// Returns a network/server error for everything else.
func Register() (int, error) {
	installToken := config.InstallToken()
	if installToken == "" {
		return 0, ErrInvalidToken
	}
	return sendRegistration(installToken)
}

// RegisterInteractive prompts the user to paste an install token, up to maxAttempts times.
// Each rejected token shows a clear error before offering another try.
// Non-auth errors (network, server down) are returned immediately without burning attempts.
func RegisterInteractive(maxAttempts int) (int, error) {
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return 0, fmt.Errorf(
			"stdin is not a terminal — cannot prompt for install token\n" +
				"  Set XCLOAK_INSTALL_TOKEN in .env, or run the agent directly (not piped)",
		)
	}

	fmt.Println()
	fmt.Println("┌─────────────────────────────────────────────────────┐")
	fmt.Println("│         XCloak Agent — Install Token Required       │")
	fmt.Println("├─────────────────────────────────────────────────────┤")
	fmt.Println("│  Generate one in the XCloak UI:                     │")
	fmt.Println("│  Agents → Add Agent → Generate Token                │")
	fmt.Println("└─────────────────────────────────────────────────────┘")

	reader := bufio.NewReader(os.Stdin)

	for attempt := 1; attempt <= maxAttempts; attempt++ {
		fmt.Printf("\nPaste install token [%d/%d]: ", attempt, maxAttempts)
		token, _ := reader.ReadString('\n')
		token = strings.TrimSpace(token)

		if token == "" {
			fmt.Println("✗ No token entered.")
			if attempt < maxAttempts {
				continue
			}
			return 0, fmt.Errorf("no token provided — generate one at XCloak UI → Agents → Add Agent")
		}

		fmt.Println("  Verifying with server...")
		id, err := sendRegistration(token)
		if err == nil {
			return id, nil
		}
		if errors.Is(err, ErrInvalidToken) {
			remaining := maxAttempts - attempt
			if remaining > 0 {
				fmt.Printf("✗ Token rejected (invalid, expired, or already used). %d attempt(s) remaining.\n", remaining)
				continue
			}
			return 0, fmt.Errorf("token rejected after %d attempt(s) — generate a fresh token at XCloak UI → Agents → Add Agent", maxAttempts)
		}
		// Network / server error — don't burn remaining attempts on something the user can't fix
		return 0, err
	}
	return 0, fmt.Errorf("max attempts reached")
}

// sendRegistration performs the HTTP registration call with the given install token.
func sendRegistration(installToken string) (int, error) {
	hostname, _ := os.Hostname()
	machineID := deriveMachineID(hostname)

	data := struct {
		MachineID    string `json:"machine_id"`
		Hostname     string `json:"hostname"`
		OS           string `json:"os"`
		IPAddress    string `json:"ip_address"`
		InstallToken string `json:"install_token"`
	}{
		MachineID:    machineID,
		Hostname:     hostname,
		OS:           detectOS(),
		IPAddress:    getLocalIP(),
		InstallToken: installToken,
	}

	body, err := json.Marshal(data)
	if err != nil {
		return 0, fmt.Errorf("failed to encode registration request: %w", err)
	}

	req, err := http.NewRequest("POST", config.ServerURL()+"/api/agents/register", bytes.NewBuffer(body))
	if err != nil {
		return 0, fmt.Errorf("register request failed: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := Client().Do(req)
	if err != nil {
		return 0, fmt.Errorf("register request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == 401 {
		return 0, ErrInvalidToken
	}
	if resp.StatusCode != 200 {
		return 0, fmt.Errorf("register returned HTTP %d", resp.StatusCode)
	}

	var result registrationResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return 0, fmt.Errorf("failed to decode register response: %w", err)
	}
	if result.AgentID == 0 {
		return 0, fmt.Errorf("server returned agent_id=0")
	}

	if result.Token != "" {
		SaveToken(result.Token)
		fmt.Println("✓ Agent token saved")
	}

	fmt.Printf("✓ Registered as agent #%d (hostname: %s)\n", result.AgentID, hostname)
	return result.AgentID, nil
}

func deriveMachineID(hostname string) string {
	h := sha256.Sum256([]byte(hostname))
	return hex.EncodeToString(h[:])
}

func detectOS() string {
	data, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return "Linux"
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "PRETTY_NAME=") {
			return strings.Trim(strings.TrimPrefix(line, "PRETTY_NAME="), `"`)
		}
	}
	return "Linux"
}

func getLocalIP() string {
	conn, err := net.Dial("udp", "1.1.1.1:80")
	if err != nil {
		return "127.0.0.1"
	}
	defer conn.Close()

	addr, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok {
		return "127.0.0.1"
	}
	return addr.IP.String()
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
