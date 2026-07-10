package agent

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"

	"xcloak-agent-desktop/config"
	"golang.org/x/term"
)

type registrationResponse struct {
	AgentID int    `json:"agent_id"`
	Message string `json:"message"`
	Token   string `json:"token"`
}

func Register() (int, error) {

	hostname, _ := os.Hostname()
	machineID := deriveMachineID(hostname)

	// ── Get install token ─────────────────────────────────────
	// Priority: env var → interactive prompt
	installToken := config.InstallToken()
	if installToken == "" {
		installToken = promptInstallToken()
	}
	if installToken == "" {
		return 0, fmt.Errorf(
			"install token required\n" +
				"  Generate one: XCloak UI → Agents → Add Agent → Generate Token",
		)
	}

	// ── Send registration request ─────────────────────────────
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
		return 0, fmt.Errorf(
			"registration rejected (401) — token may be invalid, expired, or already used\n" +
				"  Generate a new one: XCloak UI → Agents → Add Agent",
		)
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

// promptInstallToken prints a friendly prompt and reads the token from stdin.
// Returns empty string if stdin is not an interactive terminal.
func promptInstallToken() string {
	// Check if stdin is a real terminal — not a pipe or non-interactive shell
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		fmt.Println("[agent] stdin is not a terminal — cannot prompt for install token.")
		fmt.Println("[agent] Set XCLOAK_INSTALL_TOKEN env var or run interactively.")
		return ""
	}

	fmt.Println()
	fmt.Println("┌─────────────────────────────────────────────────────┐")
	fmt.Println("│         XCloak Agent — First Time Setup             │")
	fmt.Println("├─────────────────────────────────────────────────────┤")
	fmt.Println("│  An install token is required to register this      │")
	fmt.Println("│  agent with the XCloak server.                      │")
	fmt.Println("│                                                      │")
	fmt.Println("│  Generate one in the XCloak UI:                     │")
	fmt.Println("│  Agents page → Add Agent → Generate Token           │")
	fmt.Println("└─────────────────────────────────────────────────────┘")
	fmt.Println()
	fmt.Print("Paste install token: ")

	reader := bufio.NewReader(os.Stdin)
	token, _ := reader.ReadString('\n')
	token = strings.TrimSpace(token)

	if token == "" {
		fmt.Println("No token entered.")
		return ""
	}

	fmt.Println("✓ Token received, connecting to server...")
	return token
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

// getLocalIP returns the local IP this host would use to reach the network
// (no packet is actually sent — UDP "connect" just picks a route/interface).
// Falls back to 127.0.0.1 only if the host has no usable network route,
// e.g. fully offline.
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
