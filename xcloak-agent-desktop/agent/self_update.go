package agent

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime"
	"strings"
	"time"

	"xcloak-agent-desktop/config"
)

// AgentReleasePublicKey is the ed25519 public key (base64url, no padding)
// used to verify agent release signatures. Set at build time via:
//
//	go build -ldflags "-X xcloak-agent-desktop/agent.AgentReleasePublicKey=<pubkey>"
//
// When empty, signature verification is skipped (development builds only).
var AgentReleasePublicKey string

const selfUpdateCheckInterval = 6 * time.Hour

type agentRelease struct {
	Version     string `json:"version"`
	SHA256      string `json:"sha256"`
	Signature   string `json:"signature"`    // base64url ed25519 over SHA-256 of binary
	DownloadURL string `json:"download_url"`
}

// StartSelfUpdateChecker periodically checks the server for a newer agent
// release for this platform and applies it. Disabled entirely via
// XCLOAK_DISABLE_SELF_UPDATE=true.
func StartSelfUpdateChecker() {
	if config.DisableSelfUpdate() {
		fmt.Println("[self-update] disabled via XCLOAK_DISABLE_SELF_UPDATE")
		return
	}
	go runCollector("self-update", selfUpdateCheckInterval, maxJitter, checkForUpdate)
}

// platformKey uses runtime.GOOS/GOARCH directly rather than the existing
// detectOS() (register.go) — that function only ever parses
// /etc/os-release and falls back to the literal string "Linux" on every
// other platform, so it would misreport Windows/macOS hosts as Linux here.
func platformKey() string {
	return runtime.GOOS + "_" + runtime.GOARCH
}

func checkForUpdate() {
	resp, err := authGet("/api/agent-releases/" + platformKey())
	if err != nil {
		fmt.Println("[self-update] check failed:", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return // nothing published for this platform yet
	}
	if resp.StatusCode != http.StatusOK {
		fmt.Println("[self-update] check returned status", resp.StatusCode)
		return
	}

	var rel agentRelease
	if err := json.NewDecoder(resp.Body).Decode(&rel); err != nil {
		fmt.Println("[self-update] could not parse release info:", err)
		return
	}

	if rel.Version == "" || rel.Version == CurrentVersion {
		return // already current
	}

	fmt.Printf("[self-update] new version available: %s (current: %s)\n", rel.Version, CurrentVersion)
	if err := applyUpdate(rel); err != nil {
		fmt.Println("[self-update] failed:", err)
	}
}

func applyUpdate(rel agentRelease) error {
	tmpPath, err := downloadToTemp(rel.DownloadURL)
	if err != nil {
		return fmt.Errorf("download: %w", err)
	}
	defer os.Remove(tmpPath) // no-op once replaceAndRestart successfully renames it away

	content, err := os.ReadFile(tmpPath)
	if err != nil {
		return fmt.Errorf("read downloaded binary: %w", err)
	}

	// ── SHA-256 integrity check ───────────────────────────────────────────
	sum := sha256Hex(content)
	if !strings.EqualFold(sum, rel.SHA256) {
		return fmt.Errorf("checksum mismatch (got %s, expected %s) — refusing to apply", sum, rel.SHA256)
	}

	// ── ed25519 signature verification ────────────────────────────────────
	if AgentReleasePublicKey != "" {
		if rel.Signature == "" {
			return fmt.Errorf("server provided no signature but this binary was built with signing required")
		}
		if err := verifyReleaseSignature(content, rel.Signature, AgentReleasePublicKey); err != nil {
			return fmt.Errorf("signature verification failed: %w", err)
		}
		fmt.Println("[self-update] signature verified OK")
	}

	if err := os.Chmod(tmpPath, 0755); err != nil {
		return fmt.Errorf("chmod downloaded binary: %w", err)
	}

	return replaceAndRestart(tmpPath, rel.Version)
}

func sha256Hex(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

func verifyReleaseSignature(content []byte, sigB64, pubKeyB64 string) error {
	pubKeyBytes, err := base64.RawURLEncoding.DecodeString(pubKeyB64)
	if err != nil {
		return fmt.Errorf("embedded public key: invalid base64url: %w", err)
	}
	if len(pubKeyBytes) != ed25519.PublicKeySize {
		return fmt.Errorf("embedded public key: expected 32 bytes, got %d", len(pubKeyBytes))
	}
	sigBytes, err := base64.RawURLEncoding.DecodeString(sigB64)
	if err != nil {
		return fmt.Errorf("release signature: invalid base64url: %w", err)
	}
	digest := sha256.Sum256(content)
	if !ed25519.Verify(pubKeyBytes, digest[:], sigBytes) {
		return fmt.Errorf("ed25519 signature does not match binary content")
	}
	return nil
}

func downloadToTemp(url string) (string, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", err
	}

	resp, err := Client().Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("download returned status %d", resp.StatusCode)
	}

	tmp, err := os.CreateTemp("", "xcloak-agent-desktop-update-*")
	if err != nil {
		return "", err
	}
	defer tmp.Close()

	if _, err := io.Copy(tmp, resp.Body); err != nil {
		os.Remove(tmp.Name())
		return "", err
	}

	return tmp.Name(), nil
}

// fileSHA256 is retained for use by copyExecutableFile callers.
func fileSHA256(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return sha256Hex(data), nil
}

// copyExecutableFile is used by self_update_linux.go to keep a backup of
// the currently-running binary before replacing it — named distinctly from
// restore_file.go's copyFile, which writes 0644 (fine for quarantined
// non-executable evidence, wrong for a binary backup that should stay
// runnable for a manual rollback).
func copyExecutableFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, in)
	return err
}
