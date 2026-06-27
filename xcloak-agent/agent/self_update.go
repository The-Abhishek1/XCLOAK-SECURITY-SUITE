package agent

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime"
	"strings"
	"time"

	"xcloak-agent/config"
)

const selfUpdateCheckInterval = 6 * time.Hour

type agentRelease struct {
	Version     string `json:"version"`
	SHA256      string `json:"sha256"`
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

	sum, err := fileSHA256(tmpPath)
	if err != nil {
		return fmt.Errorf("hash downloaded binary: %w", err)
	}
	if !strings.EqualFold(sum, rel.SHA256) {
		return fmt.Errorf("checksum mismatch (got %s, server published %s) — refusing to apply", sum, rel.SHA256)
	}

	if err := os.Chmod(tmpPath, 0755); err != nil {
		return fmt.Errorf("chmod downloaded binary: %w", err)
	}

	return replaceAndRestart(tmpPath, rel.Version)
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

	tmp, err := os.CreateTemp("", "xcloak-agent-update-*")
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

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
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
