package services

// license_checker.go — runs in self-hosted deployments.
//
// Phones home to the license authority (your server at api.xcloak.tech) every
// 24 h. When enforcement is off the server returns immediately so there's zero
// friction. When enforcement is on, a valid XCLOAK_LICENSE_KEY is required.
//
// Skip phone-home by leaving LICENSE_SERVER_URL empty (your own server should
// always leave it empty — you ARE the authority).
//
// Grace period: 30 days from the first failed check before limits kick in.

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"log/slog"
)

const (
	defaultLicenseServerURL  = "https://api.xcloak.tech"
	licenseCheckInterval     = 24 * time.Hour
	licenseCheckTimeout      = 15 * time.Second
	defaultGraceDays         = 30
)

var (
	licenseCheckState struct {
		mu          sync.RWMutex
		enforcement bool
		valid       bool
		claim       *LicenseClaim
		lastChecked time.Time
		firstFailed time.Time
	}
	checkerStarted atomic.Bool
)

// StartLicenseChecker launches the background phone-home loop.
// Safe to call multiple times; only the first call starts the goroutine.
func StartLicenseChecker() {
	serverURL := os.Getenv("LICENSE_SERVER_URL")
	if serverURL == "" {
		serverURL = defaultLicenseServerURL
	}

	// Skip entirely when this IS the license authority.
	if os.Getenv("SKIP_LICENSE_CHECK") == "true" || serverURL == "" {
		slog.Info("LicenseChecker: skipped (this is the license authority)")
		return
	}

	if !checkerStarted.CompareAndSwap(false, true) {
		return
	}

	go func() {
		runCheck(serverURL)
		t := time.NewTicker(licenseCheckInterval)
		defer t.Stop()
		for range t.C {
			runCheck(serverURL)
		}
	}()
}

// LicenseStatus returns the current cached validation state.
// Callers can use this to apply tier limits without blocking on network.
func LicenseStatus() (enforcement bool, valid bool, claim *LicenseClaim) {
	licenseCheckState.mu.RLock()
	defer licenseCheckState.mu.RUnlock()
	return licenseCheckState.enforcement, licenseCheckState.valid, licenseCheckState.claim
}

// InGracePeriod returns true when enforcement is on but the instance has been
// failing validation for less than the grace period.
func InGracePeriod() bool {
	licenseCheckState.mu.RLock()
	defer licenseCheckState.mu.RUnlock()
	s := licenseCheckState
	if !s.enforcement || s.valid {
		return false
	}
	if s.firstFailed.IsZero() {
		return true
	}
	return time.Since(s.firstFailed) < time.Duration(defaultGraceDays)*24*time.Hour
}

func runCheck(serverURL string) {
	key := os.Getenv("XCLOAK_LICENSE_KEY")
	payload, _ := json.Marshal(map[string]string{"key": key})

	client := &http.Client{Timeout: licenseCheckTimeout}
	resp, err := client.Post(serverURL+"/api/license/check", "application/json", bytes.NewReader(payload))
	if err != nil {
		slog.Warn("LicenseChecker: phone-home failed", "err", err)
		setCheckFailed()
		return
	}
	defer resp.Body.Close()

	var result LicenseCheckResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		slog.Warn("LicenseChecker: bad response", "err", err)
		setCheckFailed()
		return
	}

	licenseCheckState.mu.Lock()
	defer licenseCheckState.mu.Unlock()
	licenseCheckState.enforcement = result.Enforcement
	licenseCheckState.valid = result.Valid
	licenseCheckState.claim = result.Claim
	licenseCheckState.lastChecked = time.Now()
	if result.Enforcement && !result.Valid {
		if licenseCheckState.firstFailed.IsZero() {
			licenseCheckState.firstFailed = time.Now()
		}
	} else {
		licenseCheckState.firstFailed = time.Time{}
	}

	if !result.Enforcement {
		slog.Debug("LicenseChecker: enforcement off — full access")
	} else if result.Valid {
		slog.Info("LicenseChecker: license valid", "tier", result.Claim.Tier, "expires", result.Claim.ExpiresAt.Format("2006-01-02"))
	} else {
		slog.Warn("LicenseChecker: license invalid", "message", result.Message)
	}
}

func setCheckFailed() {
	licenseCheckState.mu.Lock()
	defer licenseCheckState.mu.Unlock()
	if licenseCheckState.firstFailed.IsZero() {
		licenseCheckState.firstFailed = time.Now()
	}
}
