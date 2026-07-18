package services

// License key system — dual-mode monetization infrastructure.
//
// LICENSE_MODE (the enforcement toggle):
//   - OFF (default): zero enforcement, full access for everyone.
//     Self-hosted users enjoy the full product.
//   - ON: self-hosted instances must present a valid license key.
//     Flip this on your server; all phoning-home instances see it immediately.
//
// License key format: xlk_v1.<base64url(json_claim)>.<base64url(ed25519_sig)>
// Signing key: LICENSE_SIGNING_KEY env var (base64url 32-byte ed25519 seed).
// Falls back to AGENT_RELEASE_SIGNING_KEY so a fresh deployment needs only one key.

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"xcloak-platform/database"
	"xcloak-platform/repositories"
)

// licenseEnforced is the in-process cache of the LICENSE_MODE flag.
// 0 = off (free for all), 1 = on (license required for self-hosted instances).
var licenseEnforced atomic.Int32

// InitLicenseMode loads the effective LICENSE_MODE on startup.
// Env var takes precedence; DB setting is the fallback so the UI toggle persists
// without a restart.
func InitLicenseMode() {
	env := os.Getenv("LICENSE_MODE")
	if env == "true" {
		licenseEnforced.Store(1)
		return
	}
	if env == "false" {
		licenseEnforced.Store(0)
		return
	}
	if repositories.GetSystemConfig("license_mode") == "true" {
		licenseEnforced.Store(1)
	}
}

// LicenseModeEnabled reports whether license enforcement is active.
func LicenseModeEnabled() bool {
	return licenseEnforced.Load() == 1
}

// SetLicenseMode updates the in-process flag and persists to DB.
func SetLicenseMode(on bool) error {
	val := "false"
	if on {
		val = "true"
		licenseEnforced.Store(1)
	} else {
		licenseEnforced.Store(0)
	}
	return repositories.SetSystemConfig("license_mode", val)
}

// LicenseClaim is the payload embedded in an issued license key token.
type LicenseClaim struct {
	KeyID        string    `json:"key_id"`
	CustomerName string    `json:"customer_name"`
	Tier         string    `json:"tier"`
	AgentLimit   int       `json:"agent_limit"`
	UserLimit    int       `json:"user_limit"`
	IssuedAt     time.Time `json:"issued_at"`
	ExpiresAt    time.Time `json:"expires_at"`
}

// LicenseKeyRecord is a row from the license_keys table.
type LicenseKeyRecord struct {
	ID            int        `json:"id"`
	KeyID         string     `json:"key_id"`
	CustomerName  string     `json:"customer_name"`
	CustomerEmail string     `json:"customer_email"`
	Tier          string     `json:"tier"`
	AgentLimit    int        `json:"agent_limit"`
	UserLimit     int        `json:"user_limit"`
	ExpiresAt     time.Time  `json:"expires_at"`
	RevokedAt     *time.Time `json:"revoked_at"`
	RevokeReason  *string    `json:"revoke_reason"`
	Notes         *string    `json:"notes"`
	CreatedBy     string     `json:"created_by"`
	CreatedAt     time.Time  `json:"created_at"`
	Token         string     `json:"token,omitempty"` // only populated on creation
}

// LicenseCheckResponse is returned by the public /api/license/check endpoint,
// which self-hosted instances call on startup and every 24 h.
type LicenseCheckResponse struct {
	Enforcement bool          `json:"enforcement"`
	Valid       bool          `json:"valid"`
	Claim       *LicenseClaim `json:"claim,omitempty"`
	Message     string        `json:"message"`
	GraceDays   int           `json:"grace_days"`
}

const licenseKeyPrefix = "xlk_v1."

// GenerateLicenseKey creates a signed license token and stores its metadata.
func GenerateLicenseKey(customerName, customerEmail, tier string, agentLimit, userLimit int, expiresAt time.Time, notes, createdBy string) (*LicenseKeyRecord, error) {
	keyID := newKeyID()
	claim := LicenseClaim{
		KeyID:        keyID,
		CustomerName: customerName,
		Tier:         tier,
		AgentLimit:   agentLimit,
		UserLimit:    userLimit,
		IssuedAt:     time.Now().UTC(),
		ExpiresAt:    expiresAt.UTC(),
	}

	token, err := signLicenseClaim(claim)
	if err != nil {
		return nil, fmt.Errorf("sign license: %w", err)
	}

	rec := &LicenseKeyRecord{
		KeyID:         keyID,
		CustomerName:  customerName,
		CustomerEmail: customerEmail,
		Tier:          tier,
		AgentLimit:    agentLimit,
		UserLimit:     userLimit,
		ExpiresAt:     expiresAt,
		CreatedBy:     createdBy,
		Token:         token,
	}
	if notes != "" {
		rec.Notes = &notes
	}
	if err := insertLicenseKey(rec); err != nil {
		return nil, err
	}
	return rec, nil
}

// ValidateLicenseToken verifies a token's signature and returns the claim if
// the token is structurally valid and not expired. Revocation is checked
// separately by the caller via CheckLicense (which has DB access).
func ValidateLicenseToken(token string) (*LicenseClaim, error) {
	if !strings.HasPrefix(token, licenseKeyPrefix) {
		return nil, errors.New("invalid license key format")
	}
	rest := strings.TrimPrefix(token, licenseKeyPrefix)
	parts := strings.SplitN(rest, ".", 2)
	if len(parts) != 2 {
		return nil, errors.New("malformed license key")
	}

	claimBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, errors.New("license key: cannot decode claim")
	}
	sigBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, errors.New("license key: cannot decode signature")
	}

	pubKeyBytes, err := licensePublicKey()
	if err != nil {
		return nil, fmt.Errorf("license public key not configured: %w", err)
	}

	digest := sha256.Sum256(claimBytes)
	if !ed25519.Verify(pubKeyBytes, digest[:], sigBytes) {
		return nil, errors.New("license key signature verification failed")
	}

	var claim LicenseClaim
	if err := json.Unmarshal(claimBytes, &claim); err != nil {
		return nil, errors.New("license key: invalid claim payload")
	}
	if time.Now().After(claim.ExpiresAt) {
		return nil, fmt.Errorf("license key expired on %s", claim.ExpiresAt.Format("2006-01-02"))
	}
	return &claim, nil
}

// CheckLicense is called by the public endpoint. It combines enforcement
// status with optional token validation + revocation check.
func CheckLicense(token string) LicenseCheckResponse {
	enforcement := LicenseModeEnabled()
	if !enforcement {
		return LicenseCheckResponse{
			Enforcement: false,
			Valid:        false,
			Message:      "License enforcement is not yet active. Full access granted.",
			GraceDays:    0,
		}
	}

	if token == "" {
		return LicenseCheckResponse{
			Enforcement: true,
			Valid:        false,
			Message:      "No license key provided. Set XCLOAK_LICENSE_KEY in your environment.",
			GraceDays:    30,
		}
	}

	claim, err := ValidateLicenseToken(token)
	if err != nil {
		return LicenseCheckResponse{
			Enforcement: true,
			Valid:        false,
			Message:      err.Error(),
			GraceDays:    30,
		}
	}

	// Check revocation.
	if isRevoked(claim.KeyID) {
		return LicenseCheckResponse{
			Enforcement: true,
			Valid:        false,
			Message:      "License key has been revoked. Contact support.",
			GraceDays:    0,
		}
	}

	return LicenseCheckResponse{
		Enforcement: true,
		Valid:        true,
		Claim:        claim,
		Message:      "License valid.",
		GraceDays:    0,
	}
}

// ListLicenseKeys returns all issued license records (admin view).
func ListLicenseKeys() ([]LicenseKeyRecord, error) {
	rows, err := database.DB.Query(`
		SELECT id, key_id, customer_name, customer_email, tier,
		       agent_limit, user_limit, expires_at, revoked_at,
		       revoke_reason, notes, created_by, created_at
		FROM license_keys ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []LicenseKeyRecord{}
	for rows.Next() {
		var r LicenseKeyRecord
		if err := rows.Scan(&r.ID, &r.KeyID, &r.CustomerName, &r.CustomerEmail,
			&r.Tier, &r.AgentLimit, &r.UserLimit, &r.ExpiresAt,
			&r.RevokedAt, &r.RevokeReason, &r.Notes, &r.CreatedBy, &r.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	if out == nil {
		out = []LicenseKeyRecord{}
	}
	return out, rows.Err()
}

// RevokeLicenseKey marks a key as revoked so CheckLicense rejects it.
func RevokeLicenseKey(keyID, reason string) error {
	res, err := database.DB.Exec(`
		UPDATE license_keys SET revoked_at = NOW(), revoke_reason = $1
		WHERE key_id = $2 AND revoked_at IS NULL`, reason, keyID)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return errors.New("license key not found or already revoked")
	}
	return nil
}

// RegenerateLicenseToken re-signs the claim stored for the given key_id.
// Use this if the customer loses their key.
func RegenerateLicenseToken(keyID string) (string, error) {
	var r LicenseKeyRecord
	err := database.DB.QueryRow(`
		SELECT key_id, customer_name, tier, agent_limit, user_limit, expires_at, revoked_at
		FROM license_keys WHERE key_id = $1`, keyID).
		Scan(&r.KeyID, &r.CustomerName, &r.Tier, &r.AgentLimit, &r.UserLimit, &r.ExpiresAt, &r.RevokedAt)
	if err != nil {
		return "", errors.New("license key not found")
	}
	if r.RevokedAt != nil {
		return "", errors.New("license key is revoked")
	}
	claim := LicenseClaim{
		KeyID:        r.KeyID,
		CustomerName: r.CustomerName,
		Tier:         r.Tier,
		AgentLimit:   r.AgentLimit,
		UserLimit:    r.UserLimit,
		IssuedAt:     r.CreatedAt,
		ExpiresAt:    r.ExpiresAt,
	}
	return signLicenseClaim(claim)
}

// ── helpers ───────────────────────────────────────────────────────────────────

func signLicenseClaim(claim LicenseClaim) (string, error) {
	privKeyBytes, err := licensePrivateKey()
	if err != nil {
		return "", err
	}
	privKey := ed25519.NewKeyFromSeed(privKeyBytes)

	claimBytes, err := json.Marshal(claim)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(claimBytes)
	sig := ed25519.Sign(privKey, digest[:])

	return licenseKeyPrefix +
		base64.RawURLEncoding.EncodeToString(claimBytes) + "." +
		base64.RawURLEncoding.EncodeToString(sig), nil
}

func licensePrivateKey() ([]byte, error) {
	k := os.Getenv("LICENSE_SIGNING_KEY")
	if k == "" {
		k = os.Getenv("AGENT_RELEASE_SIGNING_KEY") // fall back for simple setups
	}
	if k == "" {
		return nil, errors.New("LICENSE_SIGNING_KEY not set")
	}
	b, err := base64.RawURLEncoding.DecodeString(k)
	if err != nil || len(b) != ed25519.SeedSize {
		return nil, errors.New("LICENSE_SIGNING_KEY must be a 32-byte ed25519 seed, base64url")
	}
	return b, nil
}

func licensePublicKey() ([]byte, error) {
	// Try explicit public key first, then derive from the seed.
	pub := os.Getenv("LICENSE_PUBLIC_KEY")
	if pub == "" {
		pub = os.Getenv("AGENT_RELEASE_PUBLIC_KEY")
	}
	if pub != "" {
		b, err := base64.RawURLEncoding.DecodeString(pub)
		if err != nil || len(b) != ed25519.PublicKeySize {
			return nil, errors.New("LICENSE_PUBLIC_KEY must be 32 bytes, base64url")
		}
		return b, nil
	}
	// Derive from seed.
	seed, err := licensePrivateKey()
	if err != nil {
		return nil, err
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub32 := priv.Public().(ed25519.PublicKey)
	return []byte(pub32), nil
}

func isRevoked(keyID string) bool {
	var revokedAt *time.Time
	database.DB.QueryRow(`SELECT revoked_at FROM license_keys WHERE key_id = $1`, keyID).Scan(&revokedAt)
	return revokedAt != nil
}

func insertLicenseKey(r *LicenseKeyRecord) error {
	return database.DB.QueryRow(`
		INSERT INTO license_keys (key_id, customer_name, customer_email, tier,
		    agent_limit, user_limit, expires_at, notes, created_by)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
		RETURNING id, created_at`,
		r.KeyID, r.CustomerName, r.CustomerEmail, r.Tier,
		r.AgentLimit, r.UserLimit, r.ExpiresAt, r.Notes, r.CreatedBy).
		Scan(&r.ID, &r.CreatedAt)
}

func newKeyID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return "lic_" + base64.RawURLEncoding.EncodeToString(b)
}
