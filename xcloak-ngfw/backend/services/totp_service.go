package services

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // G505: SHA1 is mandated by the TOTP/HOTP specs (RFC 6238/RFC 4226)
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"math"
	"strings"
	"time"

	"xcloak-ngfw/secrets"
)

// TOTPTransitKey is the Vault transit key users.totp_secret is encrypted
// under. Created idempotently at startup — see secrets.EnsureTransitKey.
const TOTPTransitKey = "xcloak-totp"

// EncryptTOTPSecret wraps a freshly generated TOTP secret for storage.
// Returns it unchanged (plaintext) if Vault is disabled — same behavior
// the column had before Vault support existed.
func EncryptTOTPSecret(secret string) (string, error) {
	if !secrets.Enabled() {
		return secret, nil
	}
	return secrets.TransitEncrypt(TOTPTransitKey, secret)
}

// DecryptTOTPSecret reverses EncryptTOTPSecret. A stored value without the
// "vault:" envelope prefix is assumed to be a pre-Vault plaintext secret (or
// Vault is disabled) and is returned as-is — so existing 2FA enrollments
// keep working across a Vault rollout without forcing every user to
// re-enroll the moment Vault gets turned on.
func DecryptTOTPSecret(stored string) (string, error) {
	if !strings.HasPrefix(stored, "vault:") {
		return stored, nil
	}
	return secrets.TransitDecrypt(TOTPTransitKey, stored)
}

// GenerateTOTPSecret generates a random base32 secret for TOTP.
func GenerateTOTPSecret() (string, error) {
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base32.StdEncoding.EncodeToString(b), nil
}

// GenerateTOTPQRURL returns an otpauth:// URL for QR code generation.
// The frontend renders this as a QR code for Google Authenticator / Authy.
func GenerateTOTPQRURL(username, secret string) string {
	issuer := "XCloak"
	secret = strings.TrimRight(secret, "=")
	return fmt.Sprintf(
		"otpauth://totp/%s:%s?secret=%s&issuer=%s&algorithm=SHA1&digits=6&period=30",
		issuer, username, secret, issuer,
	)
}

// ValidateTOTP checks if the 6-digit code is valid for the given secret.
// Allows a 1-window drift (±30s) to account for clock skew.
func ValidateTOTP(secret, code string) bool {
	// Normalise secret — remove spaces, uppercase
	secret = strings.ToUpper(strings.ReplaceAll(secret, " ", ""))
	// Pad to multiple of 8
	if r := len(secret) % 8; r != 0 {
		secret += strings.Repeat("=", 8-r)
	}

	key, err := base32.StdEncoding.DecodeString(secret)
	if err != nil {
		return false
	}

	now := time.Now().Unix() / 30

	// Check current window and ±1 for clock skew
	for delta := int64(-1); delta <= 1; delta++ {
		if generateTOTP(key, now+delta) == code {
			return true
		}
	}
	return false
}

func generateTOTP(key []byte, counter int64) string {
	// HOTP spec: RFC 4226
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, uint64(counter)) //nolint:gosec // G115: TOTP counter is always ≥0; RFC 4226 mandates uint64 encoding

	mac := hmac.New(sha1.New, key)
	mac.Write(buf)
	h := mac.Sum(nil)

	offset := h[len(h)-1] & 0x0f
	code := binary.BigEndian.Uint32(h[offset:offset+4]) & 0x7fffffff
	code = code % uint32(math.Pow10(6))

	return fmt.Sprintf("%06d", code)
}
