package services

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"math"
	"strings"
	"time"
)

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
	binary.BigEndian.PutUint64(buf, uint64(counter))

	mac := hmac.New(sha1.New, key)
	mac.Write(buf)
	h := mac.Sum(nil)

	offset := h[len(h)-1] & 0x0f
	code := binary.BigEndian.Uint32(h[offset:offset+4]) & 0x7fffffff
	code = code % uint32(math.Pow10(6))

	return fmt.Sprintf("%06d", code)
}
