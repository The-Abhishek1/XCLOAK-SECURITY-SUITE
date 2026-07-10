package models

import "time"

// AgentRelease is the current published agent binary for one platform
// (e.g. "linux_amd64") — global, not tenant-scoped, since the agent binary
// itself isn't tenant-specific. Republishing a platform overwrites it.
type AgentRelease struct {
	ID                   int       `json:"id"`
	Platform             string    `json:"platform"`
	Version              string    `json:"version"`
	SHA256               string    `json:"sha256"`
	Signature            string    `json:"signature"`              // base64url ed25519 over SHA-256 of binary
	PublicKeyFingerprint string    `json:"public_key_fingerprint"` // first 8 bytes of SHA-256(pubkey), hex
	DownloadURL          string    `json:"download_url"`
	CreatedBy            string    `json:"created_by"`
	CreatedAt            time.Time `json:"created_at"`
}
