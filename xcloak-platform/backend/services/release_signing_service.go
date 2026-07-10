package services

// Release signing — ed25519 signatures on agent binaries.
//
// The signing private key lives in AGENT_RELEASE_SIGNING_KEY (base64url,
// no padding) and must NEVER be committed to the repository. Rotate it by
// generating a new keypair, updating the env var, and re-publishing all
// current releases with the new signature. The embedded public key in the
// agent binary is updated at build time (see xcloak-agent-desktop/agent/self_update.go).
//
// Key lifecycle:
//   openssl genpkey -algorithm ed25519 -out release-signing.key
//   openssl pkey -in release-signing.key -outform DER | tail -c 32 | base64url
//   # paste output as AGENT_RELEASE_SIGNING_KEY
//   openssl pkey -in release-signing.key -pubout -outform DER | tail -c 32 | base64url
//   # paste output as AGENT_RELEASE_PUBLIC_KEY (goes in both backend env and agent build)

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"os"
)

// SignReleaseBinary returns a base64url-encoded ed25519 signature over the
// SHA-256 hash of the binary content. The agent verifies this signature
// before replacing its own executable.
func SignReleaseBinary(content []byte) (signature string, err error) {
	privKeyB64 := os.Getenv("AGENT_RELEASE_SIGNING_KEY")
	if privKeyB64 == "" {
		return "", errors.New("AGENT_RELEASE_SIGNING_KEY not set; cannot sign release")
	}

	privKeyBytes, err := base64.RawURLEncoding.DecodeString(privKeyB64)
	if err != nil {
		return "", errors.New("AGENT_RELEASE_SIGNING_KEY: invalid base64url")
	}
	if len(privKeyBytes) != ed25519.SeedSize {
		return "", errors.New("AGENT_RELEASE_SIGNING_KEY: must be 32 bytes (ed25519 seed)")
	}

	privKey := ed25519.NewKeyFromSeed(privKeyBytes)
	digest := sha256.Sum256(content)
	sig := ed25519.Sign(privKey, digest[:])
	return base64.RawURLEncoding.EncodeToString(sig), nil
}

// VerifyReleaseSignature returns nil when the signature is valid for the
// given binary content and the configured public key.
func VerifyReleaseSignature(content []byte, signatureB64 string) error {
	pubKeyB64 := os.Getenv("AGENT_RELEASE_PUBLIC_KEY")
	if pubKeyB64 == "" {
		return errors.New("AGENT_RELEASE_PUBLIC_KEY not set")
	}

	pubKeyBytes, err := base64.RawURLEncoding.DecodeString(pubKeyB64)
	if err != nil {
		return errors.New("AGENT_RELEASE_PUBLIC_KEY: invalid base64url")
	}
	if len(pubKeyBytes) != ed25519.PublicKeySize {
		return errors.New("AGENT_RELEASE_PUBLIC_KEY: must be 32 bytes")
	}

	sigBytes, err := base64.RawURLEncoding.DecodeString(signatureB64)
	if err != nil {
		return errors.New("release signature: invalid base64url")
	}

	digest := sha256.Sum256(content)
	if !ed25519.Verify(pubKeyBytes, digest[:], sigBytes) {
		return errors.New("release signature verification failed — binary may be tampered")
	}
	return nil
}

// PublicKeyFingerprint returns the SHA-256 fingerprint of a base64url public
// key (hex-encoded, first 16 bytes), for display in the admin UI.
func PublicKeyFingerprint(pubKeyB64 string) string {
	b, err := base64.RawURLEncoding.DecodeString(pubKeyB64)
	if err != nil {
		return "invalid"
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:8])
}
