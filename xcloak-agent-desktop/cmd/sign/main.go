// sign is a minimal release-signing helper used exclusively by the CI/CD
// pipeline. It reads AGENT_SIGNING_KEY from the environment (base64url-encoded
// 32-byte ed25519 seed, same value as the backend's AGENT_RELEASE_SIGNING_KEY),
// computes SHA-256 of the binary at the path given as argv[1], and prints the
// base64url-encoded ed25519 signature to stdout.
//
// The agent's self_update.go verifies this signature before replacing itself:
//   digest := sha256.Sum256(binaryContent)
//   ed25519.Verify(embeddedPublicKey, digest[:], signature)
//
// Usage (in release.yml):
//
//	SIG=$(AGENT_SIGNING_KEY="$SECRET" ./sign path/to/binary)
package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"os"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: sign <binary-path>")
		os.Exit(1)
	}

	seedB64 := os.Getenv("AGENT_SIGNING_KEY")
	if seedB64 == "" {
		fmt.Fprintln(os.Stderr, "AGENT_SIGNING_KEY is not set")
		os.Exit(1)
	}

	seed, err := base64.RawURLEncoding.DecodeString(seedB64)
	if err != nil || len(seed) != ed25519.SeedSize {
		fmt.Fprintln(os.Stderr, "AGENT_SIGNING_KEY must be a 32-byte ed25519 seed encoded as base64url (no padding)")
		os.Exit(1)
	}

	content, err := os.ReadFile(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, "read binary:", err)
		os.Exit(1)
	}

	privKey := ed25519.NewKeyFromSeed(seed)
	digest := sha256.Sum256(content)
	sig := ed25519.Sign(privKey, digest[:])

	fmt.Print(base64.RawURLEncoding.EncodeToString(sig))
}
