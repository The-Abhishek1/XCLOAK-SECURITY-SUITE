// Package secrets wraps HashiCorp Vault's KV v2 and transit engines behind
// a small API the rest of the backend can call without caring whether Vault
// is actually configured.
//
// Vault is optional, matching the BYO-infra pattern already used for
// Kafka/MinIO in this codebase: if VAULT_ADDR isn't set, every Resolve call
// falls back to its env var and every Get/Put/Transit call is a documented
// no-op — existing env-var-only deployments keep working unchanged.
package secrets

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	vaultapi "github.com/hashicorp/vault/api"
)

const (
	kvMount      = "secret"
	requestTimeout = 5 * time.Second
)

var (
	mu     sync.RWMutex
	client *vaultapi.Client // nil when Vault is disabled
)

// Init connects to Vault if VAULT_ADDR is set. Auth token comes from
// VAULT_TOKEN directly, or VAULT_TOKEN_FILE (the convention used by Vault
// Agent / the Vault Agent Injector in Kubernetes, which writes a resolved
// token to a file rather than an env var). Call once at startup, before
// any other backend Init (database.Connect, services.InitRedis, ...) that
// might need a secret Resolve()d from Vault.
//
// Returns nil (not an error) when VAULT_ADDR is unset — that's "disabled",
// a normal supported state, not a failure.
func Init() error {
	addr := os.Getenv("VAULT_ADDR")
	if addr == "" {
		fmt.Println("[secrets] VAULT_ADDR not set — Vault disabled, using env vars directly")
		return nil
	}

	token := os.Getenv("VAULT_TOKEN")
	if token == "" {
		if path := os.Getenv("VAULT_TOKEN_FILE"); path != "" {
			b, err := os.ReadFile(path)
			if err != nil {
				return fmt.Errorf("reading VAULT_TOKEN_FILE: %w", err)
			}
			token = strings.TrimSpace(string(b))
		}
	}
	if token == "" {
		return fmt.Errorf("VAULT_ADDR is set but neither VAULT_TOKEN nor VAULT_TOKEN_FILE provided a token")
	}

	cfg := vaultapi.DefaultConfig()
	cfg.Address = addr
	c, err := vaultapi.NewClient(cfg)
	if err != nil {
		return fmt.Errorf("creating vault client: %w", err)
	}
	c.SetToken(token)

	ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
	defer cancel()
	if _, err := c.Sys().HealthWithContext(ctx); err != nil {
		return fmt.Errorf("vault health check failed: %w", err)
	}

	mu.Lock()
	client = c
	mu.Unlock()

	fmt.Printf("[secrets] connected to Vault at %s\n", addr)
	return nil
}

// Enabled reports whether Vault is configured and reachable.
func Enabled() bool {
	mu.RLock()
	defer mu.RUnlock()
	return client != nil
}

func kv() *vaultapi.KVv2 {
	mu.RLock()
	defer mu.RUnlock()
	if client == nil {
		return nil
	}
	return client.KVv2(kvMount)
}

// Resolve returns a secret's value: Vault KV v2 at vaultPath/vaultKey when
// Vault is enabled and the key is present there, otherwise the OS env var
// named envVar. This is the standard "secrets startup" lookup used for
// DB_PASSWORD, JWT_SECRET, REDIS_PASSWORD, SMTP credentials, etc.
func Resolve(envVar, vaultPath, vaultKey string) string {
	if v, ok := GetKV(vaultPath, vaultKey); ok {
		return v
	}
	return os.Getenv(envVar)
}

// GetKV reads a single key out of a KV v2 secret. ok is false if Vault is
// disabled, the path doesn't exist, or the key isn't present in it.
func GetKV(path, key string) (string, bool) {
	data, ok := GetKVMap(path)
	if !ok {
		return "", false
	}
	v, ok := data[key]
	return v, ok
}

// GetKVMap reads an entire KV v2 secret. ok is false if Vault is disabled
// or the path doesn't exist.
func GetKVMap(path string) (map[string]string, bool) {
	kv2 := kv()
	if kv2 == nil {
		return nil, false
	}

	ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
	defer cancel()
	secret, err := kv2.Get(ctx, path)
	if err != nil || secret == nil {
		return nil, false
	}

	out := make(map[string]string, len(secret.Data))
	for k, v := range secret.Data {
		if s, ok := v.(string); ok {
			out[k] = s
		}
	}
	return out, true
}

// PutKV merges the given keys into a KV v2 secret (existing keys not in
// data are preserved — this is Patch, not a destructive overwrite).
// No-op (returns nil) if Vault is disabled.
func PutKV(path string, data map[string]string) error {
	kv2 := kv()
	if kv2 == nil {
		return nil
	}

	payload := make(map[string]interface{}, len(data))
	for k, v := range data {
		payload[k] = v
	}

	ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
	defer cancel()

	// Patch requires the secret to already exist; create it empty first if
	// this is the first write (Vault returns a 404-flavored error from
	// Patch otherwise).
	if _, ok := GetKVMap(path); !ok {
		if _, err := kv2.Put(ctx, path, payload); err != nil {
			return fmt.Errorf("vault kv put %s: %w", path, err)
		}
		return nil
	}

	if _, err := kv2.Patch(ctx, path, payload); err != nil {
		return fmt.Errorf("vault kv patch %s: %w", path, err)
	}
	return nil
}

// DeleteKV permanently destroys a KV v2 secret (all versions + metadata).
// No-op if Vault is disabled.
func DeleteKV(path string) error {
	kv2 := kv()
	if kv2 == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
	defer cancel()
	if err := kv2.DeleteMetadata(ctx, path); err != nil {
		return fmt.Errorf("vault kv delete %s: %w", path, err)
	}
	return nil
}

// EnsureTransitKey idempotently creates a transit key if it doesn't already
// exist. No-op if Vault is disabled.
func EnsureTransitKey(keyName string) error {
	mu.RLock()
	c := client
	mu.RUnlock()
	if c == nil {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
	defer cancel()

	if _, err := c.Logical().ReadWithContext(ctx, "transit/keys/"+keyName); err == nil {
		return nil // already exists
	}

	if _, err := c.Logical().WriteWithContext(ctx, "transit/keys/"+keyName, nil); err != nil {
		return fmt.Errorf("creating transit key %q: %w", keyName, err)
	}
	return nil
}

// TransitEncrypt encrypts plaintext under the named transit key, returning
// Vault's ciphertext envelope (e.g. "vault:v1:base64..."). Vault must be
// enabled — callers that need a graceful "Vault not configured" path should
// check Enabled() themselves, since unlike Resolve there's no sane plaintext
// fallback for at-rest encryption.
func TransitEncrypt(keyName, plaintext string) (string, error) {
	mu.RLock()
	c := client
	mu.RUnlock()
	if c == nil {
		return "", fmt.Errorf("vault is not configured")
	}

	ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
	defer cancel()
	secret, err := c.Logical().WriteWithContext(ctx, "transit/encrypt/"+keyName, map[string]interface{}{
		"plaintext": base64Encode(plaintext),
	})
	if err != nil {
		return "", fmt.Errorf("transit encrypt: %w", err)
	}
	ct, _ := secret.Data["ciphertext"].(string)
	if ct == "" {
		return "", fmt.Errorf("transit encrypt: empty ciphertext in response")
	}
	return ct, nil
}

// TransitDecrypt reverses TransitEncrypt.
func TransitDecrypt(keyName, ciphertext string) (string, error) {
	mu.RLock()
	c := client
	mu.RUnlock()
	if c == nil {
		return "", fmt.Errorf("vault is not configured")
	}

	ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
	defer cancel()
	secret, err := c.Logical().WriteWithContext(ctx, "transit/decrypt/"+keyName, map[string]interface{}{
		"ciphertext": ciphertext,
	})
	if err != nil {
		return "", fmt.Errorf("transit decrypt: %w", err)
	}
	ptB64, _ := secret.Data["plaintext"].(string)
	if ptB64 == "" {
		return "", fmt.Errorf("transit decrypt: empty plaintext in response")
	}
	return base64Decode(ptB64)
}
