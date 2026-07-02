package secrets

import (
	"os"
	"strings"
	"testing"
)

// ── base64 helpers ────────────────────────────────────────────────────────────

func TestBase64RoundTrip(t *testing.T) {
	plain := "hello, vault!"
	encoded := base64Encode(plain)
	if encoded == plain {
		t.Errorf("base64Encode returned same value: %q", encoded)
	}
	decoded, err := base64Decode(encoded)
	if err != nil {
		t.Fatalf("base64Decode error: %v", err)
	}
	if decoded != plain {
		t.Errorf("round-trip: got %q, want %q", decoded, plain)
	}
}

func TestBase64Decode_InvalidInput(t *testing.T) {
	_, err := base64Decode("not-valid-base64!!!")
	if err == nil {
		t.Error("expected error for invalid base64, got nil")
	}
}

func TestBase64Decode_EmptyString(t *testing.T) {
	decoded, err := base64Decode("")
	if err != nil {
		t.Fatalf("unexpected error for empty string: %v", err)
	}
	if decoded != "" {
		t.Errorf("expected empty string, got %q", decoded)
	}
}

// ── Init (no VAULT_ADDR) ──────────────────────────────────────────────────────

func TestInit_NoVaultAddr(t *testing.T) {
	os.Unsetenv("VAULT_ADDR")
	if err := Init(); err != nil {
		t.Errorf("Init() without VAULT_ADDR should return nil, got %v", err)
	}
}

func TestInit_VaultAddrSetNoToken(t *testing.T) {
	os.Setenv("VAULT_ADDR", "http://127.0.0.1:8200")
	os.Unsetenv("VAULT_TOKEN")
	os.Unsetenv("VAULT_TOKEN_FILE")
	defer func() {
		os.Unsetenv("VAULT_ADDR")
		os.Unsetenv("VAULT_TOKEN")
	}()
	err := Init()
	if err == nil {
		t.Error("Init() with VAULT_ADDR but no token should return error")
	}
	if !strings.Contains(err.Error(), "VAULT_TOKEN") {
		t.Errorf("error should mention VAULT_TOKEN, got %v", err)
	}
}

func TestInit_VaultTokenFileMissing(t *testing.T) {
	os.Setenv("VAULT_ADDR", "http://127.0.0.1:8200")
	os.Setenv("VAULT_TOKEN_FILE", "/nonexistent/path/token")
	os.Unsetenv("VAULT_TOKEN")
	defer func() {
		os.Unsetenv("VAULT_ADDR")
		os.Unsetenv("VAULT_TOKEN_FILE")
	}()
	err := Init()
	if err == nil {
		t.Error("Init() with missing VAULT_TOKEN_FILE should return error")
	}
}

// ── Enabled ───────────────────────────────────────────────────────────────────

func TestEnabled_FalseWhenNotInit(t *testing.T) {
	// After Init() with no VAULT_ADDR, client is nil → Enabled() == false.
	os.Unsetenv("VAULT_ADDR")
	_ = Init()
	if Enabled() {
		t.Error("Enabled() should be false when Vault not configured")
	}
}

// ── Resolve (falls back to env var) ──────────────────────────────────────────

func TestResolve_FallsBackToEnv(t *testing.T) {
	os.Setenv("MY_SECRET_KEY", "env_value")
	defer os.Unsetenv("MY_SECRET_KEY")

	// Vault not configured — should return env var value.
	val := Resolve("MY_SECRET_KEY", "app/secrets", "db_password")
	if val != "env_value" {
		t.Errorf("Resolve() = %q, want env var value %q", val, "env_value")
	}
}

func TestResolve_EmptyWhenNotSet(t *testing.T) {
	os.Unsetenv("NONEXISTENT_VAR_XYZ")
	val := Resolve("NONEXISTENT_VAR_XYZ", "app/secrets", "missing")
	if val != "" {
		t.Errorf("Resolve() = %q, want empty string", val)
	}
}

// ── GetKV / GetKVMap (Vault disabled) ────────────────────────────────────────

func TestGetKV_FalseWhenVaultDisabled(t *testing.T) {
	_, ok := GetKV("any/path", "any_key")
	if ok {
		t.Error("GetKV() should return false when Vault is disabled")
	}
}

func TestGetKVMap_FalseWhenVaultDisabled(t *testing.T) {
	_, ok := GetKVMap("any/path")
	if ok {
		t.Error("GetKVMap() should return false when Vault is disabled")
	}
}

// ── PutKV / DeleteKV (no-op when Vault disabled) ─────────────────────────────

func TestPutKV_NoopWhenVaultDisabled(t *testing.T) {
	err := PutKV("any/path", map[string]string{"key": "value"})
	if err != nil {
		t.Errorf("PutKV() should be no-op (nil) when Vault disabled, got %v", err)
	}
}

func TestDeleteKV_NoopWhenVaultDisabled(t *testing.T) {
	err := DeleteKV("any/path")
	if err != nil {
		t.Errorf("DeleteKV() should be no-op (nil) when Vault disabled, got %v", err)
	}
}

// ── EnsureTransitKey (no-op when Vault disabled) ─────────────────────────────

func TestEnsureTransitKey_NoopWhenVaultDisabled(t *testing.T) {
	err := EnsureTransitKey("mykey")
	if err != nil {
		t.Errorf("EnsureTransitKey() should be no-op when Vault disabled, got %v", err)
	}
}

// ── TransitEncrypt / TransitDecrypt (error when Vault disabled) ───────────────

func TestTransitEncrypt_ErrorWhenVaultDisabled(t *testing.T) {
	_, err := TransitEncrypt("mykey", "plaintext")
	if err == nil {
		t.Error("TransitEncrypt() should return error when Vault is not configured")
	}
	if !strings.Contains(err.Error(), "not configured") {
		t.Errorf("error message should mention 'not configured', got %v", err)
	}
}

func TestTransitDecrypt_ErrorWhenVaultDisabled(t *testing.T) {
	_, err := TransitDecrypt("mykey", "vault:v1:abc123")
	if err == nil {
		t.Error("TransitDecrypt() should return error when Vault is not configured")
	}
	if !strings.Contains(err.Error(), "not configured") {
		t.Errorf("error message should mention 'not configured', got %v", err)
	}
}
