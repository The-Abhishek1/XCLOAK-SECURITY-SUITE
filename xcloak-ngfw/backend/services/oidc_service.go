package services

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/oauth2"

	"xcloak-ngfw/auth"
	"xcloak-ngfw/database"
	"xcloak-ngfw/repositories"
	"xcloak-ngfw/secrets"
)

// OIDCConfig is a tenant's SSO provider settings, stored as an `integrations`
// row (name='oidc') — same per-tenant storage every other integration
// (webhook/Slack/email) already uses, not a new table.
type OIDCConfig struct {
	IssuerURL    string `json:"issuer_url"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	ButtonLabel  string `json:"button_label"`
}

func backendPublicURL() string {
	if v := os.Getenv("BACKEND_PUBLIC_URL"); v != "" {
		return v
	}
	return "http://localhost:8080"
}

// FrontendURL is the base URL the OIDC callback redirects browsers back to.
func FrontendURL() string {
	if v := os.Getenv("FRONTEND_URL"); v != "" {
		return v
	}
	return "http://localhost:3000"
}

// FrontendLoginErrorURL builds a redirect target for the login page carrying
// an SSO error message — used because the OIDC start/callback handlers are
// top-level browser navigations, not XHR calls, so errors can't be JSON.
func FrontendLoginErrorURL(msg string) string {
	return FrontendURL() + "/login?sso_error=" + url.QueryEscape(msg)
}

// loadOIDCConfig reads tenantID's OIDC settings. Returns nil if not
// configured or disabled — same "nil means not set up" convention as
// loadSMTPConfig.
func loadOIDCConfig(tenantID int) (*OIDCConfig, error) {
	var enabled bool
	var configJSON []byte

	err := database.DB.QueryRow(`
		SELECT enabled, config FROM integrations WHERE name='oidc' AND tenant_id=$1
	`, tenantID).Scan(&enabled, &configJSON)

	if err != nil || !enabled {
		return nil, nil
	}

	var cfg OIDCConfig
	if err := json.Unmarshal(configJSON, &cfg); err != nil {
		return nil, err
	}
	if secrets.Enabled() {
		if v, ok := secrets.GetKV(integrationVaultPath(tenantID, "oidc"), "client_secret"); ok {
			cfg.ClientSecret = v
		}
	}
	if cfg.IssuerURL == "" || cfg.ClientID == "" || cfg.ClientSecret == "" {
		return nil, nil
	}
	return &cfg, nil
}

// oidcStateClaims is signed with the same secret as real session JWTs and
// passed as the OAuth2 `state` param — avoids needing any server-side session
// storage for the handful of minutes between redirect and callback (same
// lightweight-token approach auth/temp_token.go already uses for 2FA).
type oidcStateClaims struct {
	TenantID int    `json:"tenant_id"`
	Nonce    string `json:"nonce"`
	jwt.RegisteredClaims
}

func newOAuth2Config(cfg *OIDCConfig, provider *oidc.Provider) *oauth2.Config {
	return &oauth2.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		RedirectURL:  backendPublicURL() + "/api/auth/oidc/callback",
		Endpoint:     provider.Endpoint(),
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
	}
}

// StartOIDCLogin resolves tenantSlug, loads its OIDC config, and returns the
// URL to redirect the browser to at the IdP.
func StartOIDCLogin(ctx context.Context, tenantSlug string) (string, error) {
	tenant, err := repositories.GetTenantBySlug(tenantSlug)
	if err != nil {
		return "", errors.New("unknown organization")
	}
	if !tenant.IsActive {
		return "", errors.New("this tenant has been suspended")
	}

	cfg, err := loadOIDCConfig(tenant.ID)
	if err != nil {
		return "", err
	}
	if cfg == nil {
		return "", errors.New("SSO is not configured for this organization")
	}

	provider, err := oidc.NewProvider(ctx, cfg.IssuerURL)
	if err != nil {
		return "", fmt.Errorf("failed to reach identity provider: %w", err)
	}

	nonceBytes := make([]byte, 16)
	rand.Read(nonceBytes)
	nonce := hex.EncodeToString(nonceBytes)

	state := jwt.NewWithClaims(jwt.SigningMethodHS256, oidcStateClaims{
		TenantID: tenant.ID,
		Nonce:    nonce,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(10 * time.Minute)),
		},
	})
	signedState, err := state.SignedString(auth.JwtSecret())
	if err != nil {
		return "", err
	}

	oauth2Cfg := newOAuth2Config(cfg, provider)
	return oauth2Cfg.AuthCodeURL(signedState, oidc.Nonce(nonce)), nil
}

// CompleteOIDCLogin verifies the callback (state + authorization code),
// exchanges the code, verifies the ID token, matches the email against an
// existing active user in that tenant (no auto-provisioning), and mints a
// normal session JWT — indistinguishable from a password-login token to
// every downstream consumer.
func CompleteOIDCLogin(ctx context.Context, code, stateStr string) (string, error) {
	var claims oidcStateClaims
	_, err := jwt.ParseWithClaims(stateStr, &claims, func(t *jwt.Token) (interface{}, error) {
		return auth.JwtSecret(), nil
	})
	if err != nil {
		return "", errors.New("invalid or expired SSO session — please try again")
	}

	cfg, err := loadOIDCConfig(claims.TenantID)
	if err != nil {
		return "", err
	}
	if cfg == nil {
		return "", errors.New("SSO is not configured for this organization")
	}

	provider, err := oidc.NewProvider(ctx, cfg.IssuerURL)
	if err != nil {
		return "", fmt.Errorf("failed to reach identity provider: %w", err)
	}

	oauth2Cfg := newOAuth2Config(cfg, provider)
	oauth2Token, err := oauth2Cfg.Exchange(ctx, code)
	if err != nil {
		return "", fmt.Errorf("failed to exchange authorization code: %w", err)
	}

	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		return "", errors.New("identity provider did not return an ID token")
	}

	verifier := provider.Verifier(&oidc.Config{ClientID: cfg.ClientID})
	idToken, err := verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return "", fmt.Errorf("invalid ID token: %w", err)
	}
	if idToken.Nonce != claims.Nonce {
		return "", errors.New("invalid SSO session — nonce mismatch")
	}

	var idClaims struct {
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
	}
	if err := idToken.Claims(&idClaims); err != nil {
		return "", err
	}
	if idClaims.Email == "" || !idClaims.EmailVerified {
		return "", errors.New("identity provider did not return a verified email")
	}

	var tenantActive bool
	if err := database.DB.QueryRow(
		`SELECT is_active FROM tenants WHERE id=$1`, claims.TenantID,
	).Scan(&tenantActive); err != nil || !tenantActive {
		return "", errors.New("this tenant has been suspended")
	}

	user, err := repositories.GetUserByEmailAndTenant(idClaims.Email, claims.TenantID)
	if err != nil || !user.IsActive {
		return "", errors.New("no account found for this email in this organization")
	}

	token, err := auth.GenerateJWT(user.ID, user.Username, user.Role, user.TenantID, user.IsPlatformAdmin)
	if err != nil {
		return "", err
	}

	database.DB.Exec(`UPDATE users SET last_login=NOW() WHERE id=$1`, user.ID)
	LogEvent("LOGIN_SSO", "SSO login via OIDC", user.Username)

	return token, nil
}
