package services

import (
	"encoding/json"
	"time"
)

// ── WebSocket tickets ───────────────────────────────────────────────────────
// Short-lived, single-use UUIDs that browser clients exchange for a WebSocket
// connection. Since WS connections bypass the Next.js proxy and go directly to
// the backend port, they can't rely on the httpOnly session cookie — the ticket
// carries the caller's identity from an authenticated POST /api/ws/ticket
// (which does go through the proxy and does carry the cookie).

const wsTicketPrefix = "ws_ticket:"

type WSTicketClaims struct {
	UserID   int    `json:"user_id"`
	Username string `json:"username"`
	Role     string `json:"role"`
	TenantID int    `json:"tenant_id"`
}

func StoreWSTicket(ticket string, claims WSTicketClaims) error {
	data, err := json.Marshal(claims)
	if err != nil {
		return err
	}
	return RDB.Set(ctx, wsTicketPrefix+ticket, string(data), 30*time.Second).Err()
}

// ConsumeWSTicket atomically reads and deletes the ticket — single-use.
func ConsumeWSTicket(ticket string) (*WSTicketClaims, error) {
	val, err := RDB.GetDel(ctx, wsTicketPrefix+ticket).Result()
	if err != nil {
		return nil, err
	}
	var claims WSTicketClaims
	if err := json.Unmarshal([]byte(val), &claims); err != nil {
		return nil, err
	}
	return &claims, nil
}

// ── OIDC one-time token exchange ────────────────────────────────────────────
// The OIDC callback runs directly at the backend port (not through the Next.js
// proxy), so any Set-Cookie header it emits would be scoped to the wrong origin
// in dev. Instead, the callback stores the JWT in Redis with a short-lived UUID
// code and redirects the browser to the frontend with just the code. The
// frontend exchanges the code via the proxy, and the backend sets the httpOnly
// cookie on that proxied response — correct origin.

const oidcOTPPrefix = "oidc_otp:"

func StoreOIDCToken(code string, jwtToken string) error {
	return RDB.Set(ctx, oidcOTPPrefix+code, jwtToken, 60*time.Second).Err()
}

// ConsumeOIDCToken atomically reads and deletes — single-use.
func ConsumeOIDCToken(code string) (string, error) {
	return RDB.GetDel(ctx, oidcOTPPrefix+code).Result()
}
