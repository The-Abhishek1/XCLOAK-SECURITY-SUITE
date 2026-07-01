package api

import (
	"net/url"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"xcloak-ngfw/services"
)

// StartOIDCLoginHandler — GET /api/auth/oidc/start?tenant=<slug>
// Unauthenticated: this IS the login entry point. Redirects the browser to
// the tenant's configured IdP, or back to the frontend login page with an
// error — this is a top-level navigation, not an XHR call, so errors can't
// be JSON.
func StartOIDCLoginHandler(c *gin.Context) {
	slug := c.Query("tenant")
	if slug == "" {
		c.Redirect(302, services.FrontendLoginErrorURL("organization is required"))
		return
	}

	authURL, err := services.StartOIDCLogin(c.Request.Context(), slug)
	if err != nil {
		c.Redirect(302, services.FrontendLoginErrorURL(err.Error()))
		return
	}

	c.Redirect(302, authURL)
}

// OIDCCallbackHandler — GET /api/auth/oidc/callback?code&state
// Unauthenticated: the IdP redirects the browser here after the user signs in.
//
// We can't set an httpOnly cookie directly here because this handler runs on
// the backend port, not the Next.js frontend port — in dev the cookie would be
// scoped to the wrong origin. Instead we store the JWT in Redis under a
// short-lived one-time code and redirect to the frontend with just the code.
// The frontend exchanges the code via the Next.js proxy (same origin), and the
// backend sets the cookie on that proxied response.
func OIDCCallbackHandler(c *gin.Context) {
	code  := c.Query("code")
	state := c.Query("state")

	token, err := services.CompleteOIDCLogin(c.Request.Context(), code, state)
	if err != nil {
		c.Redirect(302, services.FrontendLoginErrorURL(err.Error()))
		return
	}

	otp := uuid.New().String()
	if err := services.StoreOIDCToken(otp, token); err != nil {
		c.Redirect(302, services.FrontendLoginErrorURL("session setup failed — try again"))
		return
	}

	c.Redirect(302, services.FrontendURL()+"/auth/oidc/complete?code="+url.QueryEscape(otp))
}

// OIDCTokenExchange — POST /api/auth/oidc/exchange
// Exchanges a short-lived one-time code (from the OIDC callback) for a
// session cookie. Runs through the Next.js proxy so Set-Cookie is on the
// frontend's origin.
func OIDCTokenExchange(c *gin.Context) {
	var body struct {
		Code string `json:"code"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || body.Code == "" {
		c.JSON(400, gin.H{"error": "code is required"})
		return
	}

	token, err := services.ConsumeOIDCToken(body.Code)
	if err != nil {
		c.JSON(401, gin.H{"error": "invalid or expired code"})
		return
	}

	setAuthCookie(c, token)
	c.JSON(200, gin.H{"ok": true})
}
