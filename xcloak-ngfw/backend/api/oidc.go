package api

import (
	"net/url"

	"github.com/gin-gonic/gin"

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
// Unauthenticated: the IdP redirects the browser here after the user signs
// in. Redirects on to the frontend's token-pickup page either way.
func OIDCCallbackHandler(c *gin.Context) {
	code := c.Query("code")
	state := c.Query("state")

	token, err := services.CompleteOIDCLogin(c.Request.Context(), code, state)
	if err != nil {
		c.Redirect(302, services.FrontendLoginErrorURL(err.Error()))
		return
	}

	c.Redirect(302, services.FrontendURL()+"/auth/oidc/complete?token="+url.QueryEscape(token))
}
