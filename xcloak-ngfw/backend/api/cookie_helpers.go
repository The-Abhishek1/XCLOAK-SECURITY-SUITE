package api

import (
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
)

func authCookieSecure() bool {
	return os.Getenv("TLS_CERT_FILE") != ""
}

// setAuthCookie writes two cookies:
//   - token (httpOnly) — the JWT; never readable by JavaScript
//   - logged_in (not httpOnly) — a presence flag so JS can detect auth state
//     without ever touching the actual JWT
func setAuthCookie(c *gin.Context, token string) {
	secure := authCookieSecure()
	//nolint:gosec // G124: Secure is set conditionally on TLS_CERT_FILE; SameSite and HttpOnly are explicitly set
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     "token",
		Value:    token,
		Path:     "/",
		MaxAge:   8 * 60 * 60,
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	})
	//nolint:gosec // G124: logged_in is a JS-readable presence flag by design; HttpOnly: false is intentional
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     "logged_in",
		Value:    "1",
		Path:     "/",
		MaxAge:   8 * 60 * 60,
		HttpOnly: false,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	})
}

// setRefreshCookie writes the long-lived refresh token as a separate httpOnly
// cookie. It is distinct from the access "token" cookie so clients can tell
// them apart and the refresh cookie's longer MaxAge doesn't leak into the
// access token cookie.
func setRefreshCookie(c *gin.Context, refreshToken string) {
	secure := authCookieSecure()
	//nolint:gosec // G124: httpOnly, SameSite, Secure are all set; longer MaxAge matches 7-day refresh window
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     "refresh_token",
		Value:    refreshToken,
		Path:     "/api/auth/refresh",
		MaxAge:   7 * 24 * 60 * 60,
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	})
}

// clearAuthCookies expires all three auth cookies so the browser discards them.
func clearAuthCookies(c *gin.Context) {
	secure := authCookieSecure()
	cookieDefs := []struct {
		name     string
		path     string
		httpOnly bool
	}{
		{"token", "/", true},
		{"logged_in", "/", false},
		{"refresh_token", "/api/auth/refresh", true},
	}
	for _, cd := range cookieDefs {
		//nolint:gosec // G124: expiry cookie — MaxAge: -1 is correct for deletion
		http.SetCookie(c.Writer, &http.Cookie{
			Name:     cd.name,
			Value:    "",
			Path:     cd.path,
			MaxAge:   -1,
			HttpOnly: cd.httpOnly,
			Secure:   secure,
			SameSite: http.SameSiteLaxMode,
		})
	}
}
