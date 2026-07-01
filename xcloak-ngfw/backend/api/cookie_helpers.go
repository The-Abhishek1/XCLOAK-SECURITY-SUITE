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

// clearAuthCookies expires both auth cookies so the browser discards them.
func clearAuthCookies(c *gin.Context) {
	secure := authCookieSecure()
	for _, name := range []string{"token", "logged_in"} {
		//nolint:gosec // G124: expiry cookie — MaxAge: -1 is correct for deletion; attributes match setAuthCookie
		http.SetCookie(c.Writer, &http.Cookie{
			Name:     name,
			Value:    "",
			Path:     "/",
			MaxAge:   -1,
			HttpOnly: name == "token",
			Secure:   secure,
			SameSite: http.SameSiteLaxMode,
		})
	}
}
