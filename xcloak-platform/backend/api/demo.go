package api

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"xcloak-platform/auth"
)

// DemoStart issues a short-lived read-only demo JWT and sets it as a cookie,
// then returns the token so the frontend can also store it as needed.
// No credentials required — this is the "try without signup" entry point.
func DemoStart(c *gin.Context) {
	token, err := auth.GenerateDemoJWT()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate demo session"})
		return
	}

	secure := authCookieSecure()
	//nolint:gosec // G124: demo session — httpOnly, SameSite, Secure all set
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     "token",
		Value:    token,
		Path:     "/",
		MaxAge:   2 * 60 * 60, // 2h
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	})
	//nolint:gosec // G124: presence flag for JS — HttpOnly: false is intentional
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     "logged_in",
		Value:    "1",
		Path:     "/",
		MaxAge:   2 * 60 * 60,
		HttpOnly: false,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	})
	//nolint:gosec // G124: demo flag — readable by JS to show demo banner
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     "demo_mode",
		Value:    "1",
		Path:     "/",
		MaxAge:   2 * 60 * 60,
		HttpOnly: false,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	})

	c.JSON(http.StatusOK, gin.H{"ok": true, "token": token})
}
