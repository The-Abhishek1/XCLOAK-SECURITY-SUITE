package middleware

import "github.com/gin-gonic/gin"

// SecurityHeaders injects defensive HTTP headers on every response.
//
// CSP: this is a JSON-API backend — no HTML, scripts, or media are served, so
// default-src 'none' is both correct and maximally strict.
//
// HSTS: only emitted when the request arrived over TLS (direct TLS or via a
// TLS-terminating proxy that sets X-Forwarded-Proto: https), so plain-HTTP
// development environments are unaffected.
func SecurityHeaders() gin.HandlerFunc {
	return func(c *gin.Context) {
		// API backend: deny everything by default.
		c.Header("Content-Security-Policy", "default-src 'none'")

		// Prevent MIME-type sniffing — stops browsers treating JSON as script.
		c.Header("X-Content-Type-Options", "nosniff")

		// Deny framing — no HTML served but belt-and-suspenders.
		c.Header("X-Frame-Options", "DENY")

		// No referrer leakage from API calls.
		c.Header("Referrer-Policy", "no-referrer")

		// Disable browser feature APIs — unnecessary for an API backend.
		c.Header("Permissions-Policy", "geolocation=(), microphone=(), camera=()")

		// HSTS: emit only on confirmed TLS connections. Using max-age=31536000
		// (1 year) matches HSTS preload requirements; includeSubDomains covers
		// any API subdomains served from the same cert.
		proto := c.GetHeader("X-Forwarded-Proto")
		if c.Request.TLS != nil || proto == "https" {
			c.Header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}

		c.Next()
	}
}
