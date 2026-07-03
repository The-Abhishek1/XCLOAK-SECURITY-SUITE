package api

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"xcloak-ngfw/services"
)

// Signup — POST /api/signup
// Public endpoint for self-serve tenant provisioning. Creates an org + admin
// user without SMTP and returns a session cookie so the user lands directly
// in the dashboard without a separate login step.
func Signup(c *gin.Context) {
	var req struct {
		OrgName  string `json:"org_name"`
		Slug     string `json:"slug"`
		Username string `json:"username"`
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	token, err := services.SelfServeSignup(req.OrgName, req.Slug, req.Username, req.Email, req.Password)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	setAuthCookie(c, token)
	c.JSON(http.StatusOK, gin.H{"ok": true})
}
