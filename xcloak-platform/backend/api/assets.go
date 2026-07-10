package api

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"xcloak-platform/models"
	"xcloak-platform/repositories"
)

func GetAssets(c *gin.Context) {
	assets, err := repositories.GetAssets(tenantIDFromContext(c))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if assets == nil {
		assets = []models.Asset{}
	}
	c.JSON(http.StatusOK, assets)
}

func GetAssetByID(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	asset, err := repositories.GetAssetByID(id, tenantIDFromContext(c))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "asset not found"})
		return
	}
	c.JSON(http.StatusOK, asset)
}

func CreateAsset(c *gin.Context) {
	var req models.Asset
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	req.TenantID = tenantIDFromContext(c)
	if req.Tags == nil {
		req.Tags = []string{}
	}
	asset, err := repositories.CreateAsset(req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusCreated, asset)
}

func UpdateAsset(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	var req models.Asset
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	req.ID = id
	req.TenantID = tenantIDFromContext(c)
	if req.Tags == nil {
		req.Tags = []string{}
	}
	if err := repositories.UpdateAsset(req); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func DeleteAsset(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	if err := repositories.DeleteAsset(id, tenantIDFromContext(c)); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}
