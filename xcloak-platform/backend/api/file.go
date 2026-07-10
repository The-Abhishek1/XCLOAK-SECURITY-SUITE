package api

import (
	"encoding/base64"
	"os"
	"path/filepath"

	"github.com/gin-gonic/gin"

	"xcloak-platform/models"
	"xcloak-platform/repositories"
)

func ReceiveFile(c *gin.Context) {

	var upload models.FileUpload

	if err := c.ShouldBindJSON(&upload); err != nil {

		c.JSON(400, gin.H{
			"error": err.Error(),
		})

		return
	}

	data, err := base64.StdEncoding.DecodeString(
		upload.Content,
	)

	if err != nil {

		c.JSON(500, gin.H{
			"error": err.Error(),
		})

		return
	}

	os.MkdirAll("uploads", 0750)

	storedPath := filepath.Join(
		"uploads",
		upload.FileName,
	)

	err = os.WriteFile(
		storedPath,
		data,
		0644,
	)

	if err != nil {

		c.JSON(500, gin.H{
			"error": err.Error(),
		})

		return
	}

	repositories.SaveCollectedFile(
		upload.AgentID,
		upload.OriginalPath,
		upload.FileName,
		storedPath,
	)

	c.JSON(200, gin.H{
		"message": "File Received",
	})
}
