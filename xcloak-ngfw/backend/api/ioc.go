package api

import (
	"strconv"

	"github.com/gin-gonic/gin"

	"xcloak-ngfw/models"
	"xcloak-ngfw/repositories"
	"xcloak-ngfw/services"
)

func CreateIOC(c *gin.Context) {

	var ioc models.IOC

	if err := c.ShouldBindJSON(&ioc); err != nil {

		c.JSON(400, gin.H{
			"error": err.Error(),
		})

		return
	}

	err := services.CreateIOC(ioc, tenantIDFromContext(c))

	if err != nil {

		c.JSON(500, gin.H{
			"error": err.Error(),
		})

		return
	}

	c.JSON(200, gin.H{
		"message": "IOC Created",
	})
}

func GetIOCs(c *gin.Context) {
	page, _  := strconv.Atoi(c.DefaultQuery("page", "1"))
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "50"))
	search   := c.Query("search")
	iocType  := c.Query("type")

	result, err := repositories.GetIOCsPaged(tenantIDFromContext(c), page, limit, search, iocType)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, result)
}

func GetIOCByID(c *gin.Context) {

	id := c.Param("id")

	ioc, err := services.GetIOCByID(id, tenantIDFromContext(c))

	if err != nil {

		c.JSON(404, gin.H{
			"error": "IOC not found",
		})

		return
	}

	c.JSON(200, ioc)
}

func UpdateIOC(c *gin.Context) {

	id := c.Param("id")

	var ioc models.IOC

	if err := c.ShouldBindJSON(&ioc); err != nil {

		c.JSON(400, gin.H{
			"error": err.Error(),
		})

		return
	}

	err := services.UpdateIOC(
		id,
		ioc,
		tenantIDFromContext(c),
	)

	if err != nil {

		if err == repositories.ErrIOCNotFound {
			c.JSON(404, gin.H{"error": "ioc not found"})
			return
		}

		c.JSON(500, gin.H{
			"error": err.Error(),
		})

		return
	}

	c.JSON(200, gin.H{
		"message": "IOC Updated",
	})
}

func DeleteIOC(c *gin.Context) {

	id := c.Param("id")

	err := services.DeleteIOC(id, tenantIDFromContext(c))

	if err != nil {

		if err == repositories.ErrIOCNotFound {
			c.JSON(404, gin.H{"error": "ioc not found"})
			return
		}

		c.JSON(500, gin.H{
			"error": err.Error(),
		})

		return
	}

	c.JSON(200, gin.H{
		"message": "IOC Deleted",
	})
}

func EnableIOC(c *gin.Context) {

	id := c.Param("id")

	err := services.EnableIOC(id, tenantIDFromContext(c))

	if err != nil {

		if err == repositories.ErrIOCNotFound {
			c.JSON(404, gin.H{"error": "ioc not found"})
			return
		}

		c.JSON(500, gin.H{
			"error": err.Error(),
		})

		return
	}

	c.JSON(200, gin.H{
		"message": "IOC Enabled",
	})
}

func DisableIOC(c *gin.Context) {

	id := c.Param("id")

	err := services.DisableIOC(id, tenantIDFromContext(c))

	if err != nil {

		if err == repositories.ErrIOCNotFound {
			c.JSON(404, gin.H{"error": "ioc not found"})
			return
		}

		c.JSON(500, gin.H{
			"error": err.Error(),
		})

		return
	}

	c.JSON(200, gin.H{
		"message": "IOC Disabled",
	})
}
