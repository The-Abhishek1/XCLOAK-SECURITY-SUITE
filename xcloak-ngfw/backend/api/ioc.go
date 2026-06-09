package api

import (
	"github.com/gin-gonic/gin"

	"xcloak-ngfw/models"
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

	err := services.CreateIOC(ioc)

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

	iocs, err := services.GetIOCs()

	if err != nil {

		c.JSON(500, gin.H{
			"error": err.Error(),
		})

		return
	}

	c.JSON(200, iocs)
}

func GetIOCByID(c *gin.Context) {

	id := c.Param("id")

	ioc, err := services.GetIOCByID(id)

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
	)

	if err != nil {

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

	err := services.DeleteIOC(id)

	if err != nil {

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

	err := services.EnableIOC(id)

	if err != nil {

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

	err := services.DisableIOC(id)

	if err != nil {

		c.JSON(500, gin.H{
			"error": err.Error(),
		})

		return
	}

	c.JSON(200, gin.H{
		"message": "IOC Disabled",
	})
}
