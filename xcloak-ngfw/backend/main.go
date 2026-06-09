package main

import (
	"log"

	"github.com/gin-gonic/gin"

	"time"
	"xcloak-ngfw/database"
	"xcloak-ngfw/middleware"
	"xcloak-ngfw/routes"
	"xcloak-ngfw/services"
)

func main() {

	err := database.Connect()

	// firewall.SyncFirewall()

	if err != nil {
		panic(err)
	}

	go func() {

		for {

			services.MarkOfflineAgents()

			time.Sleep(
				30 * time.Second,
			)
		}

	}()

	router := gin.Default()

	router.Use(
		middleware.RequestLogger(),
	)

	router.Use(
		middleware.RequestID(),
	)

	routes.SetupRoutes(router)

	log.Println("XCloak API Running")

	router.Run(":8080")
}
