package agent

import (
	"fmt"

	"xcloak-agent/models"
)

func SendFileHashes(client *AuthClient, hashes []models.FileHash) {

	if len(hashes) == 0 {
		return
	}

	resp, err := client.Post("/api/filehashes", hashes)
	if err != nil {
		fmt.Println("SendFileHashes: send error:", err)
		return
	}
	defer resp.Body.Close()

	fmt.Printf("SendFileHashes: sent %d hashes, status %d\n", len(hashes), resp.StatusCode)
}
