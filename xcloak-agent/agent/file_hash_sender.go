package agent

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"

	"xcloak-agent/config"
	"xcloak-agent/models"
)

func SendFileHashes(hashes []models.FileHash) {

	if len(hashes) == 0 {
		return
	}

	body, err := json.Marshal(hashes)
	if err != nil {
		fmt.Println("SendFileHashes: marshal error:", err)
		return
	}

	resp, err := http.Post(
		config.ServerURL+"/api/filehashes",
		"application/json",
		bytes.NewBuffer(body),
	)

	if err != nil {
		fmt.Println("SendFileHashes: send error:", err)
		return
	}

	defer resp.Body.Close()

	fmt.Printf("SendFileHashes: sent %d hashes, status %d\n", len(hashes), resp.StatusCode)
}
