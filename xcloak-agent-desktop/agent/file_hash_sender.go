package agent

import (
	"encoding/json"
	"fmt"

	"xcloak-agent-desktop/models"
)

// SendFileHashes submits collected file hashes to the server.
// Uses authPost (Bearer token) since /api/filehashes requires agent auth.
func SendFileHashes(hashes []models.FileHash) {

	if len(hashes) == 0 {
		return
	}

	body, _ := json.Marshal(hashes)

	resp, err := authPost("/api/filehashes", body)
	if err != nil {
		fmt.Println("Failed sending file hashes:", err)
		return
	}
	defer resp.Body.Close()

	fmt.Printf("File hashes sent: %d\n", len(hashes))
}
