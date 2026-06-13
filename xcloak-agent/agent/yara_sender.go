package agent

import (
	"encoding/json"
	"fmt"

	"xcloak-agent/models"
)

func SendYaraMatches(matches []models.YaraMatch) {

	if len(matches) == 0 {
		fmt.Println("No YARA matches to send")
		return
	}

	body, _ := json.Marshal(matches)

	fmt.Println("Sending matches:", len(matches))

	resp, err := authPost("/api/yara/matches", body)

	if err != nil {
		fmt.Println("Failed sending YARA matches:", err)
		return
	}

	defer resp.Body.Close()
}
