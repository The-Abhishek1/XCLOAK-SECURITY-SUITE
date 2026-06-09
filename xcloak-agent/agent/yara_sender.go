package agent

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"

	"xcloak-agent/config"
	"xcloak-agent/models"
)

func SendYaraMatches(
	matches []models.YaraMatch,
) {

	body, _ := json.Marshal(
		matches,
	)

	fmt.Println("Sending matches:", len(matches))

	http.Post(
		config.ServerURL+
			"/api/yara/matches",
		"application/json",
		bytes.NewBuffer(body),
	)
}
