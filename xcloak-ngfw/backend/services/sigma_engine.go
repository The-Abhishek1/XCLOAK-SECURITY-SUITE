package services

import (
	"fmt"
	"strings"

	"xcloak-ngfw/models"
)

func EvaluateRules(
	log models.Log,
) {

	rules, err := GetEnabledSigmaRules()

	if err != nil {
		return
	}

	message := strings.ToLower(
		log.LogMessage,
	)

	for _, rule := range rules {

		for _, keyword := range rule.Keywords {

			if strings.Contains(
				message,
				strings.ToLower(keyword),
			) {

				alert := models.Alert{
					AgentID: log.AgentID,

					RuleName: rule.Title,
					Severity: rule.Severity,

					MitreTactic:    rule.MitreTactic,
					MitreTechnique: rule.MitreTechnique,
					MitreName:      rule.MitreName,

					Fingerprint: fmt.Sprintf(
						"%d-%s",
						log.AgentID,
						strings.ReplaceAll(
							rule.Title,
							" ",
							"-",
						),
					),

					LogMessage: log.LogMessage,
				}

				CreateAlert(alert)

				CorrelateAlert(alert)

				break
			}
		}
	}
}
