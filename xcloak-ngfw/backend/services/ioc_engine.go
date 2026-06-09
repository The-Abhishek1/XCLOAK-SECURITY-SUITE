package services

import (
	"strings"

	"xcloak-ngfw/models"
)

func CheckConnectionIOC(
	connection models.Connection,
) {

	iocs, err := GetEnabledIOCs()

	if err != nil {
		return
	}

	for _, ioc := range iocs {

		if ioc.Type != "ip" {
			continue
		}

		if strings.Contains(
			connection.RemoteAddress,
			ioc.Indicator,
		) {

			alert := models.Alert{
				AgentID: connection.AgentID,

				Severity: ioc.Severity,

				RuleName: "IOC Match",

				LogMessage: connection.RemoteAddress,

				MitreTactic: "Command and Control",

				MitreTechnique: "T1071",

				MitreName: "Application Layer Protocol",

				Fingerprint: connection.RemoteAddress,
			}

			CreateAlert(alert)
		}
	}
}
