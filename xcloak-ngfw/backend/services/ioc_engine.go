package services

import (
	"fmt"
	"strings"

	"xcloak-ngfw/models"
)

func CheckConnectionIOC(
	connection models.Connection,
) {

	iocs, err := GetEnabledIOCsForAgent(connection.AgentID)

	if err != nil {
		return
	}

	for _, ioc := range iocs {

		switch ioc.Type {

		case "ip":
			if strings.Contains(
				connection.RemoteAddress,
				ioc.Indicator,
			) {
				alert := models.Alert{
					AgentID:        connection.AgentID,
					Severity:       ioc.Severity,
					RuleName:       "IOC Match",
					LogMessage:     fmt.Sprintf("IOC IP match: %s → %s", connection.RemoteAddress, ioc.Indicator),
					MitreTactic:    "Command and Control",
					MitreTechnique: "T1071",
					MitreName:      "Application Layer Protocol",
					Fingerprint:    fmt.Sprintf("ioc-ip-%s-agent-%d", ioc.Indicator, connection.AgentID),
				}
				CreateAlert(alert)
			}

		case "domain":
			// Match remote address against domain IOCs.
			// RemoteAddress format: "domain.com:443" or "1.2.3.4:443"
			remoteHost := connection.RemoteAddress
			if idx := strings.LastIndex(remoteHost, ":"); idx > 0 {
				remoteHost = remoteHost[:idx]
			}
			if strings.EqualFold(remoteHost, ioc.Indicator) ||
				strings.HasSuffix(strings.ToLower(remoteHost), "."+strings.ToLower(ioc.Indicator)) {
				CreateAlert(models.Alert{
					AgentID:        connection.AgentID,
					Severity:       ioc.Severity,
					RuleName:       "IOC: Malicious Domain",
					LogMessage:     fmt.Sprintf("IOC domain match: %s → %s | %s", remoteHost, ioc.Indicator, ioc.Description),
					MitreTactic:    "Command and Control",
					MitreTechnique: "T1071",
					MitreName:      "Application Layer Protocol",
					Fingerprint:    fmt.Sprintf("ioc-domain-%s-agent-%d", ioc.Indicator, connection.AgentID),
				})
			}

		case "url":
			if strings.Contains(strings.ToLower(connection.RemoteAddress), strings.ToLower(ioc.Indicator)) {
				CreateAlert(models.Alert{
					AgentID:        connection.AgentID,
					Severity:       ioc.Severity,
					RuleName:       "IOC: Malicious URL",
					LogMessage:     fmt.Sprintf("IOC URL match: %s → %s", connection.RemoteAddress, ioc.Indicator),
					MitreTactic:    "Command and Control",
					MitreTechnique: "T1102",
					MitreName:      "Web Service",
					Fingerprint:    fmt.Sprintf("ioc-url-%s-agent-%d", ioc.Indicator, connection.AgentID),
				})
			}
		}
	}
}
