package services

import (
	"fmt"
	"net"
	"strings"

	"xcloak-platform/models"
	"xcloak-platform/repositories"
)

// ipIOCMatches checks whether remoteAddr (host:port, IPv4 or bracketed
// IPv6) matches an IP-type IOC indicator, which may be a single address
// or a CIDR range. This replaces a previous strings.Contains check, which
// matched "1.2.3.4" against "11.2.3.41" and silently dropped every
// CIDR-typed IOC a threat feed imported.
func ipIOCMatches(remoteAddr, indicator string) bool {
	host := remoteAddr
	if h, _, err := net.SplitHostPort(remoteAddr); err == nil {
		host = h
	} else if idx := strings.LastIndex(remoteAddr, ":"); idx > 0 && strings.Count(remoteAddr, ":") == 1 {
		host = remoteAddr[:idx]
	}

	remoteIP := net.ParseIP(host)
	if remoteIP == nil {
		return false
	}

	if strings.Contains(indicator, "/") {
		_, ipNet, err := net.ParseCIDR(indicator)
		if err != nil {
			return false
		}
		return ipNet.Contains(remoteIP)
	}

	indicatorIP := net.ParseIP(indicator)
	if indicatorIP == nil {
		return false
	}
	return remoteIP.Equal(indicatorIP)
}

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
			if ipIOCMatches(connection.RemoteAddress, ioc.Indicator) {
				repositories.RecordIOCHit(ioc.ID)
				CreateAlert(models.Alert{
					AgentID:        connection.AgentID,
					Severity:       ioc.Severity,
					RuleName:       "IOC Match",
					LogMessage:     fmt.Sprintf("IOC IP match: %s → %s", connection.RemoteAddress, ioc.Indicator),
					MitreTactic:    "Command and Control",
					MitreTechnique: "T1071",
					MitreName:      "Application Layer Protocol",
					Fingerprint:    fmt.Sprintf("ioc-ip-%s-agent-%d", ioc.Indicator, connection.AgentID),
				})
			}

		case "domain":
			remoteHost := connection.RemoteAddress
			if idx := strings.LastIndex(remoteHost, ":"); idx > 0 {
				remoteHost = remoteHost[:idx]
			}
			if strings.EqualFold(remoteHost, ioc.Indicator) ||
				strings.HasSuffix(strings.ToLower(remoteHost), "."+strings.ToLower(ioc.Indicator)) {
				repositories.RecordIOCHit(ioc.ID)
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
				repositories.RecordIOCHit(ioc.ID)
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
