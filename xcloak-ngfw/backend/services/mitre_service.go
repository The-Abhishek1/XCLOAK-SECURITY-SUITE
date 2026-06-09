package services

import "xcloak-ngfw/models"

func MapMITRE(
	alert *models.Alert,
) {

	switch alert.RuleName {

	case "Failed Password":

		alert.MitreTactic = "Credential Access"
		alert.MitreTechnique = "T1110"
		alert.MitreName = "Brute Force"

	case "Successful Login":

		alert.MitreTactic = "Initial Access"
		alert.MitreTechnique = "T1078"
		alert.MitreName = "Valid Accounts"

	case "Sudo Usage":

		alert.MitreTactic = "Privilege Escalation"
		alert.MitreTechnique = "T1548"
		alert.MitreName = "Abuse Elevation Control Mechanism"

	case "New User Created":

		alert.MitreTactic = "Persistence"
		alert.MitreTechnique = "T1136"
		alert.MitreName = "Create Account"

	default:

		alert.MitreTactic = "Unknown"
		alert.MitreTechnique = "Unknown"
		alert.MitreName = "Unknown"
	}
}
