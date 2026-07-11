package models

type DashboardOverview struct {
	Agents        int `json:"agents"`
	OnlineAgents  int `json:"online_agents"`
	OfflineAgents int `json:"offline_agents"`

	Processes   int `json:"processes"`
	Connections int `json:"connections"`
	Services    int `json:"services"`
	Packages    int `json:"packages"`
	Users       int `json:"users"`

	Alerts         int `json:"alerts"`
	CriticalAlerts int `json:"critical_alerts"`
	OpenAlerts     int `json:"open_alerts"`
	SnoozedAlerts  int `json:"snoozed_alerts"`

	Incidents         int `json:"incidents"`
	CriticalIncidents int `json:"critical_incidents"`
}
