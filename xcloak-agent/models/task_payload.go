package models

type TaskPayload struct {
	Path   string `json:"path"`
	PID    int    `json:"pid"`
	Script string `json:"script"`
}
