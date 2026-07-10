package models

type IOCImportRequest struct {
	Type string `json:"type"`

	Severity string `json:"severity"`

	Description string `json:"description"`

	Indicators []string `json:"indicators"`
}
