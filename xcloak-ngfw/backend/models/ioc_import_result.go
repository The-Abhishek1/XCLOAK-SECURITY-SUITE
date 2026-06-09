package models

type IOCImportResult struct {
	Imported int `json:"imported"`
	Skipped  int `json:"skipped"`
}
