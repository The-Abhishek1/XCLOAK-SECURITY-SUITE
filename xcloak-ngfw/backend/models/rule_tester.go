package models

type RuleTestRequest struct {
	Message string `json:"message"`
}

type RuleTestResult struct {
	RuleName string `json:"rule_name"`
	Matched  bool   `json:"matched"`
}
