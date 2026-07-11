package api

import "encoding/json"

// piiKeys is the set of parsed_fields JSON keys whose values are redacted
// in viewer-role responses to prevent credential and PII leakage through logs.
var piiKeys = map[string]bool{
	"password": true, "passwd": true, "pwd": true,
	"token": true, "access_token": true, "refresh_token": true,
	"auth_token": true, "id_token": true, "bearer_token": true,
	"secret": true, "api_secret": true, "client_secret": true,
	"api_key": true, "private_key": true, "secret_key": true,
	"authorization": true, "auth": true,
	"credential": true, "credentials": true,
	"ssn": true,
	"credit_card": true, "card_number": true, "cc_num": true,
	"cvv": true, "cvc": true,
	"passphrase": true,
}

// maskParsedFieldsPII replaces sensitive key values in a parsed_fields JSON
// string with "***". Non-JSON or empty input is returned unchanged.
func maskParsedFieldsPII(jsonStr string) string {
	if jsonStr == "" || jsonStr == "{}" {
		return jsonStr
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(jsonStr), &m); err != nil {
		return jsonStr
	}
	changed := false
	for k := range m {
		if piiKeys[k] {
			m[k] = "***"
			changed = true
		}
	}
	if !changed {
		return jsonStr
	}
	b, err := json.Marshal(m)
	if err != nil {
		return jsonStr
	}
	return string(b)
}
