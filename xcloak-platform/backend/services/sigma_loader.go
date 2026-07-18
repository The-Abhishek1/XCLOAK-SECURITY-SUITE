package services

import (
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"

	"xcloak-platform/models"
)

func LoadSigmaRules() (
	[]models.SigmaRule,
	error,
) {

	rules := []models.SigmaRule{}

	files, err := filepath.Glob(
		"rules/*.yaml",
	)

	if err != nil {
		return nil, err
	}

	for _, file := range files {

		data, err := os.ReadFile(
			file,
		)

		if err != nil {
			continue
		}

		var rule models.SigmaRule

		err = yaml.Unmarshal(
			data,
			&rule,
		)

		if err != nil {
			continue
		}

		rules = append(
			rules,
			rule,
		)
	}

	return rules, nil
}
