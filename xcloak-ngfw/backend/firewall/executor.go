package firewall

import (
	"fmt"
	"os/exec"
	"strings"
)

func ExecuteNFTCommand(command string) error {

	args := strings.Fields(command)

	cmd := exec.Command("sudo", args...)

	output, err := cmd.CombinedOutput()

	if err != nil {
		return fmt.Errorf(
			"error: %v\n%s",
			err,
			string(output),
		)
	}

	return nil
}