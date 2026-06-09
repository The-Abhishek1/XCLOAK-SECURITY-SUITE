package firewall

import (
	"fmt"
	"os/exec"
)

func runCommand(command string, args ...string) error {

	cmd := exec.Command(command, args...)

	output, err := cmd.CombinedOutput()

	if err != nil {
		return fmt.Errorf(
			"%v\n%s",
			err,
			string(output),
		)
	}

	return nil
}

func CreateXcloakTable() error {

	runCommand(
		"sudo",
		"nft",
		"add",
		"table",
		"inet",
		"xcloak",
	)

	runCommand(
		"sudo",
		"nft",
		"add",
		"chain",
		"inet",
		"xcloak",
		"test",
	)

	return nil
}

func FlushXcloakRules() error {

	return runCommand(
		"sudo",
		"nft",
		"flush",
		"chain",
		"inet",
		"xcloak",
		"test",
	)
}

func SyncFirewall() {

	fmt.Println("Syncing Firewall...")

	CreateXcloakTable()

	FlushXcloakRules()

	ApplyAllRules()

	fmt.Println("Firewall Sync Complete")
}
