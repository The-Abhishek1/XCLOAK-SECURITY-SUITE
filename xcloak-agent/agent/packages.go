//go:build !windows

package agent

import (
	"bufio"
	"encoding/json"
	"log/slog"
	"os/exec"
	"strings"

	"xcloak-agent/models"
)

// CollectPackages builds a package inventory using a distro-aware fallback chain:
// dpkg → rpm → pacman → snap → flatpak → pip3
// All available sources are queried; results are merged with a Source tag.
func CollectPackages(agentID int) {
	var packages []models.Package

	packages = append(packages, collectDpkg(agentID)...)
	packages = append(packages, collectRpm(agentID)...)
	packages = append(packages, collectPacman(agentID)...)
	packages = append(packages, collectSnap(agentID)...)
	packages = append(packages, collectFlatpak(agentID)...)
	packages = append(packages, collectPip(agentID)...)

	if len(packages) == 0 {
		slog.Warn("package collection returned 0 packages across all sources")
		return
	}

	body, _ := json.Marshal(packages)
	resp, err := authPost("/api/agents/packages", body)
	if err != nil {
		slog.Error("failed sending packages", "err", err)
		return
	}
	defer resp.Body.Close()
	slog.Info("packages sent", "count", len(packages))
}

func collectDpkg(agentID int) []models.Package {
	out, err := exec.Command("dpkg-query", "-W", "-f=${Package}\t${Version}\n").Output()
	if err != nil {
		return nil
	}
	return parseTabSeparated(agentID, string(out), "dpkg")
}

func collectRpm(agentID int) []models.Package {
	out, err := exec.Command("rpm", "-qa", "--queryformat", "%{NAME}\t%{VERSION}-%{RELEASE}\n").Output()
	if err != nil {
		return nil
	}
	return parseTabSeparated(agentID, string(out), "rpm")
}

func collectPacman(agentID int) []models.Package {
	out, err := exec.Command("pacman", "-Q").Output()
	if err != nil {
		return nil
	}
	var pkgs []models.Package
	sc := bufio.NewScanner(strings.NewReader(string(out)))
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 2 {
			continue
		}
		pkgs = append(pkgs, models.Package{
			AgentID:     agentID,
			PackageName: fields[0],
			Version:     fields[1],
			Source:      "pacman",
		})
	}
	return pkgs
}

func collectSnap(agentID int) []models.Package {
	out, err := exec.Command("snap", "list").Output()
	if err != nil {
		return nil
	}
	var pkgs []models.Package
	sc := bufio.NewScanner(strings.NewReader(string(out)))
	first := true
	for sc.Scan() {
		if first {
			first = false
			continue
		}
		fields := strings.Fields(sc.Text())
		if len(fields) < 2 {
			continue
		}
		pkgs = append(pkgs, models.Package{
			AgentID:     agentID,
			PackageName: fields[0],
			Version:     fields[1],
			Source:      "snap",
		})
	}
	return pkgs
}

func collectFlatpak(agentID int) []models.Package {
	out, err := exec.Command("flatpak", "list", "--columns=application,version").Output()
	if err != nil {
		return nil
	}
	return parseTabSeparated(agentID, string(out), "flatpak")
}

func collectPip(agentID int) []models.Package {
	// Try pip3 first, then pip
	out, err := exec.Command("pip3", "list", "--format=freeze").Output()
	if err != nil {
		out, err = exec.Command("pip", "list", "--format=freeze").Output()
		if err != nil {
			return nil
		}
	}
	var pkgs []models.Package
	sc := bufio.NewScanner(strings.NewReader(string(out)))
	for sc.Scan() {
		// format: package==version
		line := sc.Text()
		parts := strings.SplitN(line, "==", 2)
		if len(parts) != 2 {
			continue
		}
		pkgs = append(pkgs, models.Package{
			AgentID:     agentID,
			PackageName: parts[0],
			Version:     parts[1],
			Source:      "pip",
		})
	}
	return pkgs
}

func parseTabSeparated(agentID int, output, source string) []models.Package {
	var pkgs []models.Package
	sc := bufio.NewScanner(strings.NewReader(output))
	for sc.Scan() {
		fields := strings.SplitN(sc.Text(), "\t", 2)
		if len(fields) < 2 {
			continue
		}
		name := strings.TrimSpace(fields[0])
		ver := strings.TrimSpace(fields[1])
		if name == "" {
			continue
		}
		pkgs = append(pkgs, models.Package{
			AgentID:     agentID,
			PackageName: name,
			Version:     ver,
			Source:      source,
		})
	}
	return pkgs
}
