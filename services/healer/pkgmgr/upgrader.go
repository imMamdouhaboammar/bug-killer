package pkgmgr

import (
	"fmt"
	"os/exec"
)

type PackageUpgrader struct {
	Manager string
}

func NewPackageUpgrader() *PackageUpgrader {
	mgr := "unknown"
	if _, err := exec.LookPath("apt-get"); err == nil {
		mgr = "apt"
	} else if _, err := exec.LookPath("apk"); err == nil {
		mgr = "apk"
	} else if _, err := exec.LookPath("yum"); err == nil {
		mgr = "yum"
	} else if _, err := exec.LookPath("dnf"); err == nil {
		mgr = "dnf"
	} else if _, err := exec.LookPath("brew"); err == nil {
		mgr = "brew"
	} else if _, err := exec.LookPath("npm"); err == nil {
		mgr = "npm"
	}
	return &PackageUpgrader{Manager: mgr}
}

func NewPackageUpgraderWithManager(manager string) *PackageUpgrader {
	return &PackageUpgrader{Manager: manager}
}

func (pu *PackageUpgrader) GenerateUpgradeCommand(runtimeType string) []string {
	switch pu.Manager {
	case "apt":
		if runtimeType == "php" {
			return []string{"apt-get", "update", "&&", "apt-get", "install", "--only-upgrade", "-y", "php-fpm", "php-cli"}
		}
		if runtimeType == "node" {
			return []string{"apt-get", "update", "&&", "apt-get", "install", "--only-upgrade", "-y", "nodejs"}
		}
		return []string{"apt-get", "install", "--only-upgrade", "-y", runtimeType}
	case "apk":
		if runtimeType == "php" {
			return []string{"apk", "add", "--upgrade", "php82", "php83"}
		}
		if runtimeType == "node" {
			return []string{"apk", "add", "--upgrade", "nodejs"}
		}
		return []string{"apk", "add", "--upgrade", runtimeType}
	case "brew":
		if runtimeType == "php" {
			return []string{"brew", "upgrade", "php"}
		}
		if runtimeType == "node" {
			return []string{"brew", "upgrade", "node"}
		}
		return []string{"brew", "upgrade", runtimeType}
	case "yum", "dnf":
		if runtimeType == "php" {
			return []string{pu.Manager, "upgrade", "-y", "php"}
		}
		if runtimeType == "node" {
			return []string{pu.Manager, "upgrade", "-y", "nodejs"}
		}
		return []string{pu.Manager, "upgrade", "-y", runtimeType}
	case "npm":
		if runtimeType == "audit" || runtimeType == "fix" {
			return []string{"npm", "audit", "fix", "--force"}
		}
		return []string{"npm", "install", "-g", fmt.Sprintf("%s@latest", runtimeType)}
	default:
		return []string{"echo", fmt.Sprintf("No supported package manager detected for %s upgrade", runtimeType)}
	}
}

func (pu *PackageUpgrader) ExecuteUpgrade(runtimeType string, dryRun bool) (string, error) {
	cmdParts := pu.GenerateUpgradeCommand(runtimeType)
	if dryRun {
		return fmt.Sprintf("[DRY-RUN] Would execute: %v", cmdParts), nil
	}

	if len(cmdParts) == 0 {
		return "", fmt.Errorf("empty command generated for runtime %s", runtimeType)
	}

	cmd := exec.Command(cmdParts[0], cmdParts[1:]...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("upgrade execution failed: %w (output: %s)", err, string(out))
	}

	return string(out), nil
}
