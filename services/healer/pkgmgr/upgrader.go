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
	}
	return &PackageUpgrader{Manager: mgr}
}

func (pu *PackageUpgrader) GenerateUpgradeCommand(runtimeType string) []string {
	switch pu.Manager {
	case "apt":
		if runtimeType == "php" {
			return []string{"apt-get", "update", "&&", "apt-get", "install", "--only-upgrade", "-y", "php-fpm", "php-cli"}
		}
		return []string{"apt-get", "update", "&&", "apt-get", "install", "--only-upgrade", "-y", "nodejs"}
	case "apk":
		if runtimeType == "php" {
			return []string{"apk", "add", "--upgrade", "php82", "php83"}
		}
		return []string{"apk", "add", "--upgrade", "nodejs"}
	case "brew":
		if runtimeType == "php" {
			return []string{"brew", "upgrade", "php"}
		}
		return []string{"brew", "upgrade", "node"}
	case "yum", "dnf":
		if runtimeType == "php" {
			return []string{pu.Manager, "upgrade", "-y", "php"}
		}
		return []string{pu.Manager, "upgrade", "-y", "nodejs"}
	default:
		return []string{"echo", fmt.Sprintf("No supported package manager detected for %s upgrade", runtimeType)}
	}
}

func (pu *PackageUpgrader) ExecuteUpgrade(runtimeType string, dryRun bool) (string, error) {
	cmdParts := pu.GenerateUpgradeCommand(runtimeType)
	if dryRun {
		return fmt.Sprintf("[DRY-RUN] Would execute: %v", cmdParts), nil
	}

	if pu.Manager == "unknown" {
		return "", fmt.Errorf("no native package manager detected on host")
	}

	cmd := exec.Command(cmdParts[0], cmdParts[1:]...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}
