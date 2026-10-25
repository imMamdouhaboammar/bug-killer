package pkgmgr

import (
	"fmt"
	"os/exec"
	"regexp"
	"strings"
)

var validPackageNameRegex = regexp.MustCompile(`^[a-zA-Z0-9@][a-zA-Z0-9@/._+-]*$`)

// ValidatePackageName ensures the given package name or runtime type does not
// contain command flag injection attempts (e.g. leading '-') or dangerous shell metacharacters.
func ValidatePackageName(name string) error {
	if name == "" {
		return fmt.Errorf("package name / runtime type cannot be empty")
	}
	if strings.HasPrefix(name, "-") {
		return fmt.Errorf("package name / runtime type %q cannot start with '-' (command flag injection attempt)", name)
	}
	if len(name) > 256 {
		return fmt.Errorf("package name / runtime type %q exceeds maximum length (256)", name)
	}
	if !validPackageNameRegex.MatchString(name) {
		return fmt.Errorf("package name / runtime type %q contains forbidden characters or whitespace", name)
	}
	return nil
}

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

// GenerateUpgradeCommands returns an ordered slice of typed commands to execute sequentially.
// Avoids shell chaining operators (like '&&') within exec.Command arguments.
func (pu *PackageUpgrader) GenerateUpgradeCommands(runtimeType string) ([][]string, error) {
	if err := ValidatePackageName(runtimeType); err != nil {
		return nil, err
	}

	switch pu.Manager {
	case "apt":
		if runtimeType == "php" {
			return [][]string{
				{"apt-get", "update"},
				{"apt-get", "install", "--only-upgrade", "-y", "php-fpm", "php-cli"},
			}, nil
		}
		if runtimeType == "node" {
			return [][]string{
				{"apt-get", "update"},
				{"apt-get", "install", "--only-upgrade", "-y", "nodejs"},
			}, nil
		}
		return [][]string{
			{"apt-get", "update"},
			{"apt-get", "install", "--only-upgrade", "-y", runtimeType},
		}, nil
	case "apk":
		if runtimeType == "php" {
			return [][]string{{"apk", "add", "--upgrade", "php82", "php83"}}, nil
		}
		if runtimeType == "node" {
			return [][]string{{"apk", "add", "--upgrade", "nodejs"}}, nil
		}
		return [][]string{{"apk", "add", "--upgrade", runtimeType}}, nil
	case "brew":
		if runtimeType == "php" {
			return [][]string{{"brew", "upgrade", "php"}}, nil
		}
		if runtimeType == "node" {
			return [][]string{{"brew", "upgrade", "node"}}, nil
		}
		return [][]string{{"brew", "upgrade", runtimeType}}, nil
	case "yum", "dnf":
		if runtimeType == "php" {
			return [][]string{{pu.Manager, "upgrade", "-y", "php"}}, nil
		}
		if runtimeType == "node" {
			return [][]string{{pu.Manager, "upgrade", "-y", "nodejs"}}, nil
		}
		return [][]string{{pu.Manager, "upgrade", "-y", runtimeType}}, nil
	case "npm":
		if runtimeType == "audit" || runtimeType == "fix" {
			return [][]string{{"npm", "audit", "fix"}}, nil
		}
		return [][]string{{"npm", "install", "-g", fmt.Sprintf("%s@latest", runtimeType)}}, nil
	default:
		return [][]string{{"echo", fmt.Sprintf("No supported package manager detected for %s upgrade", runtimeType)}}, nil
	}
}

// GenerateUpgradeCommand returns the sequential slice of commands for the runtime.
func (pu *PackageUpgrader) GenerateUpgradeCommand(runtimeType string) [][]string {
	cmds, _ := pu.GenerateUpgradeCommands(runtimeType)
	return cmds
}

func (pu *PackageUpgrader) ExecuteUpgrade(runtimeType string, dryRun bool) (string, error) {
	cmds, err := pu.GenerateUpgradeCommands(runtimeType)
	if err != nil {
		return "", err
	}
	if len(cmds) == 0 {
		return "", fmt.Errorf("empty command generated for runtime %s", runtimeType)
	}

	if dryRun {
		var formatted []string
		for _, c := range cmds {
			formatted = append(formatted, fmt.Sprintf("%v", c))
		}
		return fmt.Sprintf("[DRY-RUN] Would execute: %s", strings.Join(formatted, " -> ")), nil
	}

	var combined strings.Builder
	for _, cmdParts := range cmds {
		if len(cmdParts) == 0 {
			continue
		}
		cmd := exec.Command(cmdParts[0], cmdParts[1:]...)
		out, err := cmd.CombinedOutput()
		if len(out) > 0 {
			if combined.Len() > 0 {
				combined.WriteString("\n")
			}
			combined.Write(out)
		}
		if err != nil {
			return combined.String(), fmt.Errorf("upgrade execution failed on %v: %w (output: %s)", cmdParts, err, string(out))
		}
	}

	return combined.String(), nil
}
