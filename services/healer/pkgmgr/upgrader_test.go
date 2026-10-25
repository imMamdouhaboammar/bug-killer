package pkgmgr

import (
	"strings"
	"testing"
)

func TestPackageUpgraderCommandGeneration(t *testing.T) {
	tests := []struct {
		manager     string
		runtime     string
		expectedCmd string
	}{
		{"apt", "php", "apt-get"},
		{"apt", "node", "apt-get"},
		{"apk", "php", "apk"},
		{"apk", "node", "apk"},
		{"brew", "php", "brew"},
		{"brew", "node", "brew"},
		{"npm", "express", "npm"},
		{"npm", "audit", "npm"},
		{"yum", "php", "yum"},
	}

	for _, tt := range tests {
		pu := NewPackageUpgraderWithManager(tt.manager)
		cmds := pu.GenerateUpgradeCommand(tt.runtime)
		if len(cmds) == 0 {
			t.Errorf("expected non-empty command for %s/%s", tt.manager, tt.runtime)
		}
		if cmds[0][0] != tt.expectedCmd {
			t.Errorf("expected cmds[0][0]=%s, got %s", tt.expectedCmd, cmds[0][0])
		}
	}
}

func TestPackageUpgraderDryRun(t *testing.T) {
	pu := NewPackageUpgraderWithManager("apt")
	out, err := pu.ExecuteUpgrade("php", true)
	if err != nil {
		t.Fatalf("dry-run should not return error, got %v", err)
	}
	if !strings.HasPrefix(out, "[DRY-RUN]") {
		t.Errorf("expected dry-run prefix, got: %s", out)
	}
	if strings.Contains(out, "&&") {
		t.Errorf("dry-run output should not suggest shell '&&' chaining: %s", out)
	}
}

func TestPackageUpgraderAptSequentialCommands(t *testing.T) {
	pu := NewPackageUpgraderWithManager("apt")
	for _, runtime := range []string{"php", "node", "curl"} {
		cmds := pu.GenerateUpgradeCommand(runtime)
		if len(cmds) < 2 {
			t.Fatalf("apt command for %q should have at least 2 sequential commands (update then install), got: %v", runtime, cmds)
		}
		// First command should be apt-get update
		if cmds[0][0] != "apt-get" || cmds[0][1] != "update" {
			t.Errorf("expected first command [apt-get update], got: %v", cmds[0])
		}
		// No command should contain literal "&&"
		for _, cmd := range cmds {
			for _, arg := range cmd {
				if arg == "&&" {
					t.Fatalf("apt command for %q contains literal '&&' in arguments: %v", runtime, cmd)
				}
			}
		}
	}
}

func TestPackageUpgraderNpmAuditNoForce(t *testing.T) {
	pu := NewPackageUpgraderWithManager("npm")
	cmds := pu.GenerateUpgradeCommand("audit")
	if len(cmds) == 0 {
		t.Fatal("expected npm audit command")
	}
	for _, cmd := range cmds {
		for _, arg := range cmd {
			if arg == "--force" {
				t.Fatalf("npm audit command must not include '--force' flag: %v", cmd)
			}
		}
	}
}

func TestPackageUpgraderFlagInjectionPrevention(t *testing.T) {
	pu := NewPackageUpgraderWithManager("apt")
	maliciousInputs := []string{
		"--force",
		"-y",
		"--upload-pack=/bin/sh",
		"-o ProxyCommand=id",
		"php; rm -rf /",
		"node && whoami",
		"pkg | evil",
		"pkg\nrm -rf /",
		"",
		"pkg with spaces",
	}

	for _, input := range maliciousInputs {
		_, err := pu.GenerateUpgradeCommands(input)
		if err == nil {
			t.Errorf("expected validation error for malicious / invalid input %q, got nil", input)
		}

		_, execErr := pu.ExecuteUpgrade(input, true)
		if execErr == nil {
			t.Errorf("expected ExecuteUpgrade error for malicious / invalid input %q, got nil", input)
		}
	}
}

func TestPackageUpgraderValidPackageNames(t *testing.T) {
	pu := NewPackageUpgraderWithManager("npm")
	validInputs := []string{
		"express",
		"@types/node",
		"react@18.2.0",
		"php8.2",
		"libssl-dev",
		"package_name.1",
	}

	for _, input := range validInputs {
		cmds, err := pu.GenerateUpgradeCommands(input)
		if err != nil {
			t.Errorf("valid package name %q rejected with error: %v", input, err)
		}
		if len(cmds) == 0 {
			t.Errorf("expected commands for %q, got empty", input)
		}
	}
}
