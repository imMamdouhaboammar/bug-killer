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
		cmd := pu.GenerateUpgradeCommand(tt.runtime)
		if len(cmd) == 0 {
			t.Errorf("expected non-empty command for %s/%s", tt.manager, tt.runtime)
		}
		if cmd[0] != tt.expectedCmd {
			t.Errorf("expected cmd[0]=%s, got %s", tt.expectedCmd, cmd[0])
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
}
