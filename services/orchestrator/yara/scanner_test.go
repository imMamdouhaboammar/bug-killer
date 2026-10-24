package yara

import (
	"strings"
	"testing"

	"github.com/spf13/afero"
)

func TestYaraScannerWebshellDetection(t *testing.T) {
	scanner, err := NewYaraScanner(DefaultBuiltinRules(), nil, 4)
	if err != nil {
		t.Fatalf("failed to initialize YaraScanner: %v", err)
	}

	payload := []byte(`<?php
	// Malicious backdoor webshell
	if (isset($_POST['cmd'])) {
		@eval(base64_decode($_POST['cmd']));
	}
	?>`)

	matches := scanner.ScanBytes("/var/www/html/shell.php", payload)
	if len(matches) == 0 {
		t.Fatalf("expected YARA rule to match webshell, got 0 matches")
	}

	found := false
	for _, m := range matches {
		if m.RuleID == "YARA-WEBSHELL-001" {
			found = true
			if m.Severity != SeverityCritical {
				t.Errorf("expected CRITICAL severity, got %s", m.Severity)
			}
		}
	}
	if !found {
		t.Errorf("expected YARA-WEBSHELL-001 match")
	}
}

func TestYaraScannerDirectoryTraversal(t *testing.T) {
	memFs := afero.NewMemMapFs()
	_ = afero.WriteFile(memFs, "/app/index.php", []byte("echo 'hello world';"), 0644)
	_ = afero.WriteFile(memFs, "/app/evil.php", []byte("system($_GET['x']);"), 0644)
	_ = afero.WriteFile(memFs, "/app/safe.js", []byte("console.log('safe');"), 0644)

	scanner, err := NewYaraScanner(DefaultBuiltinRules(), memFs, 2)
	if err != nil {
		t.Fatalf("failed to initialize YaraScanner: %v", err)
	}

	var discoveredMatches []*YaraMatch
	err = scanner.ScanDirectory("/app", func(ym *YaraMatch) {
		discoveredMatches = append(discoveredMatches, ym)
	})
	if err != nil {
		t.Fatalf("ScanDirectory failed: %v", err)
	}

	if len(discoveredMatches) != 1 {
		t.Fatalf("expected 1 match for evil.php, got %d", len(discoveredMatches))
	}
	if !strings.HasSuffix(discoveredMatches[0].FilePath, "evil.php") {
		t.Errorf("expected match on evil.php, got %s", discoveredMatches[0].FilePath)
	}
}
