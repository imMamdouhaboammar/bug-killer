package waf

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWafInjectorNginxIdempotency(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "aegis-waf-test")
	if err != nil {
		t.Fatalf("Failed to create tempdir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	confPath := filepath.Join(tempDir, "nginx.conf")
	initialContent := `server {
    listen 80;
    location / {
        proxy_pass http://localhost:3000;
    }
}`
	_ = os.WriteFile(confPath, []byte(initialContent), 0644)

	injector := NewWafInjector()

	// First injection
	applied, err := injector.InjectNginx(confPath)
	if err != nil {
		t.Fatalf("First injection failed: %v", err)
	}
	if !applied {
		t.Fatalf("Expected patch to be applied")
	}

	patchedBytes, _ := os.ReadFile(confPath)
	patchedContent := string(patchedBytes)
	if !strings.Contains(patchedContent, NginxMarkerStart) {
		t.Errorf("Patched content missing marker start")
	}
	if !strings.Contains(patchedContent, "$http_content_encoding ~* \"br\"") {
		t.Errorf("Patched content missing Brotli rejection rule")
	}

	// Second injection (Idempotency test)
	secondApplied, err := injector.InjectNginx(confPath)
	if err != nil {
		t.Fatalf("Second injection errored: %v", err)
	}
	if secondApplied {
		t.Errorf("Second injection must be idempotent and return applied=false")
	}
}

func TestWafInjectorHAProxy(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "aegis-haproxy-test")
	if err != nil {
		t.Fatalf("Failed to create tempdir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	confPath := filepath.Join(tempDir, "haproxy.cfg")
	initialContent := `frontend http_in
    bind *:80
    default_backend servers`
	_ = os.WriteFile(confPath, []byte(initialContent), 0644)

	injector := NewWafInjector()
	applied, err := injector.InjectHAProxy(confPath)
	if err != nil || !applied {
		t.Fatalf("HAProxy injection failed: %v", err)
	}

	patchedBytes, _ := os.ReadFile(confPath)
	if !strings.Contains(string(patchedBytes), "acl is_brotli_payload req.hdr(content-encoding) -m sub br") {
		t.Errorf("HAProxy missing brotli payload drop ACL")
	}
}

func TestWafInjectionPreservesPrivatePermissionsAndSymlink(t *testing.T) {
	dir := t.TempDir()
	actual := filepath.Join(dir, "nginx.conf")
	linked := filepath.Join(dir, "active-nginx.conf")
	hardLinkedAlias := filepath.Join(dir, "read-only-audit-copy.conf")
	if err := os.WriteFile(actual, []byte("server { listen 80; }"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(actual, linked); err != nil {
		t.Skipf("Symlinks unavailable in test environment: %v", err)
	}
	if err := os.Link(actual, hardLinkedAlias); err != nil {
		t.Skipf("Hard links unavailable in test environment: %v", err)
	}
	applied, err := NewWafInjector().InjectNginx(linked)
	if err != nil || !applied {
		t.Fatalf("Failed to inject through approved symlink: %v", err)
	}
	if info, err := os.Lstat(linked); err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("Configuration symlink must not be replaced: %v", err)
	}
	if info, err := os.Stat(actual); err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("Patch must preserve private file mode: %v", err)
	}
	other, err := os.ReadFile(hardLinkedAlias)
	if err != nil || string(other) != "server { listen 80; }" {
		t.Fatalf("Atomic patch must not mutate an independently named hard-linked file: %v", err)
	}
}

func TestWafInjectorNginxCommentedOutBlockNotCorrupted(t *testing.T) {
	tempDir := t.TempDir()
	confPath := filepath.Join(tempDir, "nginx.conf")
	initialContent := `# Old config:
# server {
#     location / {
#         proxy_pass http://legacy:8080;
#     }
# }

server {
    listen 80;
    server_name example.com;
    location / {
        proxy_pass http://localhost:3000;
    }
}
`
	if err := os.WriteFile(confPath, []byte(initialContent), 0644); err != nil {
		t.Fatal(err)
	}

	injector := NewWafInjector()
	applied, err := injector.InjectNginx(confPath)
	if err != nil || !applied {
		t.Fatalf("InjectNginx failed: %v", err)
	}

	patchedBytes, _ := os.ReadFile(confPath)
	patched := string(patchedBytes)

	// Ensure the patch was NOT placed before the commented-out block
	commentIdx := strings.Index(patched, "# Old config:")
	patchIdx := strings.Index(patched, NginxMarkerStart)
	activeServerIdx := strings.Index(patched, "server_name example.com;")

	if patchIdx < commentIdx {
		t.Errorf("Patch was injected before commented block! (patchIdx=%d, commentIdx=%d)", patchIdx, commentIdx)
	}
	// The patch must be inside or after the active server block, before or inside location
	if patchIdx < activeServerIdx {
		// Wait: if it's placed after "server {" of active server, patchIdx will be before server_name or before location
		// But it must be after "# server {" comment block
		oldServerCommentIdx := strings.Index(patched, "# server {")
		if patchIdx < oldServerCommentIdx {
			t.Errorf("Patch injected before commented server block!")
		}
	}
	// Specifically, check that the patch is after the active "server {"
	lines := strings.Split(patched, "\n")
	foundActiveServer := false
	foundPatchAfterActiveServer := false
	for _, l := range lines {
		trimmed := strings.TrimSpace(l)
		if strings.HasPrefix(trimmed, "server {") {
			foundActiveServer = true
		}
		if foundActiveServer && strings.Contains(trimmed, NginxMarkerStart) {
			foundPatchAfterActiveServer = true
			break
		}
	}
	if !foundPatchAfterActiveServer {
		t.Errorf("Patch was not anchored inside active server block! Content:\n%s", patched)
	}
}

func TestWafInjectorHAProxyCommentedFrontendNotCorrupted(t *testing.T) {
	tempDir := t.TempDir()
	confPath := filepath.Join(tempDir, "haproxy.cfg")
	initialContent := `# frontend commented_frontend
#     bind *:8080
frontend active_frontend
    bind *:80
    default_backend servers
`
	if err := os.WriteFile(confPath, []byte(initialContent), 0644); err != nil {
		t.Fatal(err)
	}

	injector := NewWafInjector()
	applied, err := injector.InjectHAProxy(confPath)
	if err != nil || !applied {
		t.Fatalf("InjectHAProxy failed: %v", err)
	}

	patchedBytes, _ := os.ReadFile(confPath)
	patched := string(patchedBytes)

	patchIdx := strings.Index(patched, HAProxyMarkerStart)
	activeFrontendIdx := strings.Index(patched, "frontend active_frontend")
	if patchIdx < activeFrontendIdx {
		t.Fatalf("Patch was injected before active frontend (likely inside/after commented frontend)! patchIdx=%d, activeIdx=%d",
			patchIdx, activeFrontendIdx)
	}
}

func TestWafInjectorNginxSyntaxErrorRollback(t *testing.T) {
	tempDir := t.TempDir()
	confPath := filepath.Join(tempDir, "nginx.conf")
	// Broken syntax: unclosed brace
	brokenContent := `server {
    listen 80;
    location / {
        proxy_pass http://localhost:3000;
`
	if err := os.WriteFile(confPath, []byte(brokenContent), 0644); err != nil {
		t.Fatal(err)
	}

	injector := NewWafInjector()
	applied, err := injector.InjectNginx(confPath)
	if err == nil {
		t.Fatalf("expected syntax error on broken config, but got err=nil, applied=%v", applied)
	}

	// Verify rollback: file content must NOT have been replaced with broken or patched content
	data, _ := os.ReadFile(confPath)
	if string(data) != brokenContent {
		t.Fatalf("file content was modified despite syntax failure! Got:\n%s", string(data))
	}
}

func TestWafInjectorApacheAnchoringAndRollback(t *testing.T) {
	tempDir := t.TempDir()
	confPath := filepath.Join(tempDir, "httpd.conf")
	initialContent := `# <VirtualHost *:8080>
#     ServerName legacy.example.com
# </VirtualHost>
<VirtualHost *:80>
    ServerName active.example.com
    DocumentRoot /var/www/html
</VirtualHost>
`
	if err := os.WriteFile(confPath, []byte(initialContent), 0644); err != nil {
		t.Fatal(err)
	}

	injector := NewWafInjector()
	applied, err := injector.InjectApache(confPath)
	if err != nil || !applied {
		t.Fatalf("InjectApache failed: %v", err)
	}

	patchedBytes, _ := os.ReadFile(confPath)
	patched := string(patchedBytes)

	// Marker must be after active <VirtualHost *:80>, not commented one
	activeVhostIdx := strings.Index(patched, "<VirtualHost *:80>")
	patchIdx := strings.Index(patched, ApacheMarkerStart)
	if patchIdx < activeVhostIdx {
		t.Fatalf("Apache patch was placed before active VirtualHost! patchIdx=%d, activeVhostIdx=%d", patchIdx, activeVhostIdx)
	}

	// Test rollback
	rolledBack, err := injector.RollbackApache(confPath)
	if err != nil || !rolledBack {
		t.Fatalf("RollbackApache failed: %v", err)
	}
	cleanBytes, _ := os.ReadFile(confPath)
	if strings.Contains(string(cleanBytes), ApacheMarkerStart) {
		t.Errorf("Marker still present after rollback: %s", string(cleanBytes))
	}
}

func TestWafInjectorApacheSyntaxErrorRollback(t *testing.T) {
	tempDir := t.TempDir()
	confPath := filepath.Join(tempDir, "httpd.conf")
	brokenContent := `<VirtualHost *:80>
    ServerName broken.example.com
` // Unclosed tag!
	if err := os.WriteFile(confPath, []byte(brokenContent), 0644); err != nil {
		t.Fatal(err)
	}

	injector := NewWafInjector()
	applied, err := injector.InjectApache(confPath)
	if err == nil {
		t.Fatalf("expected syntax error on unclosed Apache tag, got applied=%v", applied)
	}

	// Verify rollback
	data, _ := os.ReadFile(confPath)
	if string(data) != brokenContent {
		t.Fatalf("file content changed despite syntax failure! Got:\n%s", string(data))
	}
}

func TestWafInjectorMultipleServerBlocks(t *testing.T) {
	tempDir := t.TempDir()
	confPath := filepath.Join(tempDir, "nginx.conf")
	initialContent := `server {
    listen 80;
    server_name http.example.com;
}

server {
    listen 443 ssl;
    server_name https.example.com;
}
`
	if err := os.WriteFile(confPath, []byte(initialContent), 0644); err != nil {
		t.Fatal(err)
	}

	injector := NewWafInjector()
	applied, err := injector.InjectNginx(confPath)
	if err != nil || !applied {
		t.Fatalf("InjectNginx failed: %v", err)
	}

	patchedBytes, _ := os.ReadFile(confPath)
	patched := string(patchedBytes)

	// Validate syntax
	if err := ValidateNginxConfig(patched); err != nil {
		t.Fatalf("patched multi-server config has invalid syntax: %v", err)
	}

	// Rollback
	rolledBack, err := injector.RollbackNginx(confPath)
	if err != nil || !rolledBack {
		t.Fatalf("Rollback failed: %v", err)
	}
	cleanBytes, _ := os.ReadFile(confPath)
	if strings.Contains(string(cleanBytes), NginxMarkerStart) {
		t.Fatalf("Rollback failed to remove marker: %s", string(cleanBytes))
	}
}


