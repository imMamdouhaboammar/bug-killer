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
