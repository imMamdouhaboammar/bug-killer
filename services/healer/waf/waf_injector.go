package waf

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	NginxMarkerStart = "# --- BEGIN AEGIS VIRTUAL PATCH (CVE-2026-111497 / CVE-2026-109618) ---"
	NginxMarkerEnd   = "# --- END AEGIS VIRTUAL PATCH ---"

	HAProxyMarkerStart = "# --- BEGIN AEGIS HAPROXY GUARD ---"
	HAProxyMarkerEnd   = "# --- END AEGIS HAPROXY GUARD ---"

	ApacheMarkerStart = "# --- BEGIN AEGIS APACHE GUARD ---"
	ApacheMarkerEnd   = "# --- END AEGIS APACHE GUARD ---"
)

type WafInjector struct{}

func NewWafInjector() *WafInjector {
	return &WafInjector{}
}

func readConfig(configPath string) (string, []byte, error) {
	canonical, err := filepath.EvalSymlinks(configPath)
	if err != nil {
		return "", nil, err
	}
	data, err := os.ReadFile(canonical)
	return canonical, data, err
}

func writeConfigAtomically(canonical string, content []byte) error {
	info, err := os.Stat(canonical)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("refusing to patch non-regular configuration file: %s", canonical)
	}
	temp, err := os.CreateTemp(filepath.Dir(canonical), ".bug-killer-waf-*")
	if err != nil {
		return err
	}
	defer os.Remove(temp.Name())
	if err := temp.Chmod(info.Mode().Perm()); err != nil {
		_ = temp.Close()
		return err
	}
	_, writeErr := temp.Write(content)
	if writeErr == nil {
		writeErr = temp.Sync()
	}
	closeErr := temp.Close()
	if writeErr == nil {
		writeErr = closeErr
	}
	if writeErr != nil {
		return writeErr
	}
	return os.Rename(temp.Name(), canonical)
}

func (w *WafInjector) InjectNginx(configPath string) (bool, error) {
	canonical, data, err := readConfig(configPath)
	if err != nil {
		return false, err
	}

	content := string(data)
	if strings.Contains(content, NginxMarkerStart) {
		return false, nil // Idempotent
	}

	patch := fmt.Sprintf(`
    %s
    # Mitigate Node2Shell (CVE-2026-111497): Drop malformed Brotli payloads before reaching Node.js
    if ($http_content_encoding ~* "br") {
        return 415 "Unsupported Media Type: Brotli request body rejected by Aegis Sentinel";
    }

    # Mitigate PHP2Shell (CVE-2026-109618): Bound client body buffers and FastCGI buffers
    client_max_body_size 32m;
    client_body_buffer_size 128k;
    fastcgi_buffer_size 128k;
    fastcgi_buffers 4 256k;
    %s
`, NginxMarkerStart, NginxMarkerEnd)

	// Inject right inside server block or before proxy_pass / location
	var modified string
	if idx := strings.Index(content, "location /"); idx != -1 {
		modified = content[:idx] + patch + "\n    " + content[idx:]
	} else if lastBrace := strings.LastIndex(content, "}"); lastBrace != -1 {
		modified = content[:lastBrace] + patch + "\n" + content[lastBrace:]
	} else {
		modified = content + "\n" + patch
	}

	err = writeConfigAtomically(canonical, []byte(modified))
	return err == nil, err
}

func (w *WafInjector) InjectHAProxy(configPath string) (bool, error) {
	canonical, data, err := readConfig(configPath)
	if err != nil {
		return false, err
	}

	content := string(data)
	if strings.Contains(content, HAProxyMarkerStart) {
		return false, nil
	}

	patch := fmt.Sprintf(`
    %s
    # Drop Brotli compressed bodies targeting Node upstream backends
    acl is_brotli_payload req.hdr(content-encoding) -m sub br
    http-request deny deny_status 415 if is_brotli_payload
    %s
`, HAProxyMarkerStart, HAProxyMarkerEnd)

	var modified string
	if idx := strings.Index(content, "frontend "); idx != -1 {
		nextNl := strings.Index(content[idx:], "\n")
		insertAt := idx + nextNl + 1
		modified = content[:insertAt] + patch + content[insertAt:]
	} else {
		modified = content + "\n" + patch
	}

	err = writeConfigAtomically(canonical, []byte(modified))
	return err == nil, err
}

func (w *WafInjector) InjectApache(configPath string) (bool, error) {
	canonical, data, err := readConfig(configPath)
	if err != nil {
		return false, err
	}

	content := string(data)
	if strings.Contains(content, ApacheMarkerStart) {
		return false, nil
	}

	patch := fmt.Sprintf(`
%s
<IfModule mod_headers.c>
    # Strip or reject dangerous Brotli content-encoding headers before passing to Node/PHP
    RequestHeader unset Content-Encoding "expr=%%{HTTP:Content-Encoding} =~ /br/i"
</IfModule>
<IfModule mod_security2.c>
    SecRule REQUEST_HEADERS:Content-Encoding "@rx (?i)br" "id:109618,phase:1,deny,status:415,msg:'Brotli payload blocked by Aegis'"
</IfModule>
%s
`, ApacheMarkerStart, ApacheMarkerEnd)

	modified := content + "\n" + patch
	err = writeConfigAtomically(canonical, []byte(modified))
	return err == nil, err
}
