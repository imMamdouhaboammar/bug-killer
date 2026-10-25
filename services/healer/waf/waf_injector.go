package waf

import (
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/spf13/afero"
)

const (
	NginxMarkerStart = "# --- BEGIN AEGIS VIRTUAL PATCH (CVE-2026-111497 / CVE-2026-109618) ---"
	NginxMarkerEnd   = "# --- END AEGIS VIRTUAL PATCH ---"

	HAProxyMarkerStart = "# --- BEGIN AEGIS HAPROXY GUARD ---"
	HAProxyMarkerEnd   = "# --- END AEGIS HAPROXY GUARD ---"

	ApacheMarkerStart = "# --- BEGIN AEGIS APACHE GUARD ---"
	ApacheMarkerEnd   = "# --- END AEGIS APACHE GUARD ---"
)

type WafInjector struct {
	fs                afero.Fs
	ExternalValidator func(configType, tempPath string) error
}

func NewWafInjector() *WafInjector {
	return &WafInjector{
		fs: afero.NewOsFs(),
	}
}

func NewWafInjectorWithFs(fs afero.Fs) *WafInjector {
	if fs == nil {
		fs = afero.NewOsFs()
	}
	return &WafInjector{
		fs: fs,
	}
}

func (w *WafInjector) readConfig(configPath string) (string, []byte, error) {
	// Resolve symlinks if running against OS filesystem
	canonical := configPath
	if _, ok := w.fs.(*afero.OsFs); ok {
		resolved, err := filepath.EvalSymlinks(configPath)
		if err == nil {
			canonical = resolved
		}
	} else if w.fs == nil {
		resolved, err := filepath.EvalSymlinks(configPath)
		if err == nil {
			canonical = resolved
		}
	}
	data, err := afero.ReadFile(w.fs, canonical)
	return canonical, data, err
}

func (w *WafInjector) writeConfigAtomically(canonical string, content []byte) error {
	info, err := w.fs.Stat(canonical)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("refusing to patch non-regular configuration file: %s", canonical)
	}

	dir := filepath.Dir(canonical)
	temp, err := afero.TempFile(w.fs, dir, ".bug-killer-waf-*")
	if err != nil {
		return fmt.Errorf("failed to create temp file: %w", err)
	}
	tempName := temp.Name()
	committed := false
	defer func() {
		if !committed {
			_ = w.fs.Remove(tempName)
		}
	}()

	if err := w.fs.Chmod(tempName, info.Mode().Perm()); err != nil {
		_ = temp.Close()
		return fmt.Errorf("failed to chmod temp file: %w", err)
	}

	if _, err := temp.Write(content); err != nil {
		_ = temp.Close()
		return fmt.Errorf("failed to write temp file: %w", err)
	}

	if syncer, ok := temp.(interface{ Sync() error }); ok {
		_ = syncer.Sync()
	}

	if err := temp.Close(); err != nil {
		return fmt.Errorf("failed to close temp file: %w", err)
	}

	if err := w.fs.Rename(tempName, canonical); err != nil {
		return fmt.Errorf("failed to atomically replace config file: %w", err)
	}

	committed = true
	return nil
}

// ValidateNginxConfig performs safe dry-run syntax verification on Nginx configuration text.
// Validates balanced braces, unclosed quotes, and marker integrity.
func ValidateNginxConfig(content string) error {
	braceDepth := 0
	inSingleQuote := false
	inDoubleQuote := false
	escaped := false
	inComment := false

	runes := []rune(content)
	for i := 0; i < len(runes); i++ {
		r := runes[i]

		if inComment {
			if r == '\n' {
				inComment = false
			}
			continue
		}

		if escaped {
			escaped = false
			continue
		}

		if r == '\\' {
			escaped = true
			continue
		}

		if r == '\'' && !inDoubleQuote {
			inSingleQuote = !inSingleQuote
			continue
		}
		if r == '"' && !inSingleQuote {
			inDoubleQuote = !inDoubleQuote
			continue
		}

		if inSingleQuote || inDoubleQuote {
			continue
		}

		if r == '#' {
			inComment = true
			continue
		}

		if r == '{' {
			braceDepth++
		} else if r == '}' {
			braceDepth--
			if braceDepth < 0 {
				return errors.New("nginx syntax error: unmatched closing brace '}'")
			}
		}
	}

	if inSingleQuote || inDoubleQuote {
		return errors.New("nginx syntax error: unclosed quote")
	}

	if braceDepth != 0 {
		return fmt.Errorf("nginx syntax error: %d unclosed brace(s)", braceDepth)
	}

	if strings.Contains(content, NginxMarkerStart) && !strings.Contains(content, NginxMarkerEnd) {
		return errors.New("nginx syntax error: corrupted Aegis marker pair (missing marker end)")
	}

	return nil
}

// ValidateHAProxyConfig performs dry-run syntax verification on HAProxy configuration text.
func ValidateHAProxyConfig(content string) error {
	if strings.Contains(content, HAProxyMarkerStart) && !strings.Contains(content, HAProxyMarkerEnd) {
		return errors.New("haproxy syntax error: corrupted Aegis marker pair (missing marker end)")
	}

	inSingleQuote := false
	inDoubleQuote := false
	escaped := false

	runes := []rune(content)
	for i := 0; i < len(runes); i++ {
		r := runes[i]
		if escaped {
			escaped = false
			continue
		}
		if r == '\\' {
			escaped = true
			continue
		}
		if r == '\'' && !inDoubleQuote {
			inSingleQuote = !inSingleQuote
		} else if r == '"' && !inSingleQuote {
			inDoubleQuote = !inDoubleQuote
		}
	}

	if inSingleQuote || inDoubleQuote {
		return errors.New("haproxy syntax error: unclosed quote")
	}

	return nil
}

// ValidateApacheConfig performs dry-run syntax verification on Apache configuration text.
// Validates balanced XML-like configuration directive tags (<Tag>...</Tag>).
func ValidateApacheConfig(content string) error {
	if strings.Contains(content, ApacheMarkerStart) && !strings.Contains(content, ApacheMarkerEnd) {
		return errors.New("apache syntax error: corrupted Aegis marker pair (missing marker end)")
	}

	tagRegex := regexp.MustCompile(`(?i)</?([a-zA-Z0-9_]+)[^>]*>`)
	var tagStack []string

	lines := strings.Split(content, "\n")
	for lineNum, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			continue // Skip comments
		}

		matches := tagRegex.FindAllStringSubmatch(trimmed, -1)
		for _, m := range matches {
			fullTag := m[0]
			tagName := strings.ToLower(m[1])

			// Skip self-closing or XML headers
			if strings.HasSuffix(fullTag, "/>") || strings.HasPrefix(fullTag, "<?") {
				continue
			}

			if strings.HasPrefix(fullTag, "</") {
				// Closing tag
				if len(tagStack) == 0 {
					return fmt.Errorf("apache syntax error at line %d: unexpected closing tag </%s>", lineNum+1, tagName)
				}
				last := tagStack[len(tagStack)-1]
				if last != tagName {
					return fmt.Errorf("apache syntax error at line %d: mismatched closing tag </%s>, expected </%s>", lineNum+1, tagName, last)
				}
				tagStack = tagStack[:len(tagStack)-1]
			} else {
				// Opening tag
				tagStack = append(tagStack, tagName)
			}
		}
	}

	if len(tagStack) > 0 {
		return fmt.Errorf("apache syntax error: unclosed tag <%s>", tagStack[len(tagStack)-1])
	}

	return nil
}

func (w *WafInjector) runExternalCheck(configType, tempPath string) error {
	if w.ExternalValidator != nil {
		return w.ExternalValidator(configType, tempPath)
	}

	switch configType {
	case "nginx":
		if path, err := exec.LookPath("nginx"); err == nil {
			// Only run if nginx binary is functional and can validate standalone config
			cmd := exec.Command(path, "-t", "-c", tempPath)
			out, err := cmd.CombinedOutput()
			// If error is about missing events directive (snippet config), ignore
			if err != nil && !strings.Contains(string(out), "events") {
				return fmt.Errorf("nginx -t verification failed: %s (%w)", string(out), err)
			}
		}
	case "haproxy":
		if path, err := exec.LookPath("haproxy"); err == nil {
			cmd := exec.Command(path, "-c", "-f", tempPath)
			if out, err := cmd.CombinedOutput(); err != nil {
				return fmt.Errorf("haproxy -c verification failed: %s (%w)", string(out), err)
			}
		}
	case "apache":
		if path, err := exec.LookPath("apachectl"); err == nil {
			cmd := exec.Command(path, "-t", "-f", tempPath)
			out, err := cmd.CombinedOutput()
			// If error is about MPM not loaded (standard test snippet), ignore
			if err != nil && !strings.Contains(string(out), "AH00534") {
				return fmt.Errorf("apachectl -t verification failed: %s (%w)", string(out), err)
			}
		}
	}
	return nil
}

func (w *WafInjector) InjectNginx(configPath string) (bool, error) {
	canonical, data, err := w.readConfig(configPath)
	if err != nil {
		return false, err
	}

	content := string(data)
	if strings.Contains(content, NginxMarkerStart) {
		return false, nil // Idempotent
	}

	// Validate original content first
	if err := ValidateNginxConfig(content); err != nil {
		return false, fmt.Errorf("refusing to patch invalid nginx config: %w", err)
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

	// Safe anchoring: Find all active (non-commented) server { blocks
	// Anchoring right inside each active server { block.
	lines := strings.Split(content, "\n")
	var modifiedLines []string
	inComment := false
	inActiveServer := false
	inServerBraceFound := false
	serverPatched := false

	serverRegex := regexp.MustCompile(`(^|\s)server(\s*\{|\s*$)`)

	for i := 0; i < len(lines); i++ {
		line := lines[i]
		trimmed := strings.TrimSpace(line)

		// Check if line is purely comment
		if strings.HasPrefix(trimmed, "#") {
			modifiedLines = append(modifiedLines, line)
			continue
		}

		// Strip inline comment for detection
		codePart := line
		if idx := strings.Index(line, "#"); idx != -1 {
			codePart = line[:idx]
		}

		if !inActiveServer && serverRegex.MatchString(codePart) {
			inActiveServer = true
			if strings.Contains(codePart, "{") {
				inServerBraceFound = true
				// Inject patch right after opening brace on this line
				braceIdx := strings.Index(line, "{")
				modifiedLines = append(modifiedLines, line[:braceIdx+1]+patch+line[braceIdx+1:])
				serverPatched = true
				inActiveServer = false
				inServerBraceFound = false
				continue
			}
		} else if inActiveServer && !inServerBraceFound && strings.Contains(codePart, "{") {
			inServerBraceFound = true
			braceIdx := strings.Index(line, "{")
			modifiedLines = append(modifiedLines, line[:braceIdx+1]+patch+line[braceIdx+1:])
			serverPatched = true
			inActiveServer = false
			inServerBraceFound = false
			continue
		}

		modifiedLines = append(modifiedLines, line)
	}

	_ = inComment

	var modified string
	if serverPatched {
		modified = strings.Join(modifiedLines, "\n")
	} else {
		// If no active server block found, check for active location /
		locationRegex := regexp.MustCompile(`(^|\s)location\s+/[^{]*\{`)
		locPatched := false
		modifiedLines = nil
		for _, line := range lines {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "#") {
				modifiedLines = append(modifiedLines, line)
				continue
			}
			codePart := line
			if idx := strings.Index(line, "#"); idx != -1 {
				codePart = line[:idx]
			}
			if !locPatched && locationRegex.MatchString(codePart) {
				modifiedLines = append(modifiedLines, patch)
				locPatched = true
			}
			modifiedLines = append(modifiedLines, line)
		}
		if locPatched {
			modified = strings.Join(modifiedLines, "\n")
		} else {
			modified = content + "\n" + patch
		}
	}

	// Verify syntax before writing
	if err := ValidateNginxConfig(modified); err != nil {
		return false, fmt.Errorf("injected nginx configuration failed syntax validation: %w", err)
	}

	// Atomic write with rollback on error
	if err := w.writeConfigAtomically(canonical, []byte(modified)); err != nil {
		return false, err
	}

	return true, nil
}

func (w *WafInjector) InjectHAProxy(configPath string) (bool, error) {
	canonical, data, err := w.readConfig(configPath)
	if err != nil {
		return false, err
	}

	content := string(data)
	if strings.Contains(content, HAProxyMarkerStart) {
		return false, nil // Idempotent
	}

	if err := ValidateHAProxyConfig(content); err != nil {
		return false, fmt.Errorf("refusing to patch invalid haproxy config: %w", err)
	}

	patch := fmt.Sprintf(`
    %s
    # Drop Brotli compressed bodies targeting Node upstream backends
    acl is_brotli_payload req.hdr(content-encoding) -m sub br
    http-request deny deny_status 415 if is_brotli_payload
    %s
`, HAProxyMarkerStart, HAProxyMarkerEnd)

	// Safe anchoring: Find active frontend or listen sections (skip comments)
	lines := strings.Split(content, "\n")
	var modifiedLines []string
	frontendPatched := false

	frontendRegex := regexp.MustCompile(`^(frontend|listen)\s+\S+`)

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		modifiedLines = append(modifiedLines, line)

		if strings.HasPrefix(trimmed, "#") {
			continue // comment
		}

		if frontendRegex.MatchString(trimmed) {
			// Inject patch after active frontend declaration
			modifiedLines = append(modifiedLines, patch)
			frontendPatched = true
		}
	}

	var modified string
	if frontendPatched {
		modified = strings.Join(modifiedLines, "\n")
	} else {
		modified = content + "\n" + patch
	}

	if err := ValidateHAProxyConfig(modified); err != nil {
		return false, fmt.Errorf("injected haproxy configuration failed syntax validation: %w", err)
	}

	if err := w.writeConfigAtomically(canonical, []byte(modified)); err != nil {
		return false, err
	}

	return true, nil
}

func (w *WafInjector) InjectApache(configPath string) (bool, error) {
	canonical, data, err := w.readConfig(configPath)
	if err != nil {
		return false, err
	}

	content := string(data)
	if strings.Contains(content, ApacheMarkerStart) {
		return false, nil // Idempotent
	}

	if err := ValidateApacheConfig(content); err != nil {
		return false, fmt.Errorf("refusing to patch invalid apache config: %w", err)
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

	// Safe anchoring: Inject inside active <VirtualHost ...> blocks if present
	lines := strings.Split(content, "\n")
	var modifiedLines []string
	vhostPatched := false

	vhostOpenRegex := regexp.MustCompile(`(?i)^\s*<VirtualHost\b[^>]*>`)

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		modifiedLines = append(modifiedLines, line)

		if strings.HasPrefix(trimmed, "#") {
			continue // comment
		}

		if vhostOpenRegex.MatchString(trimmed) {
			modifiedLines = append(modifiedLines, patch)
			vhostPatched = true
		}
	}

	var modified string
	if vhostPatched {
		modified = strings.Join(modifiedLines, "\n")
	} else {
		modified = content + "\n" + patch
	}

	if err := ValidateApacheConfig(modified); err != nil {
		return false, fmt.Errorf("injected apache configuration failed syntax validation: %w", err)
	}

	if err := w.writeConfigAtomically(canonical, []byte(modified)); err != nil {
		return false, err
	}

	return true, nil
}

// Rollback strips any Aegis WAF virtual patch blocks from the given configuration file.
func (w *WafInjector) Rollback(configPath string) (bool, error) {
	canonical, data, err := w.readConfig(configPath)
	if err != nil {
		return false, err
	}

	content := string(data)
	modified := content
	changed := false

	markerPairs := [][2]string{
		{NginxMarkerStart, NginxMarkerEnd},
		{HAProxyMarkerStart, HAProxyMarkerEnd},
		{ApacheMarkerStart, ApacheMarkerEnd},
	}

	for _, pair := range markerPairs {
		startM, endM := pair[0], pair[1]
		for {
			startIdx := strings.Index(modified, startM)
			if startIdx == -1 {
				break
			}
			endIdx := strings.Index(modified, endM)
			if endIdx == -1 {
				return false, fmt.Errorf("corrupted markers in %s: missing %s", configPath, endM)
			}
			cutEnd := endIdx + len(endM)
			// Trim optional trailing newline
			if cutEnd < len(modified) && modified[cutEnd] == '\n' {
				cutEnd++
			}
			modified = modified[:startIdx] + modified[cutEnd:]
			changed = true
		}
	}

	if !changed {
		return false, nil
	}

	if err := w.writeConfigAtomically(canonical, []byte(modified)); err != nil {
		return false, err
	}

	return true, nil
}

func (w *WafInjector) RollbackNginx(configPath string) (bool, error) {
	return w.Rollback(configPath)
}

func (w *WafInjector) RollbackHAProxy(configPath string) (bool, error) {
	return w.Rollback(configPath)
}

func (w *WafInjector) RollbackApache(configPath string) (bool, error) {
	return w.Rollback(configPath)
}
