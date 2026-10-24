package yara

import (
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/spf13/afero"
)

// RuleSeverity represents the risk level associated with a signature match.
type RuleSeverity string

const (
	SeverityLow      RuleSeverity = "LOW"
	SeverityMedium   RuleSeverity = "MEDIUM"
	SeverityHigh     RuleSeverity = "HIGH"
	SeverityCritical RuleSeverity = "CRITICAL"
)

// YaraRule defines a compiled static inspection pattern.
type YaraRule struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Description string            `json:"description"`
	Severity    RuleSeverity      `json:"severity"`
	Tags        []string          `json:"tags"`
	Patterns    []*regexp.Regexp  `json:"-"`
	RawPatterns []string          `json:"patterns"`
	Condition   string            `json:"condition"` // "ANY" or "ALL"
}

// YaraMatch encapsulates telemetry emitted when a rule fires on a target artifact.
type YaraMatch struct {
	RuleID         string       `json:"rule_id"`
	RuleName       string       `json:"rule_name"`
	Severity       RuleSeverity `json:"severity"`
	FilePath       string       `json:"file_path"`
	MatchedStrings []string     `json:"matched_strings"`
	MatchedOffsets []int64      `json:"matched_offsets"`
	Timestamp      time.Time    `json:"timestamp"`
}

// YaraScanner manages compiled rules and executes concurrent directory analysis.
type YaraScanner struct {
	rules   []*YaraRule
	fs      afero.Fs
	workers int
}

// DefaultBuiltinRules returns industry-standard detection signatures.
func DefaultBuiltinRules() []*YaraRule {
	return []*YaraRule{
		{
			ID:          "YARA-WEBSHELL-001",
			Name:        "Generic_PHP_Eval_Backdoor",
			Description: "Detects hidden PHP code evaluation and base64 decode webshells",
			Severity:    SeverityCritical,
			Tags:        []string{"webshell", "php", "backdoor"},
			RawPatterns: []string{
				`(?i)eval\s*\(\s*(base64_decode|gzinflate|str_rot13)`,
				`(?i)(system|passthru|shell_exec|exec|popen|proc_open)\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)`,
				`(?i)assert\s*\(\s*\$_(GET|POST|REQUEST)`,
			},
			Condition: "ANY",
		},
		{
			ID:          "YARA-PHP2SHELL-002",
			Name:        "PHP2Shell_Brotli_Memory_Corruption_Trigger",
			Description: "Detects CVE-2026-109618 / CVE-2026-109619 heap corruption trigger sequences",
			Severity:    SeverityCritical,
			Tags:        []string{"cve-2026-109618", "cve-2026-109619", "brotli", "php"},
			RawPatterns: []string{
				`(?i)brotli_uncompress\s*\(`,
				`(?i)Transfer-Encoding:\s*chunked`,
				`(?i)php:\/\/input`,
			},
			Condition: "ALL",
		},
		{
			ID:          "YARA-NODE2SHELL-003",
			Name:        "Node2Shell_Brotli_Decompress_Vulnerability",
			Description: "Detects CVE-2026-111497 Brotli decompression out-of-bounds heap trigger",
			Severity:    SeverityCritical,
			Tags:        []string{"cve-2026-111497", "node", "brotli"},
			RawPatterns: []string{
				`(?i)zlib\.createBrotliDecompress\s*\(`,
				`(?i)brotliDecompressSync\s*\(`,
				`(?i)zlib\.constants\.BROTLI_DECODER_PARAM`,
			},
			Condition: "ANY",
		},
		{
			ID:          "YARA-REV-SHELL-004",
			Name:        "Posix_Reverse_Shell_Primitive",
			Description: "Detects raw POSIX socket spawn or interactive shell redirection",
			Severity:    SeverityHigh,
			Tags:        []string{"reverse-shell", "posix"},
			RawPatterns: []string{
				`/bin/(sh|bash|zsh)\s+-i\s+>&`,
				`fsockopen\s*\(\s*["'](?:\d{1,3}\.){3}\d{1,3}["']`,
				`pty\.spawn\s*\(\s*["']/bin/`,
			},
			Condition: "ANY",
		},
	}
}

// NewYaraScanner initializes a dynamic scanner with compiled regex signatures.
func NewYaraScanner(rules []*YaraRule, fs afero.Fs, workers int) (*YaraScanner, error) {
	if fs == nil {
		fs = afero.NewOsFs()
	}
	if workers <= 0 {
		workers = 16
	}

	compiled := make([]*YaraRule, 0, len(rules))
	for _, r := range rules {
		compiledRule := &YaraRule{
			ID:          r.ID,
			Name:        r.Name,
			Description: r.Description,
			Severity:    r.Severity,
			Tags:        r.Tags,
			RawPatterns: r.RawPatterns,
			Condition:   r.Condition,
			Patterns:    make([]*regexp.Regexp, 0, len(r.RawPatterns)),
		}
		for _, pat := range r.RawPatterns {
			re, err := regexp.Compile(pat)
			if err != nil {
				return nil, err
			}
			compiledRule.Patterns = append(compiledRule.Patterns, re)
		}
		compiled = append(compiled, compiledRule)
	}

	return &YaraScanner{
		rules:   compiled,
		fs:      fs,
		workers: workers,
	}, nil
}

// ScanBytes evaluates an in-memory byte slice against all compiled signatures.
func (ys *YaraScanner) ScanBytes(path string, data []byte) []*YaraMatch {
	var matches []*YaraMatch

	for _, rule := range ys.rules {
		matchedStrings := make([]string, 0)
		matchedOffsets := make([]int64, 0)
		patternHitCount := 0

		for _, pat := range rule.Patterns {
			locs := pat.FindAllIndex(data, -1)
			if len(locs) > 0 {
				patternHitCount++
				for _, loc := range locs {
					matchedOffsets = append(matchedOffsets, int64(loc[0]))
					matchSample := string(data[loc[0]:loc[1]])
					if len(matchSample) > 64 {
						matchSample = matchSample[:64] + "..."
					}
					matchedStrings = append(matchedStrings, matchSample)
				}
			}
		}

		isFired := false
		if rule.Condition == "ALL" {
			if patternHitCount == len(rule.Patterns) && len(rule.Patterns) > 0 {
				isFired = true
			}
		} else { // "ANY"
			if patternHitCount > 0 {
				isFired = true
			}
		}

		if isFired {
			matches = append(matches, &YaraMatch{
				RuleID:         rule.ID,
				RuleName:       rule.Name,
				Severity:       rule.Severity,
				FilePath:       path,
				MatchedStrings: matchedStrings,
				MatchedOffsets: matchedOffsets,
				Timestamp:      time.Now(),
			})
		}
	}

	return matches
}

// ScanDirectory walks the filesystem and streams match events to onMatch callback.
func (ys *YaraScanner) ScanDirectory(root string, onMatch func(*YaraMatch)) error {
	fileChan := make(chan string, 1024)
	var wg sync.WaitGroup

	// Launch worker pool
	for i := 0; i < ys.workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for path := range fileChan {
				f, err := ys.fs.Open(path)
				if err != nil {
					continue
				}
				// Cap read to 10MB to avoid OOM on huge binaries/media
				buf := make([]byte, 10*1024*1024)
				n, readErr := f.Read(buf)
				f.Close()
				if readErr != nil && readErr != io.EOF {
					continue
				}

				matches := ys.ScanBytes(path, buf[:n])
				for _, m := range matches {
					onMatch(m)
				}
			}
		}()
	}

	// Walk directory
	walkErr := afero.Walk(ys.fs, root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			base := filepath.Base(path)
			if base == ".git" || base == "node_modules" || base == "vendor" {
				return filepath.SkipDir
			}
			return nil
		}
		// Skip non-relevant file types
		ext := strings.ToLower(filepath.Ext(path))
		if ext == ".png" || ext == ".jpg" || ext == ".mp4" || ext == ".zip" {
			return nil
		}
		fileChan <- path
		return nil
	})

	close(fileChan)
	wg.Wait()
	return walkErr
}
