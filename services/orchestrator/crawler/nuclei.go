package crawler

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"time"

	"github.com/aegis/orchestrator/ledger"
)

// NucleiFinding represents a single vulnerability finding emitted by Nuclei JSONL output.
type NucleiFinding struct {
	TemplateID       string                 `json:"template-id"`
	Info             NucleiInfo             `json:"info"`
	MatchedAt        string                 `json:"matched-at"`
	Type             string                 `json:"type"`
	Host             string                 `json:"host"`
	IP               string                 `json:"ip,omitempty"`
	Timestamp        string                 `json:"timestamp"`
	ExtractedResults []string               `json:"extracted-results,omitempty"`
	Metadata         map[string]interface{} `json:"metadata,omitempty"`
}

// NucleiInfo captures metadata from the matched Nuclei template.
type NucleiInfo struct {
	Name        string   `json:"name"`
	Author      any      `json:"author,omitempty"`
	Severity    string   `json:"severity"`
	Description string   `json:"description,omitempty"`
	Tags        any      `json:"tags,omitempty"`
	Reference   any      `json:"reference,omitempty"`
}

// NucleiRunnerConfig configures execution parameters for the Nuclei DAST runner.
type NucleiRunnerConfig struct {
	BinaryPath    string
	TargetURL     string
	TemplatesPath string
	Tags          []string
	Severity      []string
	Timeout       time.Duration
	DryRun        bool
	MockOutput    string
}

// NucleiRunner executes or emulates Nuclei security scans against targeted endpoints.
type NucleiRunner struct {
	config NucleiRunnerConfig
}

// NewNucleiRunner creates a new NucleiRunner with default parameters if unspecified.
func NewNucleiRunner(cfg NucleiRunnerConfig) *NucleiRunner {
	if cfg.BinaryPath == "" {
		cfg.BinaryPath = "nuclei"
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 60 * time.Second
	}
	return &NucleiRunner{config: cfg}
}

// IsAvailable checks whether the Nuclei CLI binary is installed and discoverable on PATH.
func (r *NucleiRunner) IsAvailable() bool {
	if r.config.DryRun {
		return true
	}
	_, err := exec.LookPath(r.config.BinaryPath)
	return err == nil
}

// ParseJSONL parses raw JSONL byte stream produced by Nuclei into structured findings.
func (r *NucleiRunner) ParseJSONL(reader io.Reader) ([]NucleiFinding, error) {
	var findings []NucleiFinding
	scanner := bufio.NewScanner(reader)
	// Support large output lines up to 1MB
	buf := make([]byte, 64*1024)
	scanner.Buffer(buf, 1024*1024)

	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}

		var f NucleiFinding
		if err := json.Unmarshal(line, &f); err != nil {
			// Skip malformed lines gracefully while recording valid items
			continue
		}
		if f.TemplateID != "" {
			findings = append(findings, f)
		}
	}

	if err := scanner.Err(); err != nil {
		return findings, fmt.Errorf("error scanning nuclei output: %w", err)
	}

	return findings, nil
}

// Run executes the Nuclei scan or returns simulated findings in DryRun mode.
func (r *NucleiRunner) Run(ctx context.Context) ([]NucleiFinding, *ledger.CoverageLedger, error) {
	if r.config.TargetURL == "" && !r.config.DryRun {
		return nil, nil, errors.New("target URL must not be empty for nuclei scan")
	}

	covLedger := ledger.NewCoverageLedger("nuclei-dast-runner")

	// If in dry-run mode or mock output provided, parse without executing subprocess
	if r.config.DryRun || r.config.MockOutput != "" {
		findings, err := r.ParseJSONL(strings.NewReader(r.config.MockOutput))
		if err != nil {
			covLedger.RecordCrawlSummary(ledger.CrawlStatusError, nil, []string{err.Error()})
			return nil, covLedger, err
		}
		for _, asset := range r.ToRuntimeAssets(findings) {
			covLedger.AddAsset(asset)
		}
		covLedger.RecordCrawlSummary(ledger.CrawlStatusComplete, nil, nil)
		return findings, covLedger, nil
	}

	if !r.IsAvailable() {
		err := fmt.Errorf("nuclei binary '%s' not found on PATH", r.config.BinaryPath)
		covLedger.RecordCrawlSummary(ledger.CrawlStatusError, nil, []string{err.Error()})
		return nil, covLedger, err
	}

	execCtx, cancel := context.WithTimeout(ctx, r.config.Timeout)
	defer cancel()

	args := []string{"-u", r.config.TargetURL, "-jsonl", "-silent"}
	if r.config.TemplatesPath != "" {
		args = append(args, "-t", r.config.TemplatesPath)
	}
	if len(r.config.Tags) > 0 {
		args = append(args, "-tags", strings.Join(r.config.Tags, ","))
	}
	if len(r.config.Severity) > 0 {
		args = append(args, "-s", strings.Join(r.config.Severity, ","))
	}

	cmd := exec.CommandContext(execCtx, r.config.BinaryPath, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil && stdout.Len() == 0 {
		errMsg := fmt.Sprintf("nuclei execution failed: %v, stderr: %s", err, stderr.String())
		covLedger.RecordCrawlSummary(ledger.CrawlStatusError, nil, []string{errMsg})
		return nil, covLedger, errors.New(errMsg)
	}

	findings, parseErr := r.ParseJSONL(&stdout)
	if parseErr != nil {
		covLedger.RecordCrawlSummary(ledger.CrawlStatusPartial, nil, []string{parseErr.Error()})
		return findings, covLedger, parseErr
	}

	for _, asset := range r.ToRuntimeAssets(findings) {
		covLedger.AddAsset(asset)
	}
	covLedger.RecordCrawlSummary(ledger.CrawlStatusComplete, nil, nil)

	return findings, covLedger, nil
}

// ToRuntimeAssets converts a slice of Nuclei findings into standard runtime assets for the ledger.
func (r *NucleiRunner) ToRuntimeAssets(findings []NucleiFinding) []ledger.RuntimeAsset {
	assets := make([]ledger.RuntimeAsset, 0, len(findings))
	for _, f := range findings {
		metadata := map[string]string{
			"template_id": f.TemplateID,
			"severity":    f.Info.Severity,
			"name":        f.Info.Name,
			"matched_at":  f.MatchedAt,
			"type":        f.Type,
		}
		if f.IP != "" {
			metadata["ip"] = f.IP
		}

		assets = append(assets, ledger.RuntimeAsset{
			Type:     "dast_vulnerability",
			Path:     f.MatchedAt,
			Version:  f.TemplateID,
			Source:   "nuclei",
			Metadata: metadata,
		})
	}
	return assets
}
