package crawler

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/aegis/orchestrator/ledger"
)

const sampleNucleiJSONL = `{"template-id":"cve-2023-44487","info":{"name":"HTTP/2 Rapid Reset DDoS","author":["projectdiscovery"],"severity":"high","description":"Rapid reset flood exploits stream cancellations"},"type":"http","host":"https://example.com","matched-at":"https://example.com","ip":"93.184.216.34","timestamp":"2026-10-26T12:00:00Z"}
{"template-id":"tech-detect","info":{"name":"WAF Detection","author":["community"],"severity":"info"},"type":"http","host":"https://example.com","matched-at":"https://example.com/","timestamp":"2026-10-26T12:00:01Z"}
`

func TestNucleiParseJSONL(t *testing.T) {
	runner := NewNucleiRunner(NucleiRunnerConfig{})
	findings, err := runner.ParseJSONL(strings.NewReader(sampleNucleiJSONL))
	if err != nil {
		t.Fatalf("unexpected error parsing nuclei jsonl: %v", err)
	}

	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(findings))
	}

	f1 := findings[0]
	if f1.TemplateID != "cve-2023-44487" {
		t.Errorf("expected template cve-2023-44487, got %s", f1.TemplateID)
	}
	if f1.Info.Severity != "high" {
		t.Errorf("expected severity high, got %s", f1.Info.Severity)
	}
	if f1.IP != "93.184.216.34" {
		t.Errorf("expected ip 93.184.216.34, got %s", f1.IP)
	}

	f2 := findings[1]
	if f2.TemplateID != "tech-detect" {
		t.Errorf("expected template tech-detect, got %s", f2.TemplateID)
	}
}

func TestNucleiRunnerDryRunWithMock(t *testing.T) {
	runner := NewNucleiRunner(NucleiRunnerConfig{
		TargetURL:  "https://example.com",
		DryRun:     true,
		MockOutput: sampleNucleiJSONL,
		Timeout:    5 * time.Second,
	})

	if !runner.IsAvailable() {
		t.Error("expected runner to be available in dry-run mode")
	}

	findings, covLedger, err := runner.Run(context.Background())
	if err != nil {
		t.Fatalf("unexpected run error: %v", err)
	}

	if len(findings) != 2 {
		t.Errorf("expected 2 findings, got %d", len(findings))
	}

	if covLedger == nil {
		t.Fatal("expected non-nil coverage ledger")
	}

	if covLedger.CrawlStatus != ledger.CrawlStatusComplete {
		t.Errorf("expected crawl status complete, got %s", covLedger.CrawlStatus)
	}

	if len(covLedger.Assets) != 2 {
		t.Errorf("expected 2 runtime assets, got %d", len(covLedger.Assets))
	}

	asset := covLedger.Assets[0]
	if asset.Type != "dast_vulnerability" {
		t.Errorf("expected asset type dast_vulnerability, got %s", asset.Type)
	}
	if asset.Source != "nuclei" {
		t.Errorf("expected asset source nuclei, got %s", asset.Source)
	}
	if asset.Metadata["severity"] != "high" {
		t.Errorf("expected metadata severity high, got %s", asset.Metadata["severity"])
	}
}

func TestNucleiRunnerEmptyURLValidation(t *testing.T) {
	runner := NewNucleiRunner(NucleiRunnerConfig{
		TargetURL: "",
		DryRun:    false,
	})

	_, _, err := runner.Run(context.Background())
	if err == nil {
		t.Error("expected error when target URL is empty")
	}
}
