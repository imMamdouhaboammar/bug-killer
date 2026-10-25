package client

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aegis/orchestrator/crawler"
	"github.com/aegis/orchestrator/ledger"
)

func TestEndToEndUDSOrchestratorInspectorIPC(t *testing.T) {
	// 1. Locate the built Rust inspector binary or build it
	repoRoot, err := filepath.Abs("../../..")
	if err != nil {
		t.Fatalf("failed to determine repo root: %v", err)
	}

	inspectorBin := filepath.Join(repoRoot, "services/inspector/target/debug/bug-killer-inspector")
	if _, err := os.Stat(inspectorBin); os.IsNotExist(err) {
		t.Log("[*] Compiling Rust inspector binary for integration test...")
		buildCmd := exec.Command("cargo", "build", "--bin", "bug-killer-inspector")
		buildCmd.Dir = filepath.Join(repoRoot, "services/inspector")
		if out, err := buildCmd.CombinedOutput(); err != nil {
			t.Fatalf("failed to build bug-killer-inspector: %v\nOutput: %s", err, string(out))
		}
	}

	sockPath := fmt.Sprintf("/tmp/omni_e2e_%d.sock", time.Now().UnixNano())
	_ = os.Remove(sockPath)

	// 2. Spawn Rust inspector in background on UDS socket
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cmd := exec.CommandContext(ctx, inspectorBin, "--socket", sockPath)
	if err := cmd.Start(); err != nil {
		t.Fatalf("failed to start inspector daemon: %v", err)
	}
	defer func() {
		cancel()
		_ = cmd.Process.Kill()
		_ = os.Remove(sockPath)
	}()

	// Wait for socket readiness
	ready := false
	for i := 0; i < 20; i++ {
		if _, err := os.Stat(sockPath); err == nil {
			ready = true
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !ready {
		t.Fatalf("Rust inspector failed to bind UDS socket %s within 2s", sockPath)
	}

	// 3. Connect Service A (Go Client) over UDS
	ic, err := NewInspectorClient(sockPath)
	if err != nil {
		t.Fatalf("failed to connect to UDS socket: %v", err)
	}
	defer ic.Close()

	// 4. Test Binary Inspection via UDS
	reqCtx, reqCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer reqCancel()

	binResp, err := ic.InspectBinaryFile(reqCtx, "/bin/ls")
	if err != nil {
		t.Fatalf("InspectBinaryFile RPC failed: %v", err)
	}

	t.Logf("[✓] Discovered Binary Format: %s, Arch: %v, Hardening: %+v",
		binResp.BinaryFormat, binResp.DetectedArch, binResp.HardeningFlags)

	if !strings.HasPrefix(binResp.BinaryFormat, "Mach-O") && binResp.BinaryFormat != "ELF" {
		t.Errorf("expected Mach-O or ELF format, got: %s", binResp.BinaryFormat)
	}

	// 5. Test Packet Stream Inspection via UDS
	maliciousPayload := []byte("POST /api/upload HTTP/1.1\r\nContent-Encoding: br\r\nTransfer-Encoding: chunked\r\n\r\n")
	pktResp, err := ic.InspectPacketStream(reqCtx, "sess-e2e-1", "lo0", "127.0.0.1:9000", "127.0.0.1:80", "TCP", maliciousPayload, nil)
	if err != nil {
		t.Fatalf("InspectPacketStream RPC failed: %v", err)
	}

	if !pktResp.MaliciousIntentDetected {
		t.Errorf("expected MaliciousIntentDetected=true for Brotli chunked corruption payload")
	}
	if pktResp.RecommendedWafAction != "DROP_415_UNSUPPORTED_MEDIA_TYPE" {
		t.Errorf("expected DROP_415_UNSUPPORTED_MEDIA_TYPE, got %s", pktResp.RecommendedWafAction)
	}

	t.Logf("[✓] UDS Intercept Result: Detected=%v, Action=%s, Severity=%v",
		pktResp.MaliciousIntentDetected, pktResp.RecommendedWafAction, pktResp.Severity)

	// 6. Test Crawler Discovery, Structured CrawlResult, and Coverage Ledger Integration
	testScanDir := t.TempDir()
	_ = os.WriteFile(filepath.Join(testScanDir, "package.json"), []byte(`{"name":"e2e-service"}`), 0644)
	_ = os.WriteFile(filepath.Join(testScanDir, "nginx.conf"), []byte(`server { listen 80; }`), 0644)
	_ = os.Mkdir(filepath.Join(testScanDir, "node_modules"), 0755)
	_ = os.WriteFile(filepath.Join(testScanDir, "node_modules", "package.json"), []byte(`{}`), 0644)

	fc := crawler.NewFileCrawler(crawler.CrawlerConfig{
		RootPaths:     []string{testScanDir},
		ExcludeDirs:   []string{"node_modules"},
		CollectBinary: false,
	})

	crawlRes := fc.Crawl()
	if crawlRes.Status != crawler.CrawlStatusComplete {
		t.Fatalf("expected CrawlStatusComplete, got %s (errors: %v)", crawlRes.Status, crawlRes.TraversalErrors)
	}
	if len(crawlRes.Assets) != 2 {
		t.Fatalf("expected 2 discovered assets (excluding node_modules), got %d", len(crawlRes.Assets))
	}
	if len(crawlRes.SkippedDirs) == 0 {
		t.Errorf("expected node_modules in SkippedDirs, got: %v", crawlRes.SkippedDirs)
	}

	covLedger := ledger.NewCoverageLedger("e2e-orchestrator-host")
	for _, a := range crawlRes.Assets {
		covLedger.AddAsset(a)
	}
	covLedger.RecordCrawlSummary(crawlRes.Status, crawlRes.SkippedDirs, crawlRes.TraversalErrors)
	if covLedger.TotalAssets != 2 {
		t.Errorf("expected 2 total assets in CoverageLedger, got %d", covLedger.TotalAssets)
	}

	ledgerFile := filepath.Join(testScanDir, "coverage-ledger.json")
	if err := covLedger.WriteToFile(ledgerFile); err != nil {
		t.Fatalf("failed to write coverage ledger file: %v", err)
	}
	t.Logf("[✓] E2E Crawler & Coverage Ledger verified: TotalAssets=%d, Status=%s, SkippedDirs=%v",
		covLedger.TotalAssets, covLedger.CrawlStatus, covLedger.SkippedDirs)
}
