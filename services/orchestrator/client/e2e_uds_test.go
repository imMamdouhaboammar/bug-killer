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
}
