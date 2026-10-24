package policy

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestEvaluateNetworkBrotliChunkedDrop(t *testing.T) {
	rulePath := filepath.Join("rules", "runtime_policy.rego")
	evaluator, err := NewPolicyEvaluator(context.Background(), EvaluatorConfig{
		RulePaths: []string{rulePath},
	})
	if err != nil {
		t.Fatalf("failed to initialize policy evaluator: %v", err)
	}

	netInput := &NetworkInput{
		SourceEndpoint:      "192.168.1.100:54321",
		DestinationEndpoint: "10.0.0.5:80",
		Protocol:            "TCP",
		Method:              "POST",
		Path:                "/upload/stream",
		Headers: map[string]string{
			"content-encoding":  "br",
			"transfer-encoding": "chunked",
		},
		IsBrotli:  true,
		IsChunked: true,
	}

	dec, err := evaluator.EvaluateNetwork(context.Background(), netInput)
	if err != nil {
		t.Fatalf("evaluation error: %v", err)
	}

	if dec.Allow {
		t.Errorf("expected Brotli+Chunked request to be denied, but Allow=true")
	}
	if !dec.Deny {
		t.Errorf("expected Deny=true")
	}
	if dec.Action != "DROP_415" {
		t.Errorf("expected Action=DROP_415, got %s", dec.Action)
	}
	if dec.Severity != "CRITICAL" {
		t.Errorf("expected Severity=CRITICAL, got %s", dec.Severity)
	}
}

func TestEvaluateNetworkCleanTraffic(t *testing.T) {
	rulePath := filepath.Join("rules", "runtime_policy.rego")
	evaluator, err := NewPolicyEvaluator(context.Background(), EvaluatorConfig{
		RulePaths: []string{rulePath},
	})
	if err != nil {
		t.Fatalf("failed to initialize policy evaluator: %v", err)
	}

	netInput := &NetworkInput{
		SourceEndpoint:      "10.0.0.1:40000",
		DestinationEndpoint: "10.0.0.2:443",
		Protocol:            "TCP",
		Method:              "GET",
		Path:                "/api/v1/health",
		Headers: map[string]string{
			"accept": "application/json",
		},
		IsBrotli:  false,
		IsChunked: false,
	}

	dec, err := evaluator.EvaluateNetwork(context.Background(), netInput)
	if err != nil {
		t.Fatalf("evaluation error: %v", err)
	}

	if !dec.Allow {
		t.Errorf("expected clean GET request to be allowed, but Allow=false")
	}
	if dec.Deny {
		t.Errorf("expected Deny=false")
	}
	if dec.Action != "ALLOW" {
		t.Errorf("expected Action=ALLOW, got %s", dec.Action)
	}
}

func TestEvaluateProcessPHP2ShellExposure(t *testing.T) {
	rulePath := filepath.Join("rules", "runtime_policy.rego")
	evaluator, err := NewPolicyEvaluator(context.Background(), EvaluatorConfig{
		RulePaths: []string{rulePath},
	})
	if err != nil {
		t.Fatalf("failed to initialize policy evaluator: %v", err)
	}

	procInput := &ProcessInput{
		PID:                 1234,
		BinaryPath:          "/usr/sbin/php-fpm8.2",
		BinaryVersion:       "8.2.10",
		IsPrivileged:        false,
		HasDangerousSymbols: true,
		DangerousSymbols:    []string{"zend_hash_destroy", "longjmp"},
		MissingCleanups:     []string{"Unwound longjmp context without cleanup"},
		SecurityFlags: ProcessSecurityFlags{
			NX:          true,
			PIE:         true,
			RELRO:       true,
			StackCanary: true,
		},
	}

	dec, err := evaluator.EvaluateProcess(context.Background(), procInput)
	if err != nil {
		t.Fatalf("evaluation error: %v", err)
	}

	if dec.Allow {
		t.Errorf("expected vulnerable PHP-FPM process to be denied")
	}
	if dec.Severity != "CRITICAL" {
		t.Errorf("expected Severity=CRITICAL, got %s", dec.Severity)
	}
}

func TestEvaluateProcessNode2ShellPrivileged(t *testing.T) {
	rulePath := filepath.Join("rules", "runtime_policy.rego")
	evaluator, err := NewPolicyEvaluator(context.Background(), EvaluatorConfig{
		RulePaths: []string{rulePath},
	})
	if err != nil {
		t.Fatalf("failed to initialize policy evaluator: %v", err)
	}

	procInput := &ProcessInput{
		PID:                 5678,
		BinaryPath:          "/usr/local/bin/node",
		BinaryVersion:       "v20.10.0",
		IsPrivileged:        true,
		HasDangerousSymbols: true,
		DangerousSymbols:    []string{"BrotliDecoderCreateInstance"},
	}

	dec, err := evaluator.EvaluateProcess(context.Background(), procInput)
	if err != nil {
		t.Fatalf("evaluation error: %v", err)
	}

	if dec.Action != "KILL_PROCESS" {
		t.Errorf("expected Action=KILL_PROCESS for privileged vulnerable Node runtime, got %s", dec.Action)
	}
}

func TestDecisionCacheHitBypass(t *testing.T) {
	rulePath := filepath.Join("rules", "runtime_policy.rego")
	evaluator, err := NewPolicyEvaluator(context.Background(), EvaluatorConfig{
		RulePaths: []string{rulePath},
		CacheTTL:  1 * time.Minute,
	})
	if err != nil {
		t.Fatalf("failed to initialize policy evaluator: %v", err)
	}

	netInput := &NetworkInput{
		SourceEndpoint: "192.168.1.1:5000",
		Path:           "/static/logo.png",
		Method:         "GET",
	}

	// First evaluation -> Cache Miss
	dec1, err := evaluator.EvaluateNetwork(context.Background(), netInput)
	if err != nil {
		t.Fatalf("eval 1 failed: %v", err)
	}
	if dec1.CacheHit {
		t.Errorf("expected dec1.CacheHit=false on first evaluation")
	}

	// Second evaluation -> Cache Hit
	dec2, err := evaluator.EvaluateNetwork(context.Background(), netInput)
	if err != nil {
		t.Fatalf("eval 2 failed: %v", err)
	}
	if !dec2.CacheHit {
		t.Errorf("expected dec2.CacheHit=true on identical repeat evaluation")
	}
	if dec1.Action != dec2.Action {
		t.Errorf("cached action mismatch: dec1=%s, dec2=%s", dec1.Action, dec2.Action)
	}
}

func TestZeroDowntimeHotReload(t *testing.T) {
	tmpDir := t.TempDir()
	policyFile := filepath.Join(tmpDir, "custom.rego")

	basePolicy := `package omni.runtime
import future.keywords.contains
import future.keywords.if

default allow := true
default action := "ALLOW"
default severity := "LOW"

deny contains msg if {
    input.network.method == "TRACE"
    msg := "TRACE_BLOCKED"
}

action := "DROP" if count(deny) > 0 else := "ALLOW"

decision := {
    "allow": count(deny) == 0,
    "deny": count(deny) > 0,
    "violations": deny,
    "action": action,
    "severity": "MEDIUM",
}
`
	if err := os.WriteFile(policyFile, []byte(basePolicy), 0644); err != nil {
		t.Fatalf("failed to write policy: %v", err)
	}

	evaluator, err := NewPolicyEvaluator(context.Background(), EvaluatorConfig{
		RulePaths: []string{policyFile},
	})
	if err != nil {
		t.Fatalf("failed to initialize evaluator: %v", err)
	}

	// Test TRACE is denied
	traceReq := &NetworkInput{Method: "TRACE", Path: "/"}
	d1, err := evaluator.EvaluateNetwork(context.Background(), traceReq)
	if err != nil || d1.Allow {
		t.Fatalf("expected TRACE to be blocked")
	}

	// Update policy to also deny DELETE
	updatedPolicy := `package omni.runtime
import future.keywords.contains
import future.keywords.if

default allow := true
default action := "ALLOW"
default severity := "LOW"

deny contains msg if {
    input.network.method == "TRACE"
    msg := "TRACE_BLOCKED"
}
deny contains msg if {
    input.network.method == "DELETE"
    msg := "DELETE_BLOCKED"
}

action := "DROP" if count(deny) > 0 else := "ALLOW"

decision := {
    "allow": count(deny) == 0,
    "deny": count(deny) > 0,
    "violations": deny,
    "action": action,
    "severity": "HIGH",
}
`
	if err := os.WriteFile(policyFile, []byte(updatedPolicy), 0644); err != nil {
		t.Fatalf("failed to update policy file: %v", err)
	}

	// Atomic hot-reload
	if err := evaluator.Reload(context.Background()); err != nil {
		t.Fatalf("hot-reload failed: %v", err)
	}

	// Now DELETE must be denied without restarting
	deleteReq := &NetworkInput{Method: "DELETE", Path: "/resource/1"}
	d2, err := evaluator.EvaluateNetwork(context.Background(), deleteReq)
	if err != nil {
		t.Fatalf("eval error after reload: %v", err)
	}
	if d2.Allow {
		t.Errorf("expected DELETE to be blocked after hot reload")
	}
	if d2.Severity != "HIGH" {
		t.Errorf("expected updated severity HIGH, got %s", d2.Severity)
	}
}

func BenchmarkEvaluateNetworkCached(b *testing.B) {
	rulePath := filepath.Join("rules", "runtime_policy.rego")
	evaluator, _ := NewPolicyEvaluator(context.Background(), EvaluatorConfig{
		RulePaths: []string{rulePath},
		CacheTTL:  10 * time.Minute,
	})

	netInput := &NetworkInput{
		SourceEndpoint: "10.0.0.1:8080",
		Method:         "GET",
		Path:           "/safe/endpoint",
	}

	// Warm cache
	_, _ = evaluator.EvaluateNetwork(context.Background(), netInput)

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, _ = evaluator.EvaluateNetwork(context.Background(), netInput)
		}
	})
}
