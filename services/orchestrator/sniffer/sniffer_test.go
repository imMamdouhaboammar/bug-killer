package sniffer

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aegis/orchestrator/policy"
)

func TestTrafficSnifferHTTP2Detection(t *testing.T) {
	sn := NewTrafficSniffer(SnifferConfig{})

	h2Payload := append(HTTP2ClientPreface, []byte("\x00\x00\x00\x04\x00\x00\x00\x00\x00")...)
	res := sn.InspectPayload("127.0.0.1:54321", "127.0.0.1:8080", "TCP", h2Payload)

	if !res.IsHTTP2 {
		t.Fatalf("expected IsHTTP2 to be true, got false")
	}
	if res.ExtractedHeaders["protocol_version"] != "HTTP/2.0" {
		t.Fatalf("expected protocol_version HTTP/2.0, got %s", res.ExtractedHeaders["protocol_version"])
	}
}

func TestTrafficSnifferBrotliChunkedAnomaly(t *testing.T) {
	sn := NewTrafficSniffer(SnifferConfig{})

	maliciousPayload := []byte("POST /upload HTTP/1.1\r\n" +
		"Host: localhost:8000\r\n" +
		"Content-Encoding: br\r\n" +
		"Transfer-Encoding: chunked\r\n" +
		"\r\n" +
		"1a\r\n" +
		"corrupted_brotli_stream_data\r\n" +
		"0\r\n\r\n")

	res := sn.InspectPayload("192.168.1.10:45000", "192.168.1.5:80", "TCP", maliciousPayload)

	if !res.HasBrotli {
		t.Fatalf("expected HasBrotli to be true, got false")
	}
	if len(res.DetectedAnomalies) == 0 {
		t.Fatalf("expected detected anomalies for Brotli+Chunked combination, got none")
	}
	if res.RecommendedWafAction != "DROP_AND_STRIP_BROTLI" {
		t.Fatalf("expected WAF action DROP_AND_STRIP_BROTLI, got %s", res.RecommendedWafAction)
	}
	if res.MaliciousRiskScore < 60 {
		t.Fatalf("expected MaliciousRiskScore >= 60, got %d", res.MaliciousRiskScore)
	}
}

func TestTrafficSnifferMultipartBoundaryValidation(t *testing.T) {
	sn := NewTrafficSniffer(SnifferConfig{})

	invalidMultipart := []byte("POST /api/form HTTP/1.1\r\n" +
		"Host: localhost\r\n" +
		"Content-Type: multipart/form-data\r\n" +
		"\r\n")

	res := sn.InspectPayload("10.0.0.1:50000", "10.0.0.2:443", "TCP", invalidMultipart)

	if !res.HasMultipart {
		t.Fatalf("expected HasMultipart to be true")
	}
	if res.RecommendedWafAction != "BLOCK_400_BAD_REQUEST" {
		t.Fatalf("expected BLOCK_400_BAD_REQUEST, got %s", res.RecommendedWafAction)
	}
}

func TestTrafficSnifferWithEmbeddedOPA(t *testing.T) {
	rulePath := filepath.Join("..", "policy", "rules", "runtime_policy.rego")
	evaluator, err := policy.NewPolicyEvaluator(context.Background(), policy.EvaluatorConfig{
		RulePaths: []string{rulePath},
	})
	if err != nil {
		t.Fatalf("failed to initialize policy evaluator: %v", err)
	}

	sn := NewTrafficSniffer(SnifferConfig{
		PolicyEvaluator: evaluator,
	})

	maliciousPayload := []byte("POST /api/data HTTP/1.1\r\n" +
		"Host: localhost:8080\r\n" +
		"Content-Encoding: br\r\n" +
		"Transfer-Encoding: chunked\r\n" +
		"\r\n" +
		"payload\r\n")

	res := sn.InspectPayload("10.10.10.1:12345", "10.10.10.2:80", "TCP", maliciousPayload)

	foundOPAViolation := false
	for _, anom := range res.DetectedAnomalies {
		if strings.Contains(anom, "OPA_VIOLATION: CVE-2026-109618") {
			foundOPAViolation = true
			break
		}
	}

	if !foundOPAViolation {
		t.Errorf("expected OPA_VIOLATION for CVE-2026-109618, anomalies: %v", res.DetectedAnomalies)
	}
	if res.RecommendedWafAction != "DROP_415" {
		t.Errorf("expected RecommendedWafAction=DROP_415, got %s", res.RecommendedWafAction)
	}
}
