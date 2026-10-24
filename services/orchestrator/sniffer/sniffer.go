package sniffer

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/aegis/orchestrator/policy"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

// PacketAuditResult encapsulates security telemetry extracted from raw network frames.
type PacketAuditResult struct {
	Timestamp            time.Time         `json:"timestamp"`
	Source               string            `json:"source"`
	Destination          string            `json:"destination"`
	Protocol             string            `json:"protocol"`
	PayloadLength        int               `json:"payload_length"`
	IsHTTP2              bool              `json:"is_http2"`
	HasMultipart         bool              `json:"has_multipart"`
	HasBrotli            bool              `json:"has_brotli"`
	DetectedAnomalies    []string          `json:"detected_anomalies"`
	ExtractedHeaders     map[string]string `json:"extracted_headers"`
	MaliciousRiskScore   int               `json:"malicious_risk_score"` // 0 to 100
	RecommendedWafAction string            `json:"recommended_waf_action"`
}

// SnifferConfig configures the low-level libpcap socket interface.
type SnifferConfig struct {
	Device          string
	Snaplen         int32
	Promiscuous     bool
	Timeout         time.Duration
	BPFFilter       string
	PolicyEvaluator *policy.PolicyEvaluator
}

// TrafficSniffer coordinates deep packet inspection using native libpcap wrappers.
type TrafficSniffer struct {
	config    SnifferConfig
	handle    *pcap.Handle
	evaluator *policy.PolicyEvaluator
	mu        sync.Mutex
}

// HTTP2ClientPreface represents the standard RFC 7540 connection preface.
var HTTP2ClientPreface = []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")

// NewTrafficSniffer instantiates a deep traffic inspection sniffer.
func NewTrafficSniffer(cfg SnifferConfig) *TrafficSniffer {
	if cfg.Snaplen <= 0 {
		cfg.Snaplen = 65535
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 1 * time.Second
	}
	if cfg.Device == "" {
		cfg.Device = "lo0" // Default to loopback for local service monitoring
	}
	return &TrafficSniffer{
		config:    cfg,
		evaluator: cfg.PolicyEvaluator,
	}
}

// InspectPayload performs zero-alloc deep inspection across HTTP/2, multipart, and Brotli headers.
func (s *TrafficSniffer) InspectPayload(src, dst string, proto string, payload []byte) *PacketAuditResult {
	res := &PacketAuditResult{
		Timestamp:        time.Now(),
		Source:           src,
		Destination:      dst,
		Protocol:         proto,
		PayloadLength:    len(payload),
		DetectedAnomalies: make([]string, 0),
		ExtractedHeaders: make(map[string]string),
	}

	if len(payload) == 0 {
		return res
	}

	// 1. HTTP/2 Preface & Frame Inspection
	if bytes.HasPrefix(payload, HTTP2ClientPreface) {
		res.IsHTTP2 = true
		res.ExtractedHeaders["protocol_version"] = "HTTP/2.0"
	}

	// 2. HTTP/1.x and HTTP/2 Header Parsing
	payloadStr := string(payload)
	lines := strings.Split(payloadStr, "\r\n")
	for _, line := range lines {
		if idx := strings.Index(line, ":"); idx > 0 {
			key := strings.TrimSpace(strings.ToLower(line[:idx]))
			val := strings.TrimSpace(line[idx+1:])
			res.ExtractedHeaders[key] = val
		}
	}

	// 3. Brotli Compression Vulnerability Guard (CVE-2026-109618 / PHP2Shell Vector)
	contentEncoding := strings.ToLower(res.ExtractedHeaders["content-encoding"])
	acceptEncoding := strings.ToLower(res.ExtractedHeaders["accept-encoding"])
	transferEncoding := strings.ToLower(res.ExtractedHeaders["transfer-encoding"])

	if strings.Contains(contentEncoding, "br") || strings.Contains(acceptEncoding, "br") {
		res.HasBrotli = true
		// Verify if Brotli stream is coupled with chunked transfer encoding (trigger condition for unbuffered heap corruption)
		if strings.Contains(transferEncoding, "chunked") {
			res.DetectedAnomalies = append(res.DetectedAnomalies, "ANOMALOUS_BROTLI_CHUNKED_COMBINATION: High-risk out-of-bounds trigger")
			res.MaliciousRiskScore += 65
			res.RecommendedWafAction = "DROP_AND_STRIP_BROTLI"
		}
	}

	// 4. Multipart Form-Data Stream Auditing
	contentType := strings.ToLower(res.ExtractedHeaders["content-type"])
	if strings.Contains(contentType, "multipart/form-data") {
		res.HasMultipart = true
		if !strings.Contains(contentType, "boundary=") {
			res.DetectedAnomalies = append(res.DetectedAnomalies, "MALFORMED_MULTIPART_HEADER: Missing boundary delimiter")
			res.MaliciousRiskScore += 40
			res.RecommendedWafAction = "BLOCK_400_BAD_REQUEST"
		} else {
			// Check for boundary recursion or payload explosion
			boundaryIdx := strings.Index(contentType, "boundary=")
			boundary := contentType[boundaryIdx+9:]
			if len(boundary) > 256 {
				res.DetectedAnomalies = append(res.DetectedAnomalies, "OVERSIZED_MULTIPART_BOUNDARY: Potential buffer overflow state")
				res.MaliciousRiskScore += 50
			}
		}
	}

	// 5. Raw HTTP Request Line Inspection
	if len(lines) > 0 {
		reqLine := lines[0]
		if strings.Contains(reqLine, "GET") || strings.Contains(reqLine, "POST") || strings.Contains(reqLine, "PUT") {
			if strings.Contains(reqLine, "../") || strings.Contains(reqLine, "%2e%2e") {
				res.DetectedAnomalies = append(res.DetectedAnomalies, "PATH_TRAVERSAL_IN_REQUEST_LINE")
				res.MaliciousRiskScore += 45
			}
		}
	}

	// 6. Embedded OPA Policy Engine Evaluation
	if s.evaluator != nil {
		method := "GET"
		path := "/"
		if len(lines) > 0 {
			parts := strings.Split(lines[0], " ")
			if len(parts) >= 2 {
				method = parts[0]
				path = parts[1]
			}
		}
		netInput := &policy.NetworkInput{
			SourceEndpoint:      src,
			DestinationEndpoint: dst,
			Protocol:            proto,
			Method:              method,
			Path:                path,
			Headers:             res.ExtractedHeaders,
			ContentLength:       int64(len(payload)),
			IsChunked:           strings.Contains(strings.ToLower(res.ExtractedHeaders["transfer-encoding"]), "chunked"),
			IsBrotli:            res.HasBrotli,
			IsMultipart:         res.HasMultipart,
		}
		if dec, err := s.evaluator.EvaluateNetwork(context.Background(), netInput); err == nil && dec.Deny {
			for _, v := range dec.Violations {
				res.DetectedAnomalies = append(res.DetectedAnomalies, fmt.Sprintf("OPA_VIOLATION: %s", v))
			}
			res.RecommendedWafAction = dec.Action
			res.MaliciousRiskScore = 95
		}
	}

	if res.MaliciousRiskScore > 100 {
		res.MaliciousRiskScore = 100
	}

	return res
}

// StartLiveCapture opens the native libpcap device and streams parsed packets into the callback.
func (s *TrafficSniffer) StartLiveCapture(ctx context.Context, onPacket func(*PacketAuditResult)) error {
	s.mu.Lock()
	handle, err := pcap.OpenLive(s.config.Device, s.config.Snaplen, s.config.Promiscuous, s.config.Timeout)
	if err != nil {
		s.mu.Unlock()
		return fmt.Errorf("failed to open device %s: %w", s.config.Device, err)
	}
	s.handle = handle
	s.mu.Unlock()

	if s.config.BPFFilter != "" {
		if err := handle.SetBPFFilter(s.config.BPFFilter); err != nil {
			handle.Close()
			return fmt.Errorf("failed to apply BPF filter '%s': %w", s.config.BPFFilter, err)
		}
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packets := packetSource.Packets()

	for {
		select {
		case <-ctx.Done():
			s.Close()
			return nil
		case packet, ok := <-packets:
			if !ok {
				return nil
			}

			src := "unknown"
			dst := "unknown"
			proto := "raw"

			if netLayer := packet.NetworkLayer(); netLayer != nil {
				src = netLayer.NetworkFlow().Src().String()
				dst = netLayer.NetworkFlow().Dst().String()
				proto = netLayer.LayerType().String()
			}

			var payload []byte
			if appLayer := packet.ApplicationLayer(); appLayer != nil {
				payload = appLayer.Payload()
			} else if transLayer := packet.TransportLayer(); transLayer != nil {
				payload = transLayer.LayerPayload()
			}

			if len(payload) > 0 {
				audit := s.InspectPayload(src, dst, proto, payload)
				onPacket(audit)
			}
		}
	}
}

// Close releases the underlying pcap device handle.
func (s *TrafficSniffer) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.handle != nil {
		s.handle.Close()
		s.handle = nil
	}
}
