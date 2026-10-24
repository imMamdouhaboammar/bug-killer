package policy

import (
	"hash/fnv"
	"sort"
	"strconv"
	"time"
)

// NetworkInput maps inbound network traffic frames for Rego policy evaluation.
type NetworkInput struct {
	SourceEndpoint      string            `json:"source_endpoint"`
	DestinationEndpoint string            `json:"destination_endpoint"`
	Protocol            string            `json:"protocol"`
	Method              string            `json:"method"`
	Path                string            `json:"path"`
	Headers             map[string]string `json:"headers"`
	ContentLength       int64             `json:"content_length"`
	IsChunked           bool              `json:"is_chunked"`
	IsBrotli            bool              `json:"is_brotli"`
	IsMultipart         bool              `json:"is_multipart"`
	PayloadSample       string            `json:"payload_sample"`
}

// ProcessSecurityFlags reflects binary runtime hardening state.
type ProcessSecurityFlags struct {
	PIE             bool `json:"pie"`
	NX              bool `json:"nx"`
	RELRO           bool `json:"relro"`
	StackCanary     bool `json:"stack_canary"`
	FortifiedSource bool `json:"fortified_source"`
}

// ProcessInput maps host process and execution telemetry for Rego policy evaluation.
type ProcessInput struct {
	PID                 int32                `json:"pid"`
	PPID                int32                `json:"ppid"`
	BinaryPath          string               `json:"binary_path"`
	BinaryVersion       string               `json:"binary_version"`
	Arguments           []string             `json:"arguments"`
	EnvironmentVars     map[string]string    `json:"environment_vars"`
	IsPrivileged        bool                 `json:"is_privileged"`
	HasDangerousSymbols bool                 `json:"has_dangerous_symbols"`
	DangerousSymbols    []string             `json:"dangerous_symbols"`
	MissingCleanups     []string             `json:"missing_cleanups"`
	SecurityFlags       ProcessSecurityFlags `json:"security_flags"`
}

// PolicyDecision encapsulates the verdict returned by the embedded OPA engine.
type PolicyDecision struct {
	Allow       bool      `json:"allow"`
	Deny        bool      `json:"deny"`
	Violations  []string  `json:"violations"`
	Action      string    `json:"action"`   // "ALLOW", "DROP_415", "BLOCK_400", "KILL_PROCESS", "DROP"
	Severity    string    `json:"severity"` // "LOW", "MEDIUM", "HIGH", "CRITICAL"
	EvaluatedAt time.Time `json:"evaluated_at"`
	CacheHit    bool      `json:"cache_hit"`
	RuleCount   int       `json:"rule_count"`
}

// HashKey computes a fast, non-cryptographic 64-bit FNV-1a hash of the network payload.
func (n *NetworkInput) HashKey() uint64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte(n.Method))
	_, _ = h.Write([]byte(":"))
	_, _ = h.Write([]byte(n.Path))
	_, _ = h.Write([]byte(":"))
	_, _ = h.Write([]byte(n.SourceEndpoint))
	_, _ = h.Write([]byte(":"))
	_, _ = h.Write([]byte(n.DestinationEndpoint))
	_, _ = h.Write([]byte(":"))
	_, _ = h.Write([]byte(strconv.FormatBool(n.IsChunked)))
	_, _ = h.Write([]byte(":"))
	_, _ = h.Write([]byte(strconv.FormatBool(n.IsBrotli)))
	_, _ = h.Write([]byte(":"))
	_, _ = h.Write([]byte(strconv.FormatBool(n.IsMultipart)))

	// Deterministic header hashing
	if len(n.Headers) > 0 {
		keys := make([]string, 0, len(n.Headers))
		for k := range n.Headers {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			_, _ = h.Write([]byte(k))
			_, _ = h.Write([]byte("="))
			_, _ = h.Write([]byte(n.Headers[k]))
			_, _ = h.Write([]byte(";"))
		}
	}
	return h.Sum64()
}

// HashKey computes a fast 64-bit FNV-1a hash of the process runtime telemetry.
func (p *ProcessInput) HashKey() uint64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte(strconv.FormatInt(int64(p.PID), 10)))
	_, _ = h.Write([]byte(":"))
	_, _ = h.Write([]byte(p.BinaryPath))
	_, _ = h.Write([]byte(":"))
	_, _ = h.Write([]byte(p.BinaryVersion))
	_, _ = h.Write([]byte(":"))
	_, _ = h.Write([]byte(strconv.FormatBool(p.IsPrivileged)))
	_, _ = h.Write([]byte(":"))
	_, _ = h.Write([]byte(strconv.FormatBool(p.HasDangerousSymbols)))

	for _, arg := range p.Arguments {
		_, _ = h.Write([]byte(arg))
		_, _ = h.Write([]byte(" "))
	}
	for _, cleanup := range p.MissingCleanups {
		_, _ = h.Write([]byte(cleanup))
		_, _ = h.Write([]byte(";"))
	}
	return h.Sum64()
}
