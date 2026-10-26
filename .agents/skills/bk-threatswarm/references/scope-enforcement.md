# Scope Enforcement Engine Specification

The `bk-threatswarm` scope enforcer provides zero-trust boundary verification to prevent unauthorized outbound reconnaissance, exfiltration, or lateral connectivity during autonomous agent execution.

## Scope Rule Format (`scope.txt`)

Lines in `scope.txt` are parsed into three canonical types:

```text
# IPv4 CIDR blocks
10.0.0.0/8
192.168.1.0/24
172.16.50.0/28

# Single IPv4 addresses
10.10.10.5
198.51.100.22

# FQDN hostnames and wildcard subdomains
api.staging.internal
*.internal.corp
gateway.local
```

Lines beginning with `#` or `//` and empty lines are discarded as comments.

## Target Extraction & Detection Regexes

```rust
static RE_NETWORK_COMMANDS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b(?:nmap|nuclei|httpx|feroxbuster|ffuf|gobuster|nikto|sqlmap|curl|wget|ssh|sftp|ftp|telnet|netcat|ncat|nc|tcpdump|tshark|wireshark|grpcurl)\b").unwrap()
});

static RE_IP: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b").unwrap()
});

static RE_HOST: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b([a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)+(?:\.[a-zA-Z]{2,}))\b").unwrap()
});
```

## Security Invariants

1. **Fail-Closed Semantics:** If an external target IP or FQDN cannot be positively matched to an entry in the allowlist, execution returns `Err(ScopeViolation)`.
2. **Localhost Exemption:** `localhost`, `127.0.0.1`, `::1`, and loopback subnets are always authorized to support local unit, integration, and sandbox testing.
3. **Defense-in-Depth:** In addition to CLI pre-execution verification, source code files are statically evaluated for hardcoded egress targets outside the defined scope.
