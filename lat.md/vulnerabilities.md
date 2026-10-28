# Vulnerabilities

Bug Killer benchmarks against critical runtime memory corruptions and out-of-bounds execution flaws.

The engine detects both static configuration flaws and dynamic process runtime exposures across targeted versions.

## PHP2Shell Vulnerabilities

PHP2Shell targets memory corruptions within the Zend Engine allocator and global request state.

Detection evaluates whether PHP runtimes and pools match vulnerable version thresholds.

### OOM Heap Corruption

CVE-2026-109618 involves Zend Engine allocator longjmp failures causing heap corruption on memory exhaustion.

Version evaluation is performed via [[src/cve_db.rs#CveDatabase#check_php_version]] which flags unpatched versions prior to 8.2.35, 8.3.36, 8.4.27, and 8.5.12.

### Stale Global State Use-After-Free

CVE-2026-109619 exploits stale global state retention across persistent worker requests leading to Use-After-Free.

This flaw is identified when persistent FastCGI process pools fail to cycle memory contexts between concurrent requests.

## Node2Shell Vulnerabilities

Node2Shell targets out-of-bounds memory write corruptions in bundled Node.js runtime decoders.

Remediation requires either updating the host Node runtime or virtual patching the stream processing layer.

### Brotli Decoder Out-of-Bounds Write

CVE-2026-111497 involves an out-of-bounds memory write in Google Brotli decoder bundled within node:zlib.

Detection logic in [[src/cve_db.rs#CveDatabase#check_node_version]] flags vulnerable releases prior to Node.js 18.20.8, 20.19.1, 22.14.1, and 23.9.1.
