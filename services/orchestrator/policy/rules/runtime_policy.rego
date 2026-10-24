package omni.runtime

import future.keywords.contains
import future.keywords.if
import future.keywords.in

default allow := true
default action := "ALLOW"
default severity := "LOW"

# -------------------------------------------------------------
# 1. NETWORK TELEMETRY SECURITY POLICIES
# -------------------------------------------------------------

# CVE-2026-109618 / CVE-2026-109619: Brotli heap corruption triggered by chunked streams
deny contains msg if {
    input.network.is_brotli == true
    input.network.is_chunked == true
    msg := "CVE-2026-109618_BROTLI_CHUNKED_CORRUPTION: Brotli payload coupled with chunked transfer encoding rejected"
}

# Malformed Multipart/form-data boundary missing delimiter
deny contains msg if {
    input.network.is_multipart == true
    not input.network.headers["content-type"]
    msg := "MALFORMED_MULTIPART: Missing Content-Type header on multipart request"
}

deny contains msg if {
    input.network.is_multipart == true
    header := lower(input.network.headers["content-type"])
    not contains(header, "boundary=")
    msg := "MALFORMED_MULTIPART_BOUNDARY: Missing boundary parameter in multipart/form-data header"
}

# Path Traversal attack signature in URL path
deny contains msg if {
    path := input.network.path
    contains(path, "../")
    msg := "PATH_TRAVERSAL: Directory traversal sequence detected in request URI"
}

deny contains msg if {
    path := input.network.path
    contains(path, "%2e%2e")
    msg := "PATH_TRAVERSAL: Encoded directory traversal sequence detected in request URI"
}

# Shell Command Injection primitives in request line
deny contains msg if {
    path := input.network.path
    contains(path, "|")
    msg := "SHELL_INJECTION_PIPE: Raw pipeline operator detected in HTTP request line"
}

deny contains msg if {
    path := input.network.path
    contains(path, "`")
    msg := "SHELL_INJECTION_BACKTICK: Subshell backtick operator detected in HTTP request line"
}

# -------------------------------------------------------------
# 2. PROCESS & KERNEL RUNTIME POLICIES
# -------------------------------------------------------------

# PHP2Shell: PHP process executing uncleaned longjmp frames exposed to Brotli
deny contains msg if {
    contains(lower(input.process.binary_path), "php")
    input.process.has_dangerous_symbols == true
    count(input.process.missing_cleanups) > 0
    msg := "PHP2SHELL_EXPOSURE: PHP runtime has uncleaned longjmp exception frames vulnerable to heap corruption"
}

# Node2Shell: Privileged Node process statically compiling vulnerable Brotli symbols
deny contains msg if {
    contains(lower(input.process.binary_path), "node")
    input.process.is_privileged == true
    input.process.has_dangerous_symbols == true
    msg := "NODE2SHELL_PRIVILEGED: Privileged Node container running unhardened Brotli decoder"
}

# Unhardened Executable: Executable stack permission (Missing NX/DEP) on privileged daemon
deny contains msg if {
    input.process.is_privileged == true
    input.process.security_flags.nx == false
    msg := "UNHARDENED_EXECUTABLE_STACK: Privileged daemon running with executable stack (NX disabled)"
}

# Interactive Shell Spawn from worker process
deny contains msg if {
    some arg in input.process.arguments
    contains(arg, "/bin/sh -i")
    msg := "REVERSE_SHELL_DETECTED: Interactive shell spawn detected in process arguments"
}

deny contains msg if {
    some arg in input.process.arguments
    contains(arg, "bash -i")
    msg := "REVERSE_SHELL_DETECTED: Interactive bash spawn detected in process arguments"
}

# -------------------------------------------------------------
# 3. DETERMINISTIC DECISION AGGREGATION
# -------------------------------------------------------------

decision := {
    "allow": count(deny) == 0,
    "deny": count(deny) > 0,
    "violations": deny,
    "action": determined_action,
    "severity": determined_severity,
    "rule_count": count(deny),
}

determined_action := "DROP_415" if {
    some v in deny
    contains(v, "BROTLI_CHUNKED")
} else := "BLOCK_400" if {
    some v in deny
    contains(v, "MULTIPART")
} else := "KILL_PROCESS" if {
    some v in deny
    contains(v, "REVERSE_SHELL")
} else := "KILL_PROCESS" if {
    some v in deny
    contains(v, "NODE2SHELL_PRIVILEGED")
} else := "DROP" if {
    count(deny) > 0
} else := "ALLOW"

determined_severity := "CRITICAL" if {
    some v in deny
    contains(v, "CVE-2026")
} else := "CRITICAL" if {
    some v in deny
    contains(v, "PHP2SHELL")
} else := "CRITICAL" if {
    some v in deny
    contains(v, "NODE2SHELL")
} else := "CRITICAL" if {
    some v in deny
    contains(v, "REVERSE_SHELL")
} else := "HIGH" if {
    count(deny) > 0
} else := "LOW"
