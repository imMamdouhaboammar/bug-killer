use bug_killer::scanner::container::ContainerScanner;
use bug_killer::types::*;
use std::fs;
use tempfile::tempdir;

#[test]
fn test_detect_insecure_tls_flags_in_run_cmd_entrypoint() {
    let dir = tempdir().unwrap();
    let dockerfile_path = dir.path().join("Dockerfile");

    let vulnerable_dockerfile = r#"FROM alpine:3.20
USER app
RUN curl --insecure https://internal-repo.corp/release.tar.gz -o /tmp/release.tar.gz
RUN wget --no-tls https://internal-repo.corp/checksums.txt
ENTRYPOINT ["/app/server", "--no-tls"]
CMD ["--insecure", "--debug"]
"#;

    fs::write(&dockerfile_path, vulnerable_dockerfile).unwrap();

    let findings = ContainerScanner::scan_dockerfile(&dockerfile_path);
    let tls_findings: Vec<&Finding> = findings
        .iter()
        .filter(|f| f.cve.as_str() == "BK-AI-INF-008")
        .collect();

    // 4 lines contain insecure TLS flags (--insecure or --no-tls in RUN, ENTRYPOINT, CMD)
    assert_eq!(
        tls_findings.len(),
        4,
        "Expected 4 BK-AI-INF-008 findings, found: {:?}",
        tls_findings
    );

    for finding in &tls_findings {
        assert_eq!(finding.target_kind, TargetKind::Dockerfile);
        assert_eq!(finding.category, "container-hardening");
        assert_eq!(finding.detector_id, "container-scanner");
        assert_eq!(finding.affectedness, Affectedness::ConfirmedAffected);
    }

    assert!(
        tls_findings
            .iter()
            .any(|f| f.detected_version_or_pattern.contains("curl --insecure")),
        "Must flag RUN with --insecure"
    );
    assert!(
        tls_findings
            .iter()
            .any(|f| f.detected_version_or_pattern.contains("wget --no-tls")),
        "Must flag RUN with --no-tls"
    );
    assert!(
        tls_findings.iter().any(|f| f
            .detected_version_or_pattern
            .contains("ENTRYPOINT [\"/app/server\", \"--no-tls\"]")),
        "Must flag ENTRYPOINT with --no-tls"
    );
    assert!(
        tls_findings.iter().any(|f| f
            .detected_version_or_pattern
            .contains("CMD [\"--insecure\", \"--debug\"]")),
        "Must flag CMD with --insecure"
    );
}

#[test]
fn test_detect_exposed_debug_and_metrics_ports() {
    let dir = tempdir().unwrap();
    let dockerfile_path = dir.path().join("Dockerfile");

    // Ports 9090 (Prometheus), 2112 (Prometheus exporter), 6060 (Go pprof)
    let vulnerable_dockerfile = r#"FROM alpine:3.20
USER app
EXPOSE 8080 9090
EXPOSE 2112/tcp
EXPOSE 6060
CMD ["/app/server"]
"#;

    fs::write(&dockerfile_path, vulnerable_dockerfile).unwrap();

    let findings = ContainerScanner::scan_dockerfile(&dockerfile_path);
    let debug_port_findings: Vec<&Finding> = findings
        .iter()
        .filter(|f| f.cve.as_str() == "BK-AI-INF-010")
        .collect();

    assert_eq!(
        debug_port_findings.len(),
        3,
        "Expected 3 BK-AI-INF-010 findings for ports 9090, 2112, 6060, found: {:?}",
        debug_port_findings
    );

    for finding in &debug_port_findings {
        assert_eq!(finding.target_kind, TargetKind::Dockerfile);
        assert_eq!(finding.category, "container-hardening");
        assert_eq!(finding.detector_id, "container-scanner");
        assert_eq!(finding.affectedness, Affectedness::ConfirmedAffected);
    }

    assert!(
        debug_port_findings
            .iter()
            .any(|f| f.detected_version_or_pattern.contains("9090")),
        "Must flag exposed port 9090 (Prometheus)"
    );
    assert!(
        debug_port_findings
            .iter()
            .any(|f| f.detected_version_or_pattern.contains("2112")),
        "Must flag exposed port 2112 (Prometheus exporter)"
    );
    assert!(
        debug_port_findings
            .iter()
            .any(|f| f.detected_version_or_pattern.contains("6060")),
        "Must flag exposed port 6060 (Go pprof)"
    );
}

#[test]
fn test_hardened_container_has_no_insecure_tls_or_debug_ports() {
    let dir = tempdir().unwrap();
    let dockerfile_path = dir.path().join("Dockerfile");

    let clean_dockerfile = r#"FROM alpine:3.20
RUN apk add --no-cache ca-certificates
RUN curl -fsSL https://secure-repo.corp/release.tar.gz -o /tmp/release.tar.gz
USER app
EXPOSE 80 443 8080 8443
CMD ["/app/server", "--secure"]
"#;

    fs::write(&dockerfile_path, clean_dockerfile).unwrap();

    let findings = ContainerScanner::scan_dockerfile(&dockerfile_path);
    let hardening_findings: Vec<&Finding> = findings
        .iter()
        .filter(|f| f.cve.as_str() == "BK-AI-INF-008" || f.cve.as_str() == "BK-AI-INF-010")
        .collect();

    assert!(
        hardening_findings.is_empty(),
        "Clean Dockerfile should have no BK-AI-INF-008 or BK-AI-INF-010 findings, found: {:?}",
        hardening_findings
    );
}
