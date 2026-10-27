use bug_killer::hunter::sandbox::*;
use std::path::Path;

#[test]
fn test_adversarial_memory_limit_enforced_by_real_rss_sampling() {
    // Current bug: peak_memory_bytes was set to captured output length.
    // A command allocating 40MB in RAM with 0 bytes stdout must be terminated
    // with ResourceExceeded when limit is 15MB.
    let config = SandboxConfig::default()
        .with_timeout_ms(5000)
        .with_max_memory_bytes(15 * 1024 * 1024); // 15 MB limit

    let runner = SandboxRunner::new(config).expect("Runner must construct");

    let receipt = runner
        .run_command(
            "python3",
            &[
                "-c",
                "x = bytearray(40 * 1024 * 1024); import time; time.sleep(2)",
            ],
        )
        .expect("Execution should complete with receipt");

    assert_eq!(
        receipt.status,
        SandboxStatus::ResourceExceeded,
        "Process allocating 40MB against 15MB ceiling MUST be terminated with ResourceExceeded"
    );
    assert!(
        receipt.peak_memory_bytes > 0,
        "peak_memory_bytes must reflect actual measured RSS, got {}",
        receipt.peak_memory_bytes
    );
}

#[test]
fn test_adversarial_filesystem_write_outside_sandbox_denied_at_os_level() {
    // Attempting to write outside ephemeral sandbox directory must be denied by OS sandbox.
    let outside_target = "/tmp/bk_escape_adversarial_test.txt";
    let _ = std::fs::remove_file(outside_target);

    let runner = SandboxRunner::default_runner().expect("Runner must construct");

    let script = format!("echo 'escape' > {} 2>/dev/null || exit 42", outside_target);
    let receipt = runner
        .run_command("/bin/sh", &["-c", &script])
        .expect("Execution should produce receipt");

    assert!(
        !Path::new(outside_target).exists(),
        "Writing outside ephemeral directory must be blocked by OS sandbox"
    );
    assert_ne!(
        receipt.exit_code,
        Some(0),
        "Command attempting write outside sandbox must fail"
    );
}

#[test]
fn test_adversarial_raw_socket_egress_is_denied_at_os_level() {
    // Command attempting a raw TCP socket connection must be denied at OS kernel level.
    let runner = SandboxRunner::default_runner().expect("Runner must construct");

    let receipt = runner
        .run_command(
            "python3",
            &[
                "-c",
                "import socket; s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.settimeout(1.0); s.connect(('1.1.1.1', 80))",
            ],
        )
        .expect("Execution should produce receipt");

    assert_ne!(
        receipt.exit_code,
        Some(0),
        "Raw socket connection must fail under OS sandbox isolation"
    );
    assert!(
        receipt.network_egress_prevented,
        "Receipt must attest network egress prevented"
    );
    assert!(
        receipt.isolation_enforced,
        "Receipt must attest that OS-level isolation was enforced"
    );
}

#[test]
fn test_sandbox_receipt_truthful_isolation_provenance() {
    let runner = SandboxRunner::default_runner().expect("Runner must construct");

    let receipt = runner
        .run_command("/bin/echo", &["test-receipt"])
        .expect("Command must succeed");

    assert_eq!(receipt.status, SandboxStatus::Completed);
    assert_eq!(receipt.exit_code, Some(0));
    assert!(
        receipt.peak_memory_bytes > 0,
        "peak_memory_bytes must be measured RSS (> 0), got {}",
        receipt.peak_memory_bytes
    );
    assert!(
        receipt.isolation_mechanism != IsolationMechanism::None,
        "Isolation mechanism must be detected and recorded"
    );
}

#[test]
fn test_unsupported_host_blocks_fail_closed_when_isolation_required() {
    // When require_os_isolation is true, invalid/unsupported configuration must fail closed
    let mut config = SandboxConfig::default().with_require_os_isolation(true);
    // Explicitly validate configuration
    assert!(config.validate().is_ok());

    // If allow_network is maliciously toggled, validate must fail closed
    config.allow_network = true;
    assert!(config.validate().is_err());
    assert!(SandboxRunner::new(config).is_err());
}

#[test]
fn test_full_process_tree_killed_on_timeout() {
    let config = SandboxConfig::default().with_timeout_ms(600);
    let runner = SandboxRunner::new(config).expect("Runner must construct");

    // Spawn a shell script that starts a background grandchild sleep loop
    let receipt = runner
        .run_command("/bin/sh", &["-c", "sleep 10 & sleep 10 & wait"])
        .expect("Command must execute and timeout cleanly");

    assert_eq!(receipt.status, SandboxStatus::TimedOut);
}
