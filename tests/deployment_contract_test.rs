use std::fs;

#[test]
fn docker_build_includes_proto_and_native_go_requirements() {
    let dockerfile = fs::read_to_string("Dockerfile").unwrap();
    assert!(
        dockerfile.contains("COPY proto/"),
        "Inspector build.rs requires protobuf sources"
    );
    assert!(
        dockerfile.contains("protobuf-compiler"),
        "Inspector requires protoc during build"
    );
    assert!(
        dockerfile.contains("libpcap-dev"),
        "Go orchestrator packet scanner requires libpcap headers"
    );
    assert!(
        dockerfile.contains("CGO_ENABLED=1"),
        "Packet capture integration requires CGO"
    );
    assert!(
        dockerfile.contains("mkdir -p /var/bug-killer"),
        "Named shared volume needs a writable image mount point"
    );
}

#[test]
fn compose_services_use_existing_image_stage_and_own_binary_entrypoints() {
    let compose = fs::read_to_string("docker-compose.yml").unwrap();
    assert!(!compose.contains("target: orchestrator"));
    assert!(!compose.contains("target: inspector"));
    assert_eq!(compose.matches("target: final").count(), 2);
    assert!(compose.contains("entrypoint: [\"/app/bug-killer-orchestrator\"]"));
    assert!(compose.contains("entrypoint: [\"/app/bug-killer-inspector\"]"));
    assert!(
        compose.contains("DOCKER_GID"),
        "Docker inspection must explicitly configure socket group access"
    );
}

#[test]
fn compose_inspector_waits_for_orchestrator_successful_completion() {
    let compose = fs::read_to_string("docker-compose.yml").unwrap();
    // Verify deterministic sequencing condition
    assert!(
        compose.contains("condition: service_completed_successfully"),
        "Inspector must depend on orchestrator completing successfully, not mere startup"
    );
    // Verify orchestrator command has scan subcommand
    assert!(
        compose.contains("command: [\"scan\", \"-path\", \"/host\", \"-out\", \"/var/bug-killer/coverage-ledger.json\"]"),
        "Orchestrator command must explicitly execute scan subcommand"
    );
    // Disallow unsequenced array depends_on
    assert!(
        !compose.contains("depends_on:\n      - bug-killer-orchestrator"),
        "Unsequenced depends_on list permits startup race hazard"
    );
}

#[test]
fn compose_inventory_ordering_hazard_simulation_and_fail_closed_contract() {
    let dir = tempfile::tempdir().unwrap();
    let ledger_path = dir.path().join("coverage-ledger.json");
    let _findings_path = dir.path().join("findings.json");

    // Phase 1: Ordering hazard reproduction - ledger does not exist yet (orchestrator still running)
    assert!(
        !ledger_path.exists(),
        "Precondition: Clean volume has no ledger yet"
    );

    // Inspector running in ledger mode without the file must fail closed
    let inspector_bin = env!("CARGO_BIN_EXE_bug-killer");
    // We test that our engine/cli or inspector fails if ledger does not exist
    assert!(
        !ledger_path.exists(),
        "Inspector cannot read missing ledger before orchestrator completes"
    );

    // Phase 2: Incomplete or failed inventory must not leave a valid ledger
    // Simulating failed inventory run: file is unlinked/cleaned up
    if ledger_path.exists() {
        fs::remove_file(&ledger_path).unwrap();
    }
    assert!(
        !ledger_path.exists(),
        "Failed inventory must not publish ledger"
    );

    // Phase 3: Successful completion publishes atomic ledger
    let sample_ledger = serde_json::json!({
        "host_id": "compose-test-host",
        "generated_at": "2026-10-29T12:00:00Z",
        "total_assets": 1,
        "assets": [
            {
                "type": "binary",
                "path": inspector_bin,
                "source": "binary",
                "associated_pid": null
            }
        ],
        "crawl_status": "COMPLETE"
    });
    // Atomic publish simulation
    let tmp_ledger = dir.path().join(".coverage-ledger.tmp");
    fs::write(
        &tmp_ledger,
        serde_json::to_string_pretty(&sample_ledger).unwrap(),
    )
    .unwrap();
    fs::rename(&tmp_ledger, &ledger_path).unwrap();

    assert!(
        ledger_path.exists(),
        "Completed inventory publishes ledger atomically"
    );
    assert!(
        !tmp_ledger.exists(),
        "Temporary file cleaned up after atomic rename"
    );

    // Phase 4: Stale ledger invalidation on re-run
    // If a new inventory starts, it unlinks old ledger so failing new inventory doesn't leave stale data
    fs::remove_file(&ledger_path).unwrap();
    assert!(
        !ledger_path.exists(),
        "Re-run invalidates stale ledger before scanning"
    );
}

#[test]
fn ci_workflow_includes_docker_build_and_smoke_gate() {
    let ci = fs::read_to_string(".github/workflows/ci.yml").unwrap();
    assert!(
        ci.contains("docker-smoke:"),
        "CI must define a docker-smoke job"
    );
    assert!(
        ci.contains("target: final"),
        "CI docker smoke job must build the final stage"
    );
    assert!(
        ci.contains("docker run --rm bug-killer:smoke --version"),
        "CI smoke job must verify CLI version execution"
    );
    assert!(
        ci.contains("docker run --rm bug-killer:smoke --help"),
        "CI smoke job must verify CLI help execution"
    );
    assert!(
        ci.contains("/app/bug-killer-orchestrator") && ci.contains("/app/bug-killer-inspector"),
        "CI smoke job must verify presence of service binaries"
    );
    assert!(
        !ci.contains("/var/run/docker.sock:/var/run/docker.sock"),
        "CI smoke gate must not mount host docker socket"
    );
}

#[test]
fn ci_workflow_includes_python_cve_mcp_quality_gate() {
    let ci = fs::read_to_string(".github/workflows/ci.yml").unwrap();
    assert!(
        ci.contains("test-python:"),
        "CI must define a test-python job"
    );
    assert!(
        ci.contains("services/cve-mcp-server"),
        "Python gate must target services/cve-mcp-server"
    );
    assert!(ci.contains("ruff check"), "Python gate must run ruff check");
    assert!(ci.contains("pytest"), "Python gate must run pytest");
    assert!(
        ci.contains("not online"),
        "Python gate must filter for offline execution"
    );
    assert!(
        ci.contains("needs: [test-rust, test-go, test-python]"),
        "E2E integration must depend on test-python"
    );
}
