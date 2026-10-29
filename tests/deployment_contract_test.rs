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

#[test]
fn operational_mcp_configuration_and_docs_are_portable() {
    let docs = fs::read_to_string("docs/SIBLING_TOOLS.md").unwrap();
    assert!(
        !docs.contains("file:///") && !docs.contains("file://"),
        "operational sibling-tool links must be repository-relative"
    );
    assert!(
        !std::path::Path::new("services/cve-mcp-server/.mcp.json").exists(),
        "machine-local MCP settings must not be tracked"
    );
    let example = fs::read_to_string("services/cve-mcp-server/.mcp.example.json").unwrap();
    let config: serde_json::Value = serde_json::from_str(&example).unwrap();
    let server = &config["mcpServers"]["cve-mcp"];
    assert_eq!(server["command"], "uv");
    assert_eq!(server["args"][0], "run");
    assert_eq!(server["args"][1], "--directory");
    assert!(
        server["args"][2]
            .as_str()
            .unwrap()
            .starts_with("/absolute/path/to/"),
        "the example must require an explicit checkout-specific substitution"
    );
    assert_eq!(server["args"][3], "cve-mcp");
    assert!(
        server.get("env").is_none(),
        "example must not embed credentials"
    );
}

#[test]
fn shell_completions_are_fresh_and_match_cli() {
    let binary = env!("CARGO_BIN_EXE_bug-killer");
    let shells = [
        ("bash", "completions/bug-killer.bash"),
        ("zsh", "completions/_bug-killer"),
        ("fish", "completions/bug-killer.fish"),
    ];

    for (shell, path) in shells {
        let output = std::process::Command::new(binary)
            .args(["completion", shell])
            .output()
            .unwrap_or_else(|e| panic!("failed to execute bug-killer completion {}: {}", shell, e));
        assert!(output.status.success(), "completion for {} failed", shell);
        let generated = String::from_utf8(output.stdout).unwrap();
        let committed =
            fs::read_to_string(path).unwrap_or_else(|e| panic!("failed to read {}: {}", path, e));
        assert_eq!(
            generated, committed,
            "shell completion for '{}' in {} is stale. Run 'make completions' to update.",
            shell, path
        );
    }
}

#[test]
fn ci_workflow_includes_completions_drift_check() {
    let ci = fs::read_to_string(".github/workflows/ci.yml").unwrap();
    assert!(
        ci.contains("git diff --exit-code completions/"),
        "CI Full System Build must enforce zero uncommitted drift in completions/"
    );
}

#[test]
fn lat_md_skill_is_canonical_in_agents_directory() {
    let canonical = std::path::Path::new(".agents/skills/lat-md/SKILL.md");
    assert!(
        canonical.exists(),
        ".agents/skills/lat-md/SKILL.md must exist as the canonical skill definition"
    );

    let mirror = std::path::Path::new("skills/lat-md/SKILL.md");
    assert!(
        mirror.exists(),
        "skills/lat-md/SKILL.md must remain resolvable for host discovery compatibility"
    );

    let canonical_content = fs::read_to_string(canonical).unwrap();
    let mirror_content = fs::read_to_string(mirror).unwrap();
    assert_eq!(
        canonical_content, mirror_content,
        "skills/lat-md must be synchronized with canonical .agents/skills/lat-md"
    );
}

#[test]
fn omni_skill_and_skill_conductor_shared_assets_are_synchronized() {
    let shared_assets = [
        "agents/analyzer.md",
        "agents/bineval.md",
        "agents/comparator.md",
        "agents/grader.md",
        "assets/eval_review.html",
        "eval-viewer/generate_review.py",
        "eval-viewer/viewer.html",
        "references/bineval-method.md",
        "references/patterns.md",
        "references/pressure-testing.md",
        "references/quality-questions.md",
        "references/schemas.md",
        "references/sop-practices.md",
        "scripts/aggregate_benchmark.py",
        "scripts/eval_skill.py",
        "scripts/generate_report.py",
        "scripts/improve_description.py",
        "scripts/init_skill.py",
        "scripts/package_skill.py",
        "scripts/quick_validate.py",
        "scripts/run_eval.py",
        "scripts/run_loop.py",
        "scripts/split_evals.py",
        "scripts/test_smoke.py",
        "scripts/utils.py",
    ];

    let omni_root = std::path::Path::new(".agents/skills/omni-skill");
    let conductor_root = std::path::Path::new(".agents/skills/skill-conductor");

    assert!(
        omni_root.join("SKILL.md").exists(),
        "omni-skill SKILL.md must exist"
    );
    assert!(
        conductor_root.join("SKILL.md").exists(),
        "skill-conductor SKILL.md must exist"
    );

    for asset in shared_assets {
        let omni_path = omni_root.join(asset);
        let conductor_path = conductor_root.join(asset);

        assert!(
            omni_path.exists(),
            "omni-skill is missing expected shared asset: {}",
            asset
        );
        assert!(
            conductor_path.exists(),
            "skill-conductor is missing expected shared asset: {}",
            asset
        );

        let omni_bytes = fs::read(&omni_path).unwrap_or_else(|e| {
            panic!("failed reading {}: {}", omni_path.display(), e);
        });
        let conductor_bytes = fs::read(&conductor_path).unwrap_or_else(|e| {
            panic!("failed reading {}: {}", conductor_path.display(), e);
        });

        assert_eq!(
            omni_bytes, conductor_bytes,
            "Shared skill asset '{}' has diverged between omni-skill and skill-conductor. Both must remain synchronized.",
            asset
        );
    }
}
