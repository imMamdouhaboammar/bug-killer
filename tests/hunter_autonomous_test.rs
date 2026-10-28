use bug_killer::hunter::orchestrator::{AttackSurfaceScanner, AutonomousHunter};
use bug_killer::hunter::sandbox::{SandboxConfig, SandboxRunner, SandboxStatus};
use std::fs;
use tempfile::tempdir;

#[test]
fn test_attack_surface_scanner_polyglot() {
    let temp = tempdir().expect("Failed to create temporary directory");
    let root = temp.path();

    // 1. Create a TypeScript Express route file
    let ts_file = root.join("routes.ts");
    fs::write(
        &ts_file,
        r#"
import express from 'express';
const app = express();

// Public unauthenticated mutation endpoint
app.post('/api/v1/billing/charge', (req, res) => {
    const { amount, account } = req.body;
    chargeCard(amount, account);
});

// Authenticated query endpoint
app.get('/api/v1/user/profile', requireAuth, (req, res) => {
    res.json(req.user);
});

// Parser usage
const data = JSON.parse(req.body.payload);
"#,
    )
    .expect("Failed to write TypeScript route fixture");

    // 2. Create a Python FastAPI file
    let py_file = root.join("main.py");
    fs::write(
        &py_file,
        r#"
from fastapi import FastAPI
app = FastAPI()

@app.post("/items/create")
def create_item(payload: dict):
    return {"status": "ok"}
"#,
    )
    .expect("Failed to write Python route fixture");

    let scanner = AttackSurfaceScanner::new();
    let entries = scanner.scan_workspace(root);

    assert!(
        entries.len() >= 3,
        "Expected at least 3 attack surface entries, found {}",
        entries.len()
    );

    let billing_post = entries
        .iter()
        .find(|e| e.route_or_entry.contains("/api/v1/billing/charge"))
        .expect("Billing route must be discovered");
    assert_eq!(billing_post.method, "POST");
    assert!(
        !billing_post.has_auth_guard,
        "Billing post route must not have auth guard"
    );
    assert!(
        billing_post.has_untrusted_input,
        "Billing post route must detect req.body input"
    );

    let profile_get = entries
        .iter()
        .find(|e| e.route_or_entry.contains("/api/v1/user/profile"))
        .expect("Profile route must be discovered");
    assert!(
        profile_get.has_auth_guard,
        "Profile route must have auth guard"
    );
}

#[test]
fn test_autonomous_hunter_pipeline_end_to_end() {
    let temp = tempdir().expect("Failed to create tempdir");
    let root = temp.path();

    // Setup dummy vulnerable service with unauthenticated state mutation
    let route_file = root.join("server.js");
    fs::write(
        &route_file,
        r#"
const express = require('express');
const app = express();

app.post('/api/admin/system/reset', (req, res) => {
    const input = req.body;
    resetDatabase();
});
"#,
    )
    .expect("Failed to write route file");

    let hunter = AutonomousHunter::new();
    let report = hunter
        .hunt(root, 5)
        .expect("Autonomous hunt pipeline execution must succeed");

    assert_eq!(report.attack_surface_entries_discovered, 1);
    assert_eq!(report.hypotheses_synthesized, 1);
    assert_eq!(report.hypotheses_triaged_out, 0);
    assert_eq!(report.candidates_reproduced, 1);
    assert_eq!(report.simulated_hypotheses, 1);
    assert_eq!(report.candidates_verified, 0);
    assert!(report.verified_findings.is_empty());
    assert!(report.research_receipts.is_empty());
    assert!(report.pvr_drafts.is_empty());
}

#[test]
fn test_autonomous_hunter_novelty_dedup() {
    let temp = tempdir().expect("Failed to create tempdir");
    let root = temp.path();

    let route_file = root.join("api.ts");
    fs::write(
        &route_file,
        r#"
app.post('/api/vulnerable', (req, res) => {
    eval(req.body.code);
});
"#,
    )
    .expect("Failed to write route file");

    // Register a known advisory that matches the candidate asset
    let hunter = AutonomousHunter::new().with_known_advisories(["CVE-2026-99999"]);
    let report = hunter.hunt(root, 5).expect("Hunt execution must succeed");

    assert!(report.hypotheses_synthesized >= 1);
    assert!(report.candidates_verified <= report.hypotheses_synthesized);
}

#[test]
fn test_sandbox_process_group_termination_on_timeout() {
    let config = SandboxConfig::default().with_timeout_ms(600);
    let runner = SandboxRunner::new(config).expect("Runner must construct");

    // Launch a script that spawns background child processes
    let receipt = runner
        .run_command("/bin/sh", &["-c", "sleep 10 & sleep 10 & wait"])
        .expect("Command must execute");

    assert_eq!(receipt.status, SandboxStatus::TimedOut);
    assert!(receipt.duration_ms >= 550 && receipt.duration_ms < 3000);
}

#[test]
fn test_simulated_experiments_are_quarantined_and_cannot_yield_verified_findings_or_pvr_drafts() {
    let temp = tempdir().expect("Failed to create tempdir");
    let root = temp.path();

    let route_file = root.join("server.js");
    fs::write(
        &route_file,
        r#"
const express = require('express');
const app = express();

app.post('/api/admin/system/reset', (req, res) => {
    const input = req.body;
    resetDatabase();
});
"#,
    )
    .expect("Failed to write route file");

    let hunter = AutonomousHunter::new();
    let report = hunter.hunt(root, 5).expect("Hunt execution must succeed");

    // BK-ND-01 Invariant: Under simulated closure experiments without target execution:
    // 1. candidates_verified MUST be 0
    // 2. verified_findings MUST be empty
    // 3. pvr_drafts MUST be empty
    assert_eq!(
        report.candidates_verified, 0,
        "Simulated experiment without target runtime execution cannot yield verified candidates"
    );
    assert!(
        report.verified_findings.is_empty(),
        "Simulated experiment cannot yield verified findings"
    );
    assert!(
        report.pvr_drafts.is_empty(),
        "Simulated experiment cannot yield private vulnerability report disclosure drafts"
    );
}
