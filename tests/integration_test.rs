use std::fs;
use tempfile::tempdir;

#[test]
fn test_end_to_end_scan_and_heal_and_rollback() {
    let dir = tempdir().unwrap();
    let root = dir.path();

    // 1. Create vulnerable package.json
    let package_json = root.join("package.json");
    fs::write(
        &package_json,
        r#"{
  "name": "vulnerable-node-service",
  "version": "1.0.0",
  "engines": {
    "node": "22.20.0"
  },
  "dependencies": {
    "express": "^4.19.2",
    "body-parser": "^1.20.2"
  }
}
"#,
    )
    .unwrap();

    // 2. Create vulnerable composer.json
    let composer_json = root.join("composer.json");
    fs::write(
        &composer_json,
        r#"{
  "name": "vulnerable/php-app",
  "require": {
    "php": "^8.2.14"
  }
}
"#,
    )
    .unwrap();

    // 3. Create vulnerable Dockerfile
    let dockerfile = root.join("Dockerfile");
    fs::write(
        &dockerfile,
        r#"FROM php:8.2-fpm
WORKDIR /var/www
COPY . .
"#,
    )
    .unwrap();

    // 4. Create vulnerable Nginx configuration
    let nginx_conf = root.join("nginx.conf");
    fs::write(
        &nginx_conf,
        r#"server {
    listen 80;
    server_name api.example.com;

    location / {
        proxy_pass http://localhost:3000;
    }
}
"#,
    )
    .unwrap();

    // 5. Create vulnerable Express entrypoint
    let server_js = root.join("server.js");
    fs::write(
        &server_js,
        r#"const express = require('express');
const app = express();
const bodyParser = require('body-parser');

app.use(bodyParser.json());
app.get('/', (req, res) => res.send('OK'));
"#,
    )
    .unwrap();

    // Run Scanner directly
    let report = bug_killer::scanner::FleetScanner::scan_directory(root, false);
    assert!(report.is_vulnerable);
    assert!(report.findings.len() >= 4);

    // Plan Healing
    let plan = bug_killer::healer::AutopilotHealer::plan_healing(&report);
    assert!(!plan.is_empty());

    // Record original SHA256 of package.json
    let original_package_hash =
        bug_killer::healer::backup::BackupManager::compute_sha256(&package_json).unwrap();
    let original_dockerfile_hash =
        bug_killer::healer::backup::BackupManager::compute_sha256(&dockerfile).unwrap();

    // Execute Live Healing
    let (manifest, applied_count) =
        bug_killer::healer::AutopilotHealer::execute_healing(root, &plan).unwrap();
    assert_eq!(applied_count, plan.len());

    // Verify package.json is patched
    let patched_package = fs::read_to_string(&package_json).unwrap();
    assert!(patched_package.contains(">=22.23.4"));

    // Verify composer.json is patched
    let patched_composer = fs::read_to_string(&composer_json).unwrap();
    assert!(patched_composer.contains(">=8.2.35"));

    // Verify Dockerfile is patched
    let patched_dockerfile = fs::read_to_string(&dockerfile).unwrap();
    assert!(patched_dockerfile.contains("FROM php:8.2.35-fpm"));

    // Verify Nginx is patched with virtual patch
    let patched_nginx = fs::read_to_string(&nginx_conf).unwrap();
    assert!(patched_nginx.contains("BUG KILLER VIRTUAL PATCH (CVE-2026-111497"));

    // Verify Express server.js has guard injected
    let patched_server = fs::read_to_string(&server_js).unwrap();
    assert!(patched_server.contains("[BUG-KILLER-GUARD]"));

    // Rescan: should detect virtual patch and zero unhandled exposures for healed targets
    let rescan_report = bug_killer::scanner::FleetScanner::scan_directory(root, false);
    let new_plan = bug_killer::healer::AutopilotHealer::plan_healing(&rescan_report);
    assert_eq!(
        new_plan.len(),
        0,
        "Idempotency invariant violated: planned patches on already-healed target"
    );

    // Execute Rollback
    let restored =
        bug_killer::healer::rollback::RollbackManager::rollback(root, &manifest.backup_id).unwrap();
    assert_eq!(restored, applied_count);

    // Verify bit-for-bit restoration
    let restored_package_hash =
        bug_killer::healer::backup::BackupManager::compute_sha256(&package_json).unwrap();
    assert_eq!(original_package_hash, restored_package_hash);

    let restored_dockerfile_hash =
        bug_killer::healer::backup::BackupManager::compute_sha256(&dockerfile).unwrap();
    assert_eq!(original_dockerfile_hash, restored_dockerfile_hash);
}
