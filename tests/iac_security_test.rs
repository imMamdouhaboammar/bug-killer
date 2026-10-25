pub use bug_killer::types;
use bug_killer::types::*;
use std::path::Path;

#[path = "../src/scanner/iac.rs"]
mod iac;

use iac::IacScanner;

// ===========================================================================
// Category 15: Infrastructure, Cloud & Defaults Tests (BK-AI-INF-002 - 016)
// ===========================================================================

#[test]
fn test_inf_002_vulnerable_public_s3_bucket() {
    let code = r#"
resource "aws_s3_bucket" "data_bucket" {
  bucket = "company-analytics-export"
  acl    = "public-read"
}
"#;
    let path = Path::new("terraform/s3.tf");
    let findings = IacScanner::scan_source(path, code);

    let f = findings
        .iter()
        .find(|f| f.cve.as_str() == "BK-AI-INF-002")
        .expect("Must flag public-read ACL on S3 bucket");
    assert_eq!(f.severity, Severity::High);
    assert_eq!(f.detector_id, "iac-security");
    assert!(f.advisory_ids.contains(&"CWE-732".to_string()));
}

#[test]
fn test_inf_002_safe_private_s3_bucket() {
    let code = r#"
resource "aws_s3_bucket" "data_bucket" {
  bucket = "company-analytics-export"
  acl    = "private"
}
"#;
    let path = Path::new("terraform/s3.tf");
    let findings = IacScanner::scan_source(path, code);
    assert!(findings.iter().all(|f| f.cve.as_str() != "BK-AI-INF-002"));
}

#[test]
fn test_inf_005_vulnerable_wildcard_iam_policy() {
    let code = r#"
data "aws_iam_policy_document" "admin" {
  statement {
    actions   = ["*"]
    resources = ["*"]
  }
}
"#;
    let path = Path::new("terraform/iam.tf");
    let findings = IacScanner::scan_source(path, code);

    let f = findings
        .iter()
        .find(|f| f.cve.as_str() == "BK-AI-INF-005")
        .expect("Must flag wildcard '*' actions in IAM policy");
    assert_eq!(f.severity, Severity::High);
    assert_eq!(f.detector_id, "iac-security");
    assert!(f.advisory_ids.contains(&"CWE-269".to_string()));
}

#[test]
fn test_inf_005_safe_scoped_iam_policy() {
    let code = r#"
data "aws_iam_policy_document" "reader" {
  statement {
    actions   = ["s3:GetObject"]
    resources = ["arn:aws:s3:::my-bucket/*"]
  }
}
"#;
    let path = Path::new("terraform/iam.tf");
    let findings = IacScanner::scan_source(path, code);
    assert!(findings.iter().all(|f| f.cve.as_str() != "BK-AI-INF-005"));
}

#[test]
fn test_inf_006_vulnerable_database_port_to_internet() {
    let code = r#"
resource "aws_security_group" "db" {
  name = "db-security-group"
  ingress {
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
"#;
    let path = Path::new("terraform/security_group.tf");
    let findings = IacScanner::scan_source(path, code);

    let f = findings
        .iter()
        .find(|f| f.cve.as_str() == "BK-AI-INF-006")
        .expect("Must flag database port 5432 exposed to 0.0.0.0/0");
    assert_eq!(f.severity, Severity::High);
    assert_eq!(f.detector_id, "iac-security");
    assert!(f.advisory_ids.contains(&"CWE-284".to_string()));
}

#[test]
fn test_inf_006_safe_database_port_private_vpc() {
    let code = r#"
resource "aws_security_group" "db" {
  name = "db-security-group"
  ingress {
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]
  }
}
"#;
    let path = Path::new("terraform/security_group.tf");
    let findings = IacScanner::scan_source(path, code);
    assert!(findings.iter().all(|f| f.cve.as_str() != "BK-AI-INF-006"));
}

#[test]
fn test_inf_009_vulnerable_redis_empty_password() {
    let code = r#"
const redis = require('redis');
const client = redis.createClient({
    host: '10.0.1.5',
    password: ""
});
"#;
    let path = Path::new("src/redis_client.js");
    let findings = IacScanner::scan_source(path, code);

    let f = findings
        .iter()
        .find(|f| f.cve.as_str() == "BK-AI-INF-009")
        .expect("Must flag Redis client with empty password");
    assert_eq!(f.severity, Severity::High);
    assert_eq!(f.detector_id, "iac-security");
    assert!(f.advisory_ids.contains(&"CWE-306".to_string()));
}

#[test]
fn test_inf_009_safe_redis_with_auth() {
    let code = r#"
const redis = require('redis');
const client = redis.createClient({
    host: '10.0.1.5',
    password: process.env.REDIS_AUTH_SECRET
});
"#;
    let path = Path::new("src/redis_client.js");
    let findings = IacScanner::scan_source(path, code);
    assert!(findings.iter().all(|f| f.cve.as_str() != "BK-AI-INF-009"));
}

#[test]
fn test_inf_011_vulnerable_default_credentials() {
    let code = r#"
database:
  user: admin
  default_password: "admin_default_password"
  use_default_credentials: true
"#;
    let path = Path::new("config/database.yml");
    let findings = IacScanner::scan_source(path, code);

    let f = findings
        .iter()
        .find(|f| f.cve.as_str() == "BK-AI-INF-011")
        .expect("Must flag default credentials active");
    assert_eq!(f.severity, Severity::High);
    assert_eq!(f.detector_id, "iac-security");
    assert!(f.advisory_ids.contains(&"CWE-798".to_string()));
}

#[test]
fn test_inf_011_safe_no_default_credentials() {
    let code = r#"
database:
  user: app_service
  use_default_credentials: false
"#;
    let path = Path::new("config/database.yml");
    let findings = IacScanner::scan_source(path, code);
    assert!(findings.iter().all(|f| f.cve.as_str() != "BK-AI-INF-011"));
}

#[test]
fn test_inf_012_vulnerable_latest_base_image() {
    let code = r#"FROM ubuntu:latest
RUN apt-get update && apt-get install -y curl
"#;
    let path = Path::new("Dockerfile");
    let findings = IacScanner::scan_source(path, code);

    let f = findings
        .iter()
        .find(|f| f.cve.as_str() == "BK-AI-INF-012")
        .expect("Must flag unpinned :latest container base image");
    assert_eq!(f.severity, Severity::Medium);
    assert_eq!(f.detector_id, "iac-security");
    assert!(f.advisory_ids.contains(&"CWE-1104".to_string()));
}

#[test]
fn test_inf_012_safe_pinned_base_image() {
    let code = r#"FROM ubuntu:24.04
RUN apt-get update && apt-get install -y curl
"#;
    let path = Path::new("Dockerfile");
    let findings = IacScanner::scan_source(path, code);
    assert!(findings.iter().all(|f| f.cve.as_str() != "BK-AI-INF-012"));
}

#[test]
fn test_inf_013_vulnerable_disabled_audit_logging() {
    let code = r#"
resource "aws_cloudtrail" "audit_trail" {
  name           = "main-audit-trail"
  s3_bucket_name = "corp-audit-logs"
  enable_logging = false
}
"#;
    let path = Path::new("terraform/cloudtrail.tf");
    let findings = IacScanner::scan_source(path, code);

    let f = findings
        .iter()
        .find(|f| f.cve.as_str() == "BK-AI-INF-013")
        .expect("Must flag disabled audit logging in infrastructure");
    assert_eq!(f.severity, Severity::Medium);
    assert_eq!(f.detector_id, "iac-security");
    assert!(f.advisory_ids.contains(&"CWE-778".to_string()));
}

#[test]
fn test_inf_013_safe_enabled_audit_logging() {
    let code = r#"
resource "aws_cloudtrail" "audit_trail" {
  name           = "main-audit-trail"
  s3_bucket_name = "corp-audit-logs"
  enable_logging = true
}
"#;
    let path = Path::new("terraform/cloudtrail.tf");
    let findings = IacScanner::scan_source(path, code);
    assert!(findings.iter().all(|f| f.cve.as_str() != "BK-AI-INF-013"));
}

#[test]
fn test_inf_014_vulnerable_k8s_privileged_workload() {
    let code = r#"
apiVersion: v1
kind: Pod
metadata:
  name: privileged-pod
spec:
  containers:
    - name: runner
      image: alpine:3.19
      securityContext:
        privileged: true
        allowPrivilegeEscalation: true
        runAsUser: 0
"#;
    let path = Path::new("k8s/pod.yaml");
    let findings = IacScanner::scan_source(path, code);

    let f = findings
        .iter()
        .find(|f| f.cve.as_str() == "BK-AI-INF-014")
        .expect("Must flag privileged K8s securityContext");
    assert_eq!(f.severity, Severity::High);
    assert_eq!(f.detector_id, "iac-security");
    assert!(f.advisory_ids.contains(&"CWE-250".to_string()));
}

#[test]
fn test_inf_014_safe_k8s_confined_workload() {
    let code = r#"
apiVersion: v1
kind: Pod
metadata:
  name: confined-pod
spec:
  containers:
    - name: runner
      image: alpine:3.19
      securityContext:
        privileged: false
        allowPrivilegeEscalation: false
        runAsNonRoot: true
        readOnlyRootFilesystem: true
"#;
    let path = Path::new("k8s/pod.yaml");
    let findings = IacScanner::scan_source(path, code);
    assert!(findings.iter().all(|f| f.cve.as_str() != "BK-AI-INF-014"));
}

#[test]
fn test_inf_015_vulnerable_imdsv1_optional_tokens() {
    let code = r#"
resource "aws_instance" "app_server" {
  ami           = "ami-12345678"
  instance_type = "t3.medium"
  metadata_options {
    http_tokens                 = "optional"
    http_put_response_hop_limit = 3
  }
}
"#;
    let path = Path::new("terraform/ec2.tf");
    let findings = IacScanner::scan_source(path, code);

    let f = findings
        .iter()
        .find(|f| f.cve.as_str() == "BK-AI-INF-015")
        .expect("Must flag http_tokens optional and hop limit > 1");
    assert_eq!(f.severity, Severity::High);
    assert_eq!(f.detector_id, "iac-security");
    assert!(f.advisory_ids.contains(&"CWE-918".to_string()));
}

#[test]
fn test_inf_015_safe_imdsv2_required_tokens() {
    let code = r#"
resource "aws_instance" "app_server" {
  ami           = "ami-12345678"
  instance_type = "t3.medium"
  metadata_options {
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }
}
"#;
    let path = Path::new("terraform/ec2.tf");
    let findings = IacScanner::scan_source(path, code);
    assert!(findings.iter().all(|f| f.cve.as_str() != "BK-AI-INF-015"));
}

#[test]
fn test_inf_016_vulnerable_unencrypted_backup_vault() {
    let code = r#"
resource "aws_backup_vault" "vault" {
  name                  = "production_vault"
  kms_key_arn           = null
  enable_retention_lock = false
}
"#;
    let path = Path::new("terraform/backup.tf");
    let findings = IacScanner::scan_source(path, code);

    let f = findings
        .iter()
        .find(|f| f.cve.as_str() == "BK-AI-INF-016")
        .expect("Must flag null KMS key and disabled retention lock in backup vault");
    assert_eq!(f.severity, Severity::High);
    assert_eq!(f.detector_id, "iac-security");
    assert!(f.advisory_ids.contains(&"CWE-552".to_string()));
}

#[test]
fn test_inf_016_safe_encrypted_backup_vault() {
    let code = r#"
resource "aws_backup_vault" "vault" {
  name                  = "production_vault"
  kms_key_arn           = "arn:aws:kms:us-east-1:123456789012:key/test-kms-key"
  enable_retention_lock = true
}
"#;
    let path = Path::new("terraform/backup.tf");
    let findings = IacScanner::scan_source(path, code);
    assert!(findings.iter().all(|f| f.cve.as_str() != "BK-AI-INF-016"));
}

// ===========================================================================
// Category 14: CI/CD, Build Pipelines & Repo Automation Tests (BK-AI-CIC)
// ===========================================================================

#[test]
fn test_cic_005_vulnerable_curl_pipe_bash() {
    let code = r#"
#!/usr/bin/env bash
curl -sSL https://raw.githubusercontent.com/untrusted/installer/main/install.sh | bash
"#;
    let path = Path::new("scripts/install.sh");
    let findings = IacScanner::scan_source(path, code);

    let f = findings
        .iter()
        .find(|f| f.cve.as_str() == "BK-AI-CIC-005")
        .expect("Must flag curl piped directly to bash");
    assert_eq!(f.severity, Severity::High);
    assert_eq!(f.detector_id, "iac-security");
    assert!(f.advisory_ids.contains(&"CWE-829".to_string()));
}

#[test]
fn test_cic_005_safe_curl_with_checksum_verification() {
    let code = r#"
#!/usr/bin/env bash
curl -sSL https://raw.githubusercontent.com/untrusted/installer/main/install.sh -o /tmp/install.sh
echo "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad  /tmp/install.sh" | sha256sum -c
bash /tmp/install.sh
"#;
    let path = Path::new("scripts/install.sh");
    let findings = IacScanner::scan_source(path, code);
    assert!(findings.iter().all(|f| f.cve.as_str() != "BK-AI-CIC-005"));
}

#[test]
fn test_cic_007_vulnerable_pr_cache_reuse() {
    let code = r#"
- name: Cache dependencies
  uses: actions/cache@v4
  with:
    path: ~/.npm
    key: ${{ runner.os }}-build-${{ github.head_ref }}
"#;
    let path = Path::new(".github/workflows/ci.yml");
    let findings = IacScanner::scan_source(path, code);

    let f = findings
        .iter()
        .find(|f| f.cve.as_str() == "BK-AI-CIC-007")
        .expect("Must flag cache key bound to github.head_ref");
    assert_eq!(f.severity, Severity::High);
    assert_eq!(f.detector_id, "iac-security");
    assert!(f.advisory_ids.contains(&"CWE-829".to_string()));
}

#[test]
fn test_cic_007_safe_lockfile_cache_key() {
    let code = r#"
- name: Cache dependencies
  uses: actions/cache@v4
  with:
    path: ~/.npm
    key: ${{ runner.os }}-build-${{ hashFiles('**/package-lock.json') }}
    restore-keys: ${{ runner.os }}-build-
"#;
    let path = Path::new(".github/workflows/ci.yml");
    let findings = IacScanner::scan_source(path, code);
    assert!(findings.iter().all(|f| f.cve.as_str() != "BK-AI-CIC-007"));
}

#[test]
fn test_cic_008_vulnerable_wildcard_deploy_trigger() {
    let code = r#"
name: Deploy Production
on:
  push:
    branches: ["**"]
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - run: ./deploy.sh
"#;
    let path = Path::new(".github/workflows/deploy.yml");
    let findings = IacScanner::scan_source(path, code);

    let f = findings
        .iter()
        .find(|f| f.cve.as_str() == "BK-AI-CIC-008")
        .expect("Must flag deployment triggered on wildcard branches without environment gates");
    assert_eq!(f.severity, Severity::High);
    assert_eq!(f.detector_id, "iac-security");
    assert!(f.advisory_ids.contains(&"CWE-284".to_string()));
}

#[test]
fn test_cic_008_safe_protected_branch_deployment() {
    let code = r#"
name: Deploy Production
on:
  push:
    branches: [main]
jobs:
  deploy:
    environment: production
    runs-on: ubuntu-latest
    steps:
      - run: ./deploy.sh
"#;
    let path = Path::new(".github/workflows/deploy.yml");
    let findings = IacScanner::scan_source(path, code);
    assert!(findings.iter().all(|f| f.cve.as_str() != "BK-AI-CIC-008"));
}

#[test]
fn test_cic_009_vulnerable_mutable_release_checkout() {
    let code = r#"
name: Release
jobs:
  publish:
    runs-on: ubuntu-latest
    steps:
      - run: |
          git checkout main
          npm run publish
"#;
    let path = Path::new(".github/workflows/release.yml");
    let findings = IacScanner::scan_source(path, code);

    let f = findings
        .iter()
        .find(|f| f.cve.as_str() == "BK-AI-CIC-009")
        .expect("Must flag release checkout of mutable main branch head");
    assert_eq!(f.severity, Severity::High);
    assert_eq!(f.detector_id, "iac-security");
    assert!(f.advisory_ids.contains(&"CWE-494".to_string()));
}

#[test]
fn test_cic_009_safe_immutable_release_checkout() {
    let code = r#"
name: Release
jobs:
  publish:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.sha }}
      - run: npm run publish
"#;
    let path = Path::new(".github/workflows/release.yml");
    let findings = IacScanner::scan_source(path, code);
    assert!(findings.iter().all(|f| f.cve.as_str() != "BK-AI-CIC-009"));
}

#[test]
fn test_cic_010_vulnerable_continue_on_error_test() {
    let code = r#"
name: Test Suite
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - name: Run test suite
        run: npm test
        continue-on-error: true
"#;
    let path = Path::new(".github/workflows/test.yml");
    let findings = IacScanner::scan_source(path, code);

    let f = findings
        .iter()
        .find(|f| f.cve.as_str() == "BK-AI-CIC-010")
        .expect("Must flag continue-on-error: true on test job");
    assert_eq!(f.severity, Severity::High);
    assert_eq!(f.detector_id, "iac-security");
}

#[test]
fn test_cic_010_safe_blocking_test_failure() {
    let code = r#"
name: Test Suite
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - name: Run test suite
        run: npm test
        continue-on-error: false
"#;
    let path = Path::new(".github/workflows/test.yml");
    let findings = IacScanner::scan_source(path, code);
    assert!(findings.iter().all(|f| f.cve.as_str() != "BK-AI-CIC-010"));
}

#[test]
fn test_cic_011_vulnerable_privileged_token_install() {
    let code = r#"
steps:
  - name: Install dependencies
    env:
      GITHUB_TOKEN: ${{ secrets.CUSTOM_BOT_TOKEN }}
    run: npm install
"#;
    let path = Path::new(".github/workflows/build.yml");
    let findings = IacScanner::scan_source(path, code);

    let f = findings
        .iter()
        .find(|f| f.cve.as_str() == "BK-AI-CIC-011")
        .expect("Must flag npm install exposing GITHUB_TOKEN without ignore-scripts");
    assert_eq!(f.severity, Severity::High);
    assert_eq!(f.detector_id, "iac-security");
    assert!(f.advisory_ids.contains(&"CWE-250".to_string()));
}

#[test]
fn test_cic_011_safe_ignore_scripts_install() {
    let code = r#"
steps:
  - name: Install dependencies
    run: npm ci --ignore-scripts
"#;
    let path = Path::new(".github/workflows/build.yml");
    let findings = IacScanner::scan_source(path, code);
    assert!(findings.iter().all(|f| f.cve.as_str() != "BK-AI-CIC-011"));
}

#[test]
fn test_cic_012_vulnerable_skip_provenance_publish() {
    let code = r#"
steps:
  - name: Publish NPM package
    run: npm publish --no-provenance
"#;
    let path = Path::new(".github/workflows/publish.yml");
    let findings = IacScanner::scan_source(path, code);

    let f = findings
        .iter()
        .find(|f| f.cve.as_str() == "BK-AI-CIC-012")
        .expect("Must flag package publish with --no-provenance");
    assert_eq!(f.severity, Severity::High);
    assert_eq!(f.detector_id, "iac-security");
    assert!(f.advisory_ids.contains(&"CWE-494".to_string()));
}

#[test]
fn test_cic_012_safe_provenance_publish() {
    let code = r#"
steps:
  - name: Publish NPM package
    run: npm publish --provenance
"#;
    let path = Path::new(".github/workflows/publish.yml");
    let findings = IacScanner::scan_source(path, code);
    assert!(findings.iter().all(|f| f.cve.as_str() != "BK-AI-CIC-012"));
}

#[test]
fn test_cic_013_vulnerable_unattended_auto_merge() {
    let code = r#"
steps:
  - name: Auto-merge PR
    run: gh pr merge $PR_URL --auto --squash
"#;
    let path = Path::new(".github/workflows/automerge.yml");
    let findings = IacScanner::scan_source(path, code);

    let f = findings
        .iter()
        .find(|f| f.cve.as_str() == "BK-AI-CIC-013")
        .expect("Must flag unattended gh pr merge --auto");
    assert_eq!(f.severity, Severity::High);
    assert_eq!(f.detector_id, "iac-security");
    assert!(f.advisory_ids.contains(&"CWE-863".to_string()));
}

#[test]
fn test_cic_013_safe_approved_auto_merge() {
    let code = r#"
steps:
  - name: Merge after human approval review
    run: |
      if [ "$REVIEW_DECISION" = "APPROVED" ]; then
        gh pr merge $PR_URL --squash
      fi
"#;
    let path = Path::new(".github/workflows/automerge.yml");
    let findings = IacScanner::scan_source(path, code);
    assert!(findings.iter().all(|f| f.cve.as_str() != "BK-AI-CIC-013"));
}

#[test]
fn test_cic_014_vulnerable_untrusted_event_in_run() {
    let code = r#"
steps:
  - name: Echo issue title
    run: |
      echo "Processing issue: ${{ github.event.issue.title }}"
"#;
    let path = Path::new(".github/workflows/comment.yml");
    let findings = IacScanner::scan_source(path, code);

    let f = findings
        .iter()
        .find(|f| f.cve.as_str() == "BK-AI-CIC-014")
        .expect("Must flag inline interpolation of github.event.issue.title in run step");
    assert_eq!(f.severity, Severity::High);
    assert_eq!(f.detector_id, "iac-security");
    assert!(f.advisory_ids.contains(&"CWE-78".to_string()));
}

#[test]
fn test_cic_014_safe_env_variable_mapping() {
    let code = r#"
steps:
  - name: Echo issue title
    env:
      ISSUE_TITLE: ${{ github.event.issue.title }}
    run: |
      echo "Processing issue: $ISSUE_TITLE"
"#;
    let path = Path::new(".github/workflows/comment.yml");
    let findings = IacScanner::scan_source(path, code);
    assert!(findings.iter().all(|f| f.cve.as_str() != "BK-AI-CIC-014"));
}
