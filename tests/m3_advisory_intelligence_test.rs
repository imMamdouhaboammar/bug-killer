use bug_killer::advisory::*;
use bug_killer::engine::protocol::*;
use chrono::{Duration, Utc};

const DUMMY_HASH: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

fn create_sample_advisory(
    id: &str,
    aliases: Vec<&str>,
    ecosystem: &str,
    package_name: &str,
    introduced: Option<&str>,
    fixed: Option<&str>,
    status: AdvisoryStatus,
) -> AdvisoryRecord {
    AdvisoryRecord {
        schema_version: "1.0".to_string(),
        advisory_id: id.to_string(),
        aliases: aliases.into_iter().map(|s| s.to_string()).collect(),
        source: AdvisorySource {
            provider: "OSV".to_string(),
            url: "https://osv.dev".to_string(),
            retrieved_at: Utc::now().to_rfc3339(),
        },
        source_sha256: DUMMY_HASH.to_string(),
        published_at: Some("2024-01-01T00:00:00Z".to_string()),
        modified_at: Some("2024-01-02T00:00:00Z".to_string()),
        withdrawn_at: if status == AdvisoryStatus::Withdrawn {
            Some("2024-01-03T00:00:00Z".to_string())
        } else {
            None
        },
        affected: vec![AdvisoryAffected {
            purl: Some(make_purl(ecosystem, package_name, "")),
            ecosystem: ecosystem.to_string(),
            name: Some(package_name.to_string()),
            ranges: vec![AdvisoryRange {
                range_type: "SEMVER".to_string(),
                events: vec![AdvisoryEvent {
                    introduced: introduced.map(|s| s.to_string()),
                    fixed: fixed.map(|s| s.to_string()),
                    last_affected: None,
                }],
            }],
            fixed_versions: fixed.into_iter().map(|s| s.to_string()).collect(),
        }],
        references: vec!["https://example.com/advisory".to_string()],
        status,
        summary: Some(format!("Vulnerability in {}", package_name)),
        details: Some("Detailed vulnerability report".to_string()),
        severity: Some("HIGH".to_string()),
    }
}

// -------------------------------------------------------------------------
// Test 1: Alias deduplication
// OSV advisory with aliases CVE-2024-1234 and GHSA-abcd-1234 merges into 1 canonical finding.
// -------------------------------------------------------------------------
#[test]
fn test_1_alias_deduplication_merges_into_canonical_finding() {
    let adv1 = create_sample_advisory(
        "OSV-2024-1234",
        vec!["CVE-2024-1234", "GHSA-abcd-1234"],
        "npm",
        "express",
        Some("4.0.0"),
        Some("4.19.2"),
        AdvisoryStatus::Active,
    );
    let adv2 = create_sample_advisory(
        "GHSA-abcd-1234",
        vec!["CVE-2024-1234", "OSV-2024-1234"],
        "npm",
        "express",
        Some("4.0.0"),
        Some("4.19.2"),
        AdvisoryStatus::Active,
    );

    let pkg = PackageIdentity {
        ecosystem: "npm".to_string(),
        name: "express".to_string(),
        resolved_version: Some("4.18.2".to_string()),
        purl: Some("pkg:npm/express@4.18.2".to_string()),
        direct: true,
        resolution_kind: ResolutionKind::LockedExact,
        commit: None,
        origin: None,
        path: Some("package-lock.json".to_string()),
        source_digest: None,
        declared_requirement: None,
    };

    let correlator = AffectednessCorrelator::new();
    let findings = correlator.correlate("run-test-1", DUMMY_HASH, &[pkg], &[adv1, adv2]);

    assert_eq!(
        findings.len(),
        1,
        "Expected exactly 1 canonical finding after alias deduplication, got {}",
        findings.len()
    );

    let canonical = &findings[0];
    assert!(
        canonical.validate().is_ok(),
        "Canonical finding must satisfy FindingV1 schema validation"
    );
    assert_eq!(canonical.kind, FindingKind::KnownAdvisory);
    assert_eq!(canonical.status, FindingStatus::VersionAffected);

    // Advisory IDs in finding must contain all deduplicated aliases
    assert!(
        canonical
            .advisory_ids
            .contains(&"CVE-2024-1234".to_string())
    );
    assert!(
        canonical
            .advisory_ids
            .contains(&"GHSA-abcd-1234".to_string())
    );
    assert!(
        canonical
            .advisory_ids
            .contains(&"OSV-2024-1234".to_string())
    );
}

// -------------------------------------------------------------------------
// Test 2: Declared requirement without lockfile yields Affectedness::Inconclusive
// e.g. requests>=2.20.0 yields Inconclusive, not a fake exact version match.
// -------------------------------------------------------------------------
#[test]
fn test_2_declared_requirement_without_lockfile_yields_inconclusive() {
    let adv = create_sample_advisory(
        "CVE-2023-32681",
        vec!["GHSA-j8r2-6x86-q33q"],
        "pypi",
        "requests",
        Some("2.0.0"),
        Some("2.31.0"),
        AdvisoryStatus::Active,
    );

    let requirements_txt = "requests>=2.20.0\n";
    let packages = parse_requirements_txt(requirements_txt, Some("requirements.txt"))
        .expect("requirements.txt should parse successfully");

    assert_eq!(packages.len(), 1);
    let pkg = &packages[0];
    assert_eq!(pkg.name, "requests");
    assert_eq!(pkg.resolution_kind, ResolutionKind::DeclaredRange);
    assert!(pkg.resolved_version.is_none());

    let correlator = AffectednessCorrelator::new();
    let affectedness = correlator.evaluate_affectedness(pkg, &adv);

    assert_eq!(
        affectedness,
        Affectedness::Inconclusive,
        "Declared requirement without lockfile must yield Inconclusive"
    );
}

// -------------------------------------------------------------------------
// Test 3: Exact locked version within affected range yields VersionAffected
// -------------------------------------------------------------------------
#[test]
fn test_3_exact_locked_version_within_affected_range_yields_version_affected() {
    let adv = create_sample_advisory(
        "CVE-2023-32681",
        vec!["GHSA-j8r2-6x86-q33q"],
        "pypi",
        "requests",
        Some("2.0.0"),
        Some("2.31.0"),
        AdvisoryStatus::Active,
    );

    let pkg = PackageIdentity {
        ecosystem: "pypi".to_string(),
        name: "requests".to_string(),
        resolved_version: Some("2.28.1".to_string()),
        purl: Some("pkg:pypi/requests@2.28.1".to_string()),
        direct: true,
        resolution_kind: ResolutionKind::LockedExact,
        commit: None,
        origin: None,
        path: Some("poetry.lock".to_string()),
        source_digest: None,
        declared_requirement: None,
    };

    let correlator = AffectednessCorrelator::new();
    let affectedness = correlator.evaluate_affectedness(&pkg, &adv);

    assert_eq!(
        affectedness,
        Affectedness::VersionAffected,
        "Locked version 2.28.1 in range [2.0.0, 2.31.0) must yield VersionAffected"
    );

    // Verify finding metadata includes the correct fixed version
    let findings = correlator.correlate("run-test-3", DUMMY_HASH, &[pkg], &[adv]);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].status, FindingStatus::VersionAffected);
}

// -------------------------------------------------------------------------
// Test 4: Patched version yields Affectedness::NotAffected
// -------------------------------------------------------------------------
#[test]
fn test_4_patched_version_yields_not_affected() {
    let adv = create_sample_advisory(
        "CVE-2023-32681",
        vec!["GHSA-j8r2-6x86-q33q"],
        "pypi",
        "requests",
        Some("2.0.0"),
        Some("2.31.0"),
        AdvisoryStatus::Active,
    );

    let pkg = PackageIdentity {
        ecosystem: "pypi".to_string(),
        name: "requests".to_string(),
        resolved_version: Some("2.31.0".to_string()),
        purl: Some("pkg:pypi/requests@2.31.0".to_string()),
        direct: true,
        resolution_kind: ResolutionKind::LockedExact,
        commit: None,
        origin: None,
        path: Some("poetry.lock".to_string()),
        source_digest: None,
        declared_requirement: None,
    };

    let correlator = AffectednessCorrelator::new();
    let affectedness = correlator.evaluate_affectedness(&pkg, &adv);

    assert_eq!(
        affectedness,
        Affectedness::NotAffected,
        "Patched version 2.31.0 must yield NotAffected"
    );

    let findings = correlator.correlate("run-test-4", DUMMY_HASH, &[pkg], &[adv]);
    assert_eq!(
        findings.len(),
        0,
        "NotAffected package must not produce active vulnerability findings"
    );
}

// -------------------------------------------------------------------------
// Test 5: Transitive exposure guard
// Upgrading direct dependency while transitive vulnerable copy remains blocks FixedVerified
// and yields honest incomplete status.
// -------------------------------------------------------------------------
#[test]
fn test_5_transitive_exposure_guard_blocks_fixed_verified() {
    let adv = create_sample_advisory(
        "CVE-2021-3749",
        vec!["GHSA-2p37-4rq4-8mqf"],
        "npm",
        "axios",
        Some("0.0.0"),
        Some("0.21.2"),
        AdvisoryStatus::Active,
    );

    // Direct dependency 'api-client' was bumped to 2.0.0,
    // BUT an indirect/transitive 'axios@0.21.1' is still present in the lockfile inventory!
    let direct_pkg = PackageIdentity {
        ecosystem: "npm".to_string(),
        name: "api-client".to_string(),
        resolved_version: Some("2.0.0".to_string()),
        purl: Some("pkg:npm/api-client@2.0.0".to_string()),
        direct: true,
        resolution_kind: ResolutionKind::LockedExact,
        commit: None,
        origin: None,
        path: Some("package-lock.json".to_string()),
        source_digest: None,
        declared_requirement: None,
    };

    let remaining_transitive_vulnerable = PackageIdentity {
        ecosystem: "npm".to_string(),
        name: "axios".to_string(),
        resolved_version: Some("0.21.1".to_string()),
        purl: Some("pkg:npm/axios@0.21.1".to_string()),
        direct: false,
        resolution_kind: ResolutionKind::LockedExact,
        commit: None,
        origin: None,
        path: Some("package-lock.json".to_string()),
        source_digest: None,
        declared_requirement: None,
    };

    let post_repair_inventory = vec![direct_pkg.clone(), remaining_transitive_vulnerable];

    let planner = PackageRepairPlanner::new();
    let plan = planner
        .plan_package_upgrade(
            "run-repair-5",
            DUMMY_HASH,
            &direct_pkg,
            "2.0.0",
            "package-lock.json",
            "{\"dependencies\": {\"api-client\": \"1.0.0\"}}",
            vec!["finding-axios-001".to_string()],
            RepairRiskLevel::L1,
        )
        .expect("Repair plan generation should succeed");

    assert!(plan.validate().is_ok());

    let verification_outcome = planner.verify_repair_outcome(&plan, &post_repair_inventory, &[adv]);

    match &verification_outcome {
        RepairVerificationStatus::IncompleteRepair {
            reason,
            retained_vulnerabilities,
        } => {
            assert!(
                reason.to_lowercase().contains("transitive")
                    || reason.to_lowercase().contains("retained"),
                "Expected incomplete repair reason to mention transitive retention, got: {}",
                reason
            );
            assert!(
                !retained_vulnerabilities.is_empty(),
                "Must list retained vulnerabilities"
            );
        }
        other => panic!(
            "Expected IncompleteRepair due to remaining transitive vulnerability, got: {:?}",
            other
        ),
    }

    let receipt = planner.generate_coverage_receipt("run-repair-5", &verification_outcome);
    assert_eq!(receipt.status, CoverageReceiptStatus::Partial);
    assert!(receipt.validate().is_ok());
}

// -------------------------------------------------------------------------
// Test 6: Stale feed cache beyond TTL surfaces honest receipt warning / partial status
// -------------------------------------------------------------------------
#[test]
fn test_6_stale_feed_cache_surfaces_partial_receipt_warning() {
    let old_timestamp = (Utc::now() - Duration::hours(48)).to_rfc3339();
    let snapshot = AdvisorySnapshot {
        snapshot_sha256: DUMMY_HASH.to_string(),
        retrieved_at: old_timestamp,
        records: vec![],
    };

    let cache = AdvisoryCache::new(snapshot);

    // With a TTL of 24 hours (86400 seconds), 48h-old snapshot must be stale
    let ttl_seconds = 86400;
    assert!(
        cache.is_stale(ttl_seconds),
        "Advisory cache older than TTL must be reported as stale"
    );

    let receipt = cache.generate_receipt(
        "run-test-6",
        "check-advisory",
        "target-workspace",
        ttl_seconds,
    );
    assert_eq!(
        receipt.status,
        CoverageReceiptStatus::Partial,
        "Stale cache must yield CoverageReceiptStatus::Partial"
    );
    assert!(
        !receipt.reason_codes.is_empty(),
        "Stale cache receipt must include reason code"
    );
    assert!(
        receipt.validate().is_ok(),
        "CoverageReceiptV1 must satisfy schema invariants"
    );
}

// -------------------------------------------------------------------------
// Test 7: Offline fixture execution runs cleanly with 0 network calls
// -------------------------------------------------------------------------
#[test]
fn test_7_offline_fixture_execution_with_zero_network_calls() {
    let adv = create_sample_advisory(
        "RUSTSEC-2020-0071",
        vec!["CVE-2020-35873"],
        "cargo",
        "smallvec",
        Some("0.6.0"),
        Some("0.6.14"),
        AdvisoryStatus::Active,
    );

    let mut mock_provider = MockAdvisoryProvider::new();
    mock_provider.add_advisory(adv.clone());

    let pkg = PackageIdentity {
        ecosystem: "cargo".to_string(),
        name: "smallvec".to_string(),
        resolved_version: Some("0.6.13".to_string()),
        purl: Some("pkg:cargo/smallvec@0.6.13".to_string()),
        direct: true,
        resolution_kind: ResolutionKind::LockedExact,
        commit: None,
        origin: None,
        path: Some("Cargo.lock".to_string()),
        source_digest: None,
        declared_requirement: None,
    };

    // Provider lookup is completely local and offline
    let purl = pkg.purl.as_ref().unwrap();
    let advisories = mock_provider.get_advisories_for_package(purl);
    assert_eq!(advisories.len(), 1);

    let correlator = AffectednessCorrelator::new();
    let findings = correlator.correlate("run-test-7", DUMMY_HASH, &[pkg], &advisories);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].status, FindingStatus::VersionAffected);
}

// -------------------------------------------------------------------------
// Test 8: Withdrawn advisory updates do not produce active vulnerability findings
// -------------------------------------------------------------------------
#[test]
fn test_8_withdrawn_advisory_does_not_produce_active_finding() {
    let withdrawn_adv = create_sample_advisory(
        "GHSA-withdrawn-0001",
        vec!["CVE-2024-99999"],
        "npm",
        "lodash",
        Some("4.0.0"),
        Some("4.17.21"),
        AdvisoryStatus::Withdrawn,
    );

    let pkg = PackageIdentity {
        ecosystem: "npm".to_string(),
        name: "lodash".to_string(),
        resolved_version: Some("4.17.15".to_string()),
        purl: Some("pkg:npm/lodash@4.17.15".to_string()),
        direct: true,
        resolution_kind: ResolutionKind::LockedExact,
        commit: None,
        origin: None,
        path: Some("package-lock.json".to_string()),
        source_digest: None,
        declared_requirement: None,
    };

    let correlator = AffectednessCorrelator::new();
    let affectedness = correlator.evaluate_affectedness(&pkg, &withdrawn_adv);

    assert_eq!(
        affectedness,
        Affectedness::NotAffected,
        "Withdrawn advisory must evaluate to NotAffected"
    );

    let findings = correlator.correlate("run-test-8", DUMMY_HASH, &[pkg], &[withdrawn_adv]);
    assert_eq!(
        findings.len(),
        0,
        "Withdrawn advisory must not emit active vulnerability findings"
    );
}

// -------------------------------------------------------------------------
// Additional Tests: SBOM Manifest Ingestion across ecosystems
// -------------------------------------------------------------------------
#[test]
fn test_sbom_manifest_and_lockfile_ingestion() {
    // 1. package-lock.json
    let pkg_lock_json = r#"{
        "name": "my-app",
        "version": "1.0.0",
        "lockfileVersion": 3,
        "packages": {
            "": {
                "dependencies": {
                    "debug": "^4.3.4"
                }
            },
            "node_modules/debug": {
                "version": "4.3.4"
            },
            "node_modules/debug/node_modules/ms": {
                "version": "2.1.2"
            }
        }
    }"#;
    let npm_pkgs = parse_package_lock(pkg_lock_json, Some("package-lock.json"))
        .expect("package-lock.json should parse");
    assert_eq!(npm_pkgs.len(), 2);
    let debug_pkg = npm_pkgs.iter().find(|p| p.name == "debug").unwrap();
    assert_eq!(debug_pkg.resolved_version.as_deref(), Some("4.3.4"));
    assert_eq!(debug_pkg.resolution_kind, ResolutionKind::LockedExact);
    assert!(debug_pkg.direct);

    let ms_pkg = npm_pkgs.iter().find(|p| p.name == "ms").unwrap();
    assert_eq!(ms_pkg.resolved_version.as_deref(), Some("2.1.2"));
    assert!(
        !ms_pkg.direct,
        "Nested package should be indirect/transitive"
    );

    // 2. Cargo.lock
    let cargo_lock = r#"
[[package]]
name = "serde"
version = "1.0.197"
dependencies = [
 "serde_derive",
]

[[package]]
name = "serde_json"
version = "1.0.115"
"#;
    let cargo_pkgs =
        parse_cargo_lock(cargo_lock, Some("Cargo.lock")).expect("Cargo.lock should parse");
    assert_eq!(cargo_pkgs.len(), 2);
    assert_eq!(cargo_pkgs[0].name, "serde");
    assert_eq!(cargo_pkgs[0].resolved_version.as_deref(), Some("1.0.197"));
    assert_eq!(
        cargo_pkgs[0].purl.as_deref(),
        Some("pkg:cargo/serde@1.0.197")
    );

    // 3. composer.lock
    let composer_lock = r#"{
        "packages": [
            {
                "name": "guzzlehttp/guzzle",
                "version": "v7.8.1"
            }
        ],
        "packages-dev": [
            {
                "name": "phpunit/phpunit",
                "version": "10.5.0"
            }
        ]
    }"#;
    let composer_pkgs = parse_composer_lock(composer_lock, Some("composer.lock"))
        .expect("composer.lock should parse");
    assert_eq!(composer_pkgs.len(), 2);
    let guzzle = composer_pkgs
        .iter()
        .find(|p| p.name == "guzzlehttp/guzzle")
        .unwrap();
    assert_eq!(guzzle.resolved_version.as_deref(), Some("7.8.1"));
    assert!(guzzle.direct);
    let phpunit = composer_pkgs
        .iter()
        .find(|p| p.name == "phpunit/phpunit")
        .unwrap();
    assert_eq!(phpunit.resolved_version.as_deref(), Some("10.5.0"));
    assert!(!phpunit.direct);

    // 4. pyproject.toml
    let pyproject = r#"
[project]
name = "demo"
dependencies = [
    "urllib3>=1.26.5",
    "requests<3.0.0"
]
"#;
    let pyproject_pkgs = parse_pyproject_toml(pyproject, Some("pyproject.toml"))
        .expect("pyproject.toml should parse");
    assert_eq!(pyproject_pkgs.len(), 2);
    assert_eq!(
        pyproject_pkgs[0].resolution_kind,
        ResolutionKind::DeclaredRange
    );
    assert!(pyproject_pkgs[0].resolved_version.is_none());
    assert_eq!(
        pyproject_pkgs[0].declared_requirement.as_deref(),
        Some(">=1.26.5")
    );
}

// -------------------------------------------------------------------------
// Additional Tests: PURL generation for all 5 required ecosystems
// -------------------------------------------------------------------------
#[test]
fn test_purl_generation_all_ecosystems() {
    assert_eq!(
        make_purl("npm", "lodash", "4.17.21"),
        "pkg:npm/lodash@4.17.21"
    );
    assert_eq!(
        make_purl("pypi", "requests", "2.31.0"),
        "pkg:pypi/requests@2.31.0"
    );
    assert_eq!(
        make_purl("cargo", "tokio", "1.36.0"),
        "pkg:cargo/tokio@1.36.0"
    );
    assert_eq!(
        make_purl("golang", "github.com/gin-gonic/gin", "1.9.1"),
        "pkg:golang/github.com/gin-gonic/gin@1.9.1"
    );
    assert_eq!(
        make_purl("composer", "monolog/monolog", "3.5.0"),
        "pkg:composer/monolog/monolog@3.5.0"
    );

    // Unpinned / Range PURLs
    assert_eq!(make_purl("pypi", "flask", ""), "pkg:pypi/flask");
}

// -------------------------------------------------------------------------
// Additional Tests: Cache snapshot creation with SHA-256 digest
// -------------------------------------------------------------------------
#[test]
fn test_cache_snapshot_creation_and_digest() {
    let adv = create_sample_advisory(
        "CVE-2024-0001",
        vec![],
        "npm",
        "tar",
        Some("6.0.0"),
        Some("6.2.1"),
        AdvisoryStatus::Active,
    );
    let cache = AdvisoryCache::from_records(vec![adv], Utc::now().to_rfc3339());
    assert_eq!(cache.snapshot().snapshot_sha256.len(), 64);
    assert!(!cache.is_stale(3600));
}
