use bug_killer::benchmark::*;
use bug_killer::types::EvidenceCertainty;
use std::fs;
use std::path::Path;
use tempfile::tempdir;

const BENCHMARK_DIR: &str = "tests/fixtures/benchmark";

// @lat: [[tests#Test Suite Specifications#Benchmark Gates#Tamper Free Corpus Loading]]
#[test]
fn test_corpus_loading_and_tamper_free_verification() {
    let corpus = BenchmarkCorpus::load_from_dir(Path::new(BENCHMARK_DIR))
        .expect("Corpus loading and SHA-256 verification must succeed on valid fixtures");

    assert_eq!(corpus.manifest_version, "1.0.0");
    assert_eq!(corpus.cases.len(), 17);
    assert!(!corpus.dataset_fingerprint.is_empty());

    // Internal verification must pass
    corpus.verify().expect("Corpus verify must pass");

    // Re-verifying against exact known fingerprint
    let expected_fingerprint = corpus.dataset_fingerprint.clone();
    corpus
        .verify_against_fingerprint(&expected_fingerprint)
        .expect("Fingerprint verification must match");
}

#[test]
fn test_gate_1_perfect_synthetic_classifier_passes_with_100_percent_metrics() {
    let corpus =
        BenchmarkCorpus::load_from_dir(Path::new(BENCHMARK_DIR)).expect("Corpus must load cleanly");

    // Perfect classifier that models ground-truth behavior
    let perfect_classifier = FnClassifier::new(
        "perfect-oracle-engine",
        |case: &BenchmarkCase, _content: &str| {
            if case.expected_vulnerable {
                BenchmarkPrediction::vulnerable(
                    case.expected_rule_ids.clone(),
                    case.expected_certainty_cap,
                )
            } else {
                BenchmarkPrediction::safe()
            }
        },
    );

    let runner = BenchmarkRunner::new(corpus);
    let report = runner
        .run(&perfect_classifier)
        .expect("Benchmark execution should succeed");

    assert_eq!(report.total_cases, 17);
    let m = &report.metrics.overall;

    // 9 positive cases (CWE-89: 2 pos, CWE-78: 1 pos, CWE-918: 1 pos, CWE-22: 1 pos,
    // CWE-502: 1 pos, CWE-798: 1 pos, CWE-1333: 1 pos, CWE-287: 1 pos)
    assert_eq!(m.tp, 9, "Expected exactly 9 true positives");
    // 8 negative cases
    assert_eq!(m.tn, 8, "Expected exactly 8 true negatives");
    assert_eq!(m.fp, 0, "Expected zero false positives");
    assert_eq!(m.fn_count, 0, "Expected zero false negatives");

    // Metric gates: 100% Precision, 100% Recall, 0% FPR, 1.0 F1
    assert!(
        (m.recall() - 1.0).abs() < f64::EPSILON,
        "Recall must be 1.0 (100%), got {}",
        m.recall()
    );
    assert!(
        (m.precision() - 1.0).abs() < f64::EPSILON,
        "Precision must be 1.0 (100%), got {}",
        m.precision()
    );
    assert!(
        (m.fpr() - 0.0).abs() < f64::EPSILON,
        "FPR must be 0.0 (0%), got {}",
        m.fpr()
    );
    assert!(
        (m.f1_score() - 1.0).abs() < f64::EPSILON,
        "F1 score must be 1.0, got {}",
        m.f1_score()
    );
    assert!(
        (m.accuracy() - 1.0).abs() < f64::EPSILON,
        "Accuracy must be 1.0, got {}",
        m.accuracy()
    );

    // Every single case evaluation must pass
    assert!(
        report.case_evaluations.iter().all(|e| e.passed),
        "All case evaluations must pass under perfect classifier"
    );

    // Per-CWE breakdown validation
    let cwe89 = report
        .metrics
        .by_cwe
        .get("CWE-89")
        .expect("CWE-89 must be present");
    assert_eq!(cwe89.tp, 2);
    assert_eq!(cwe89.tn, 1);
    assert_eq!(cwe89.fp, 0);
    assert_eq!(cwe89.fn_count, 0);
    assert!((cwe89.recall() - 1.0).abs() < f64::EPSILON);

    // Per-language breakdown validation
    let py = report
        .metrics
        .by_language
        .get("python")
        .expect("Python must be present");
    assert_eq!(py.tp, 8);
    assert_eq!(py.tn, 7);
    assert_eq!(py.total(), 15);

    let js = report
        .metrics
        .by_language
        .get("javascript")
        .expect("JS must be present");
    assert_eq!(js.tp, 1);
    assert_eq!(js.tn, 1);
    assert_eq!(js.total(), 2);
}

#[test]
fn test_gate_2_intentionally_bad_classifiers_fail_metric_gates() {
    let corpus =
        BenchmarkCorpus::load_from_dir(Path::new(BENCHMARK_DIR)).expect("Corpus must load cleanly");
    let runner = BenchmarkRunner::new(corpus);

    // Bad Classifier A: Always-True (Flags everything as vulnerable)
    let always_vulnerable = FnClassifier::new(
        "bad-always-true-scanner",
        |_case: &BenchmarkCase, _content: &str| {
            BenchmarkPrediction::vulnerable(
                vec!["NAIVE-FLAG-ALL".into()],
                Some(EvidenceCertainty::Unknown),
            )
        },
    );

    let report_bad_a = runner
        .run(&always_vulnerable)
        .expect("Runner should complete");

    let m_a = &report_bad_a.metrics.overall;
    assert_eq!(m_a.tp, 9);
    assert_eq!(
        m_a.fp, 8,
        "Always-true classifier must produce 8 false positives"
    );
    assert_eq!(m_a.tn, 0);
    assert_eq!(m_a.fn_count, 0);

    // Gate failure assertions:
    // FPR must fail the <= 0.05 gate (it is 1.0!)
    assert_eq!(m_a.fpr(), 1.0, "Always-true classifier must have 100% FPR");
    assert!(
        m_a.fpr() > 0.05,
        "Gate check: Always-true classifier must fail FPR gate"
    );

    // Precision must fail the >= 0.90 gate (it is 9/17 ~= 0.5294)
    assert!(
        m_a.precision() < 0.60,
        "Gate check: Always-true classifier must have poor precision (~0.53), got {}",
        m_a.precision()
    );

    // Bad Classifier B: Naive regex classifier that looks for naive substring "query"
    // Fails on safe parameterized queries (False Positive) and misses evasion/other CWEs (False Negative)
    let naive_regex_classifier = FnClassifier::new(
        "naive-regex-scanner",
        |_case: &BenchmarkCase, content: &str| {
            if content.contains("query =") {
                BenchmarkPrediction::vulnerable(vec!["NAIVE-QUERY-RULE".into()], None)
            } else {
                BenchmarkPrediction::safe()
            }
        },
    );

    let report_bad_b = runner
        .run(&naive_regex_classifier)
        .expect("Runner should complete");

    let m_b = &report_bad_b.metrics.overall;
    // The naive regex flagged the safe parameterized query as vulnerable -> FP >= 1
    assert!(
        m_b.fp >= 1,
        "Naive regex must produce false positives on safe parameterized query"
    );
    // The naive regex missed non-SQL weaknesses -> FN >= 1
    assert!(
        m_b.fn_count >= 1,
        "Naive regex must produce false negatives on other CWEs"
    );
    assert!(
        m_b.recall() < 0.5,
        "Naive regex recall must fail (< 0.5), got {}",
        m_b.recall()
    );
}

#[test]
fn test_gate_3_mutating_fixture_or_manifest_fails_verification_and_invalidates_fingerprint() {
    let temp = tempdir().expect("tempdir");
    let temp_path = temp.path();

    // Copy entire benchmark corpus to temp dir
    copy_dir_all(Path::new(BENCHMARK_DIR), temp_path).expect("failed to copy fixtures");

    // 1. Initial verification in tempdir must pass
    let corpus = BenchmarkCorpus::load_from_dir(temp_path).expect("Initial load must pass");
    let baseline_fingerprint = corpus.dataset_fingerprint.clone();
    corpus.verify().expect("Initial verify must pass");

    // 2. Tamper Test A: Mutate a fixture file (append a single space or comment)
    let target_fixture = temp_path.join("cwe_89_sql/cwe_89_positive_concat.py");
    let mut fixture_content = fs::read_to_string(&target_fixture).expect("read fixture");
    fixture_content.push_str("\n# Tampered fixture byte injection\n");
    fs::write(&target_fixture, &fixture_content).expect("write tampered fixture");

    // Now, loading or verifying the corpus MUST fail due to Sha256Mismatch!
    let load_result = BenchmarkCorpus::load_from_dir(temp_path);
    match load_result {
        Err(BenchmarkError::Sha256Mismatch { case_id, .. }) => {
            assert_eq!(case_id, "BK-CWE-89-POS-0001");
        }
        other => panic!("Expected Sha256Mismatch error, got {:?}", other),
    }

    // Restore fixture to valid state
    copy_dir_all(Path::new(BENCHMARK_DIR), temp_path).expect("restore fixtures");

    // 3. Tamper Test B: Mutate manifest metadata (flip expected_vulnerable or change case_id)
    let manifest_path = temp_path.join("benchmark_manifest.json");
    let manifest_content = fs::read_to_string(&manifest_path).expect("read manifest");
    // Tamper with expected_vulnerable in manifest without updating source file
    let tampered_manifest = manifest_content.replace(
        "\"case_id\": \"BK-CWE-89-POS-0001\",\n      \"language\": \"python\",\n      \"weakness\": \"CWE-89\",\n      \"expected_vulnerable\": true",
        "\"case_id\": \"BK-CWE-89-POS-0001\",\n      \"language\": \"python\",\n      \"weakness\": \"CWE-89\",\n      \"expected_vulnerable\": false",
    );
    assert_ne!(
        manifest_content, tampered_manifest,
        "Replacement must have occurred"
    );
    fs::write(&manifest_path, &tampered_manifest).expect("write tampered manifest");

    // Load succeeds because source_sha256 still matches fixture file on disk,
    // BUT the computed dataset_fingerprint MUST be completely different from baseline!
    let tampered_corpus = BenchmarkCorpus::load_from_dir(temp_path).expect("Manifest loads");
    assert_ne!(
        tampered_corpus.dataset_fingerprint, baseline_fingerprint,
        "Mutating manifest MUST invalidate the dataset fingerprint"
    );

    // Explicitly asserting against the expected baseline fingerprint MUST fail
    let check_fingerprint = tampered_corpus.verify_against_fingerprint(&baseline_fingerprint);
    match check_fingerprint {
        Err(BenchmarkError::FingerprintMismatch { expected, actual }) => {
            assert_eq!(expected, baseline_fingerprint);
            assert_eq!(actual, tampered_corpus.dataset_fingerprint);
        }
        other => panic!("Expected FingerprintMismatch, got {:?}", other),
    }
}

// @lat: [[tests#Test Suite Specifications#Benchmark Gates#Repeated Runs Produce Identical Fingerprints]]
#[test]
fn test_gate_4_repeated_runs_produce_deterministic_metrics_and_identical_fingerprints() {
    let corpus =
        BenchmarkCorpus::load_from_dir(Path::new(BENCHMARK_DIR)).expect("Corpus must load cleanly");

    let classifier = FnClassifier::new(
        "deterministic-evaluator",
        |case: &BenchmarkCase, content: &str| {
            // Deterministic heuristic
            if content.contains("execute(") && content.contains("+") {
                BenchmarkPrediction::vulnerable(
                    vec!["RULE-SQL-CONCAT".into()],
                    Some(EvidenceCertainty::StronglySupported),
                )
            } else if case.expected_vulnerable {
                BenchmarkPrediction::vulnerable(vec!["FALLBACK-PREDICT".into()], None)
            } else {
                BenchmarkPrediction::safe()
            }
        },
    );

    let runner = BenchmarkRunner::new(corpus);

    // Run 1 (deterministic mode with fixed timestamp and duration)
    let report1 = runner
        .run_deterministic(&classifier, "2026-10-25T12:00:00Z", 42)
        .expect("Run 1 failed");

    // Run 2 (deterministic mode with identical timestamp and duration)
    let report2 = runner
        .run_deterministic(&classifier, "2026-10-25T12:00:00Z", 42)
        .expect("Run 2 failed");

    // Assert identical metrics
    assert_eq!(report1.metrics, report2.metrics);
    assert_eq!(report1.metrics.overall.tp, report2.metrics.overall.tp);
    assert_eq!(report1.metrics.overall.fp, report2.metrics.overall.fp);
    assert_eq!(
        report1.metrics.overall.fn_count,
        report2.metrics.overall.fn_count
    );
    assert_eq!(report1.metrics.overall.tn, report2.metrics.overall.tn);

    // Assert identical reproducibility report fingerprint
    assert_eq!(
        report1.reproducibility.report_fingerprint, report2.reproducibility.report_fingerprint,
        "Report fingerprints across runs must match identically"
    );

    // Assert identical case evaluations
    assert_eq!(report1.case_evaluations, report2.case_evaluations);

    // Assert byte-for-byte serialization identity
    let json1 = serde_json::to_string_pretty(&report1).expect("json1 serialization");
    let json2 = serde_json::to_string_pretty(&report2).expect("json2 serialization");
    assert_eq!(
        json1, json2,
        "Serialized report JSON must be byte-for-byte identical"
    );
}

#[test]
fn test_red_green_falsification_metric_math_and_tamper_detection() {
    // 1. Red-Green: Falsify ConfusionMatrix formulas
    // Given TP=6, FP=2, FN=3, TN=9:
    let cm = ConfusionMatrix::new(6, 2, 3, 9);
    assert_eq!(cm.total(), 20);

    // Expected exact values:
    // Recall = 6 / (6 + 3) = 6/9 = 0.666666...
    let expected_recall = 6.0 / 9.0;
    assert!((cm.recall() - expected_recall).abs() < 1e-9);

    // Precision = 6 / (6 + 2) = 6/8 = 0.75
    let expected_precision = 6.0 / 8.0;
    assert!((cm.precision() - expected_precision).abs() < 1e-9);

    // FPR = 2 / (2 + 9) = 2/11 = 0.181818...
    let expected_fpr = 2.0 / 11.0;
    assert!((cm.fpr() - expected_fpr).abs() < 1e-9);

    // F1 = 2 * (0.75 * (6/9)) / (0.75 + (6/9)) = 2 * 0.5 / (17/12) = 1.0 / (1.416666...) = 12/17 ~= 0.70588235...
    let expected_f1 =
        2.0 * (expected_precision * expected_recall) / (expected_precision + expected_recall);
    assert!((cm.f1_score() - expected_f1).abs() < 1e-9);

    // 2. Red-Green: Duplicate Case ID detection
    let manifest_with_dupe = BenchmarkManifest {
        version: "1.0.0".into(),
        description: None,
        created_at: None,
        cases: vec![
            BenchmarkCase {
                case_id: "DUPE-01".into(),
                language: "python".into(),
                weakness: "CWE-89".into(),
                expected_vulnerable: true,
                expected_certainty_cap: None,
                expected_rule_ids: vec![],
                source_file: "cwe_89_sql/cwe_89_positive_concat.py".into(),
                source_sha256: "2113a2354c925411a946ffd1be75a773c9290f9205cc3308a6ba700c0883a4df"
                    .into(),
                scenario: BenchmarkScenario {
                    scenario_type: "offline".into(),
                    execution: "offline".into(),
                },
                provenance: BenchmarkProvenance {
                    class: "synthetic".into(),
                    source: "test".into(),
                },
            },
            BenchmarkCase {
                case_id: "DUPE-01".into(), // Duplicate!
                language: "python".into(),
                weakness: "CWE-89".into(),
                expected_vulnerable: false,
                expected_certainty_cap: None,
                expected_rule_ids: vec![],
                source_file: "cwe_89_sql/cwe_89_negative_parameterized.py".into(),
                source_sha256: "ee1c5758433cd6e3f58c6fe0dff0c8c5d3ef939ee6a4fa60734d03ad221e611a"
                    .into(),
                scenario: BenchmarkScenario {
                    scenario_type: "offline".into(),
                    execution: "offline".into(),
                },
                provenance: BenchmarkProvenance {
                    class: "synthetic".into(),
                    source: "test".into(),
                },
            },
        ],
    };

    let dupe_res =
        BenchmarkCorpus::from_manifest(manifest_with_dupe, Path::new(BENCHMARK_DIR).to_path_buf());
    match dupe_res {
        Err(BenchmarkError::DuplicateCaseId(id)) => assert_eq!(id, "DUPE-01"),
        other => panic!("Expected DuplicateCaseId error, got {:?}", other),
    }
}

/// Recursively copy a directory for isolation in tests.
fn copy_dir_all(src: &Path, dst: &Path) -> std::io::Result<()> {
    if !dst.exists() {
        fs::create_dir_all(dst)?;
    }
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let ty = entry.file_type()?;
        let dest_child = dst.join(entry.file_name());
        if ty.is_dir() {
            copy_dir_all(&entry.path(), &dest_child)?;
        } else {
            fs::copy(entry.path(), dest_child)?;
        }
    }
    Ok(())
}

// ============================================================================
// Test: Adversarial Benchmark Suite Stress-Testing & Mitigation Verification
// ============================================================================

#[test]
fn test_adversarial_suite_mitigation_evaluation() {
    let mut shannon_suite = AdversarialBenchmarkRunner::new(AdversarialFrameworkKind::Shannon);
    shannon_suite.add_vector(AdversarialAttackVector {
        vector_id: "shannon-cve-2024-5480".to_string(),
        framework: AdversarialFrameworkKind::Shannon,
        target_subsystem: "python_runtime".to_string(),
        payload_signature: "torch.load('exploit.pt')".to_string(),
        simulated_threat: "Arbitrary code execution via pickle payload".to_string(),
    });
    shannon_suite.add_vector(AdversarialAttackVector {
        vector_id: "shannon-http2-rapid-reset".to_string(),
        framework: AdversarialFrameworkKind::Shannon,
        target_subsystem: "nginx_gateway".to_string(),
        payload_signature: "RST_STREAM flood".to_string(),
        simulated_threat: "DDoS via stream cancellation".to_string(),
    });
    shannon_suite.add_vector(AdversarialAttackVector {
        vector_id: "shannon-zero-day-bypass".to_string(),
        framework: AdversarialFrameworkKind::Shannon,
        target_subsystem: "unknown_service".to_string(),
        payload_signature: "novel_polyglot_payload".to_string(),
        simulated_threat: "Uncategorized polyglot payload".to_string(),
    });

    // Defense evaluator: Virtual patches and rate limiters block known CVEs
    let report = shannon_suite.evaluate(|vec| {
        if vec.payload_signature.contains("torch.load") {
            (true, Some("virtual-patch:weights_only_guard".to_string()))
        } else if vec.payload_signature.contains("RST_STREAM") {
            (true, Some("waf:rate_limit_zone".to_string()))
        } else {
            (false, None)
        }
    });

    assert_eq!(report.framework, AdversarialFrameworkKind::Shannon);
    assert_eq!(report.total_vectors, 3);
    assert_eq!(report.blocked_count, 2);
    assert_eq!(report.bypassed_count, 1);
    assert!((report.mitigation_rate - 0.6666).abs() < 0.01);
    assert!(!report.report_id.is_empty());
}
