//! Security Benchmark Harness and Labelled Fixture Corpus Engine.
//!
//! Provides dataset schema, SHA-256 fingerprinting for tamper detection,
//! confusion matrix metrics calculation (TP, FP, FN, TN, precision, recall, FPR, F1),
//! per-CWE and per-language breakdowns, and deterministic execution runners.

pub mod corpus;
pub mod metrics;
pub mod runner;

pub use corpus::{
    BenchmarkCase, BenchmarkCorpus, BenchmarkError, BenchmarkManifest, BenchmarkProvenance,
    BenchmarkScenario, compute_file_sha256,
};
pub use metrics::{BenchmarkMetrics, CaseEvaluation, ClassificationKind, ConfusionMatrix};
pub use runner::{
    AdversarialAttackVector, AdversarialBenchmarkReport, AdversarialBenchmarkRunner,
    AdversarialEvaluationResult, AdversarialFrameworkKind, BenchmarkClassifier,
    BenchmarkPrediction, BenchmarkReport, BenchmarkRunner, FnClassifier, ReproducibilityManifest,
};
