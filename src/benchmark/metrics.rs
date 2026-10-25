use crate::types::EvidenceCertainty;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Fundamental classification outcome for a benchmark case.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClassificationKind {
    TruePositive,
    FalsePositive,
    FalseNegative,
    TrueNegative,
}

impl ClassificationKind {
    /// Classify an evaluation based on ground truth and classifier prediction.
    pub fn classify(expected_vulnerable: bool, predicted_vulnerable: bool) -> Self {
        match (expected_vulnerable, predicted_vulnerable) {
            (true, true) => ClassificationKind::TruePositive,
            (false, true) => ClassificationKind::FalsePositive,
            (true, false) => ClassificationKind::FalseNegative,
            (false, false) => ClassificationKind::TrueNegative,
        }
    }

    /// Whether this classification is considered correct (either true positive or true negative).
    pub fn is_pass(&self) -> bool {
        matches!(
            self,
            ClassificationKind::TruePositive | ClassificationKind::TrueNegative
        )
    }

    /// Short label notation (TP, FP, FN, TN).
    pub fn as_str(&self) -> &'static str {
        match self {
            ClassificationKind::TruePositive => "TP",
            ClassificationKind::FalsePositive => "FP",
            ClassificationKind::FalseNegative => "FN",
            ClassificationKind::TrueNegative => "TN",
        }
    }
}

/// Standard 2x2 confusion matrix tallying TP, FP, FN, and TN.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ConfusionMatrix {
    pub tp: usize,
    pub fp: usize,
    #[serde(rename = "fn")]
    pub fn_count: usize,
    pub tn: usize,
}

impl ConfusionMatrix {
    /// Construct a confusion matrix with explicit counts.
    pub const fn new(tp: usize, fp: usize, fn_count: usize, tn: usize) -> Self {
        Self {
            tp,
            fp,
            fn_count,
            tn,
        }
    }

    /// Record a single case outcome.
    pub fn record(&mut self, expected_vulnerable: bool, predicted_vulnerable: bool) {
        match (expected_vulnerable, predicted_vulnerable) {
            (true, true) => self.tp += 1,
            (false, true) => self.fp += 1,
            (true, false) => self.fn_count += 1,
            (false, false) => self.tn += 1,
        }
    }

    /// Total number of evaluated cases.
    pub fn total(&self) -> usize {
        self.tp + self.fp + self.fn_count + self.tn
    }

    /// Recall = TP / (TP + FN). Returns 0.0 if denominator is 0.
    pub fn recall(&self) -> f64 {
        let denom = self.tp + self.fn_count;
        if denom == 0 {
            0.0
        } else {
            self.tp as f64 / denom as f64
        }
    }

    /// Precision = TP / (TP + FP). Returns 0.0 if denominator is 0.
    pub fn precision(&self) -> f64 {
        let denom = self.tp + self.fp;
        if denom == 0 {
            0.0
        } else {
            self.tp as f64 / denom as f64
        }
    }

    /// False Positive Rate (FPR) = FP / (FP + TN). Returns 0.0 if denominator is 0.
    pub fn fpr(&self) -> f64 {
        let denom = self.fp + self.tn;
        if denom == 0 {
            0.0
        } else {
            self.fp as f64 / denom as f64
        }
    }

    /// F1 Score = 2 * (Precision * Recall) / (Precision + Recall). Returns 0.0 if denominator is 0.
    pub fn f1_score(&self) -> f64 {
        let p = self.precision();
        let r = self.recall();
        let denom = p + r;
        if denom == 0.0 {
            0.0
        } else {
            2.0 * (p * r) / denom
        }
    }

    /// Accuracy = (TP + TN) / Total. Returns 0.0 if total is 0.
    pub fn accuracy(&self) -> f64 {
        let total = self.total();
        if total == 0 {
            0.0
        } else {
            (self.tp + self.tn) as f64 / total as f64
        }
    }
}

/// Evaluation outcome for a single benchmark test case.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CaseEvaluation {
    pub case_id: String,
    pub weakness: String,
    pub language: String,
    pub expected_vulnerable: bool,
    pub predicted_vulnerable: bool,
    pub classification: ClassificationKind,
    pub passed: bool,
    pub matched_rules: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub predicted_certainty: Option<EvidenceCertainty>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub details: Option<String>,
}

/// Aggregated benchmark metrics including overall and breakdowns by CWE and language.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BenchmarkMetrics {
    pub overall: ConfusionMatrix,
    pub by_cwe: BTreeMap<String, ConfusionMatrix>,
    pub by_language: BTreeMap<String, ConfusionMatrix>,
    pub total_cases: usize,
}

impl BenchmarkMetrics {
    /// Calculate metrics from a list of case evaluations.
    pub fn from_evaluations(evaluations: &[CaseEvaluation]) -> Self {
        let mut overall = ConfusionMatrix::default();
        let mut by_cwe: BTreeMap<String, ConfusionMatrix> = BTreeMap::new();
        let mut by_language: BTreeMap<String, ConfusionMatrix> = BTreeMap::new();

        for eval in evaluations {
            overall.record(eval.expected_vulnerable, eval.predicted_vulnerable);
            by_cwe
                .entry(eval.weakness.clone())
                .or_default()
                .record(eval.expected_vulnerable, eval.predicted_vulnerable);
            by_language
                .entry(eval.language.clone())
                .or_default()
                .record(eval.expected_vulnerable, eval.predicted_vulnerable);
        }

        Self {
            overall,
            by_cwe,
            by_language,
            total_cases: evaluations.len(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_confusion_matrix_perfect_score() {
        let matrix = ConfusionMatrix::new(10, 0, 0, 10);
        assert_eq!(matrix.total(), 20);
        assert!((matrix.recall() - 1.0).abs() < f64::EPSILON);
        assert!((matrix.precision() - 1.0).abs() < f64::EPSILON);
        assert!((matrix.fpr() - 0.0).abs() < f64::EPSILON);
        assert!((matrix.f1_score() - 1.0).abs() < f64::EPSILON);
        assert!((matrix.accuracy() - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_confusion_matrix_zero_denominators() {
        let matrix = ConfusionMatrix::default();
        assert_eq!(matrix.total(), 0);
        assert_eq!(matrix.recall(), 0.0);
        assert_eq!(matrix.precision(), 0.0);
        assert_eq!(matrix.fpr(), 0.0);
        assert_eq!(matrix.f1_score(), 0.0);
        assert_eq!(matrix.accuracy(), 0.0);
    }

    #[test]
    fn test_confusion_matrix_known_imperfect() {
        // TP = 8, FP = 2, FN = 2, TN = 8
        let matrix = ConfusionMatrix::new(8, 2, 2, 8);
        assert_eq!(matrix.total(), 20);
        assert!((matrix.recall() - 0.8).abs() < 1e-9); // 8 / (8 + 2) = 0.8
        assert!((matrix.precision() - 0.8).abs() < 1e-9); // 8 / (8 + 2) = 0.8
        assert!((matrix.fpr() - 0.2).abs() < 1e-9); // 2 / (2 + 8) = 0.2
        assert!((matrix.f1_score() - 0.8).abs() < 1e-9); // 2 * (0.8 * 0.8) / 1.6 = 0.8
        assert!((matrix.accuracy() - 0.8).abs() < 1e-9); // 16 / 20 = 0.8
    }

    #[test]
    fn test_metrics_breakdown() {
        let evals = vec![
            CaseEvaluation {
                case_id: "C1".into(),
                weakness: "CWE-89".into(),
                language: "python".into(),
                expected_vulnerable: true,
                predicted_vulnerable: true,
                classification: ClassificationKind::TruePositive,
                passed: true,
                matched_rules: vec!["R1".into()],
                predicted_certainty: None,
                details: None,
            },
            CaseEvaluation {
                case_id: "C2".into(),
                weakness: "CWE-89".into(),
                language: "python".into(),
                expected_vulnerable: false,
                predicted_vulnerable: false,
                classification: ClassificationKind::TrueNegative,
                passed: true,
                matched_rules: vec![],
                predicted_certainty: None,
                details: None,
            },
            CaseEvaluation {
                case_id: "C3".into(),
                weakness: "CWE-78".into(),
                language: "javascript".into(),
                expected_vulnerable: true,
                predicted_vulnerable: false,
                classification: ClassificationKind::FalseNegative,
                passed: false,
                matched_rules: vec![],
                predicted_certainty: None,
                details: None,
            },
        ];

        let metrics = BenchmarkMetrics::from_evaluations(&evals);
        assert_eq!(metrics.total_cases, 3);
        assert_eq!(metrics.overall.tp, 1);
        assert_eq!(metrics.overall.tn, 1);
        assert_eq!(metrics.overall.fn_count, 1);
        assert_eq!(metrics.overall.fp, 0);

        let cwe89 = metrics.by_cwe.get("CWE-89").expect("CWE-89 should exist");
        assert_eq!(cwe89.tp, 1);
        assert_eq!(cwe89.tn, 1);
        assert_eq!(cwe89.recall(), 1.0);

        let cwe78 = metrics.by_cwe.get("CWE-78").expect("CWE-78 should exist");
        assert_eq!(cwe78.fn_count, 1);
        assert_eq!(cwe78.recall(), 0.0);

        let py = metrics.by_language.get("python").expect("python exists");
        assert_eq!(py.tp, 1);
        assert_eq!(py.tn, 1);

        let js = metrics
            .by_language
            .get("javascript")
            .expect("javascript exists");
        assert_eq!(js.fn_count, 1);
    }
}
