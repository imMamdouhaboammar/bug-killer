use crate::types::EvidenceCertainty;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::path::{Path, PathBuf};

/// Error types encountered during benchmark dataset loading, verification, or execution.
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum BenchmarkError {
    #[error("IO error: {0}")]
    Io(String),

    #[error("Failed to parse benchmark manifest: {0}")]
    ManifestParse(String),

    #[error("Duplicate case ID: {0}")]
    DuplicateCaseId(String),

    #[error("Fixture file not found for case {case_id}: {path}")]
    FileNotFound { case_id: String, path: String },

    #[error("SHA-256 mismatch for case {case_id}: expected {expected}, got {actual}")]
    Sha256Mismatch {
        case_id: String,
        expected: String,
        actual: String,
    },

    #[error("Dataset fingerprint mismatch: expected {expected}, got {actual}")]
    FingerprintMismatch { expected: String, actual: String },

    #[error("Classifier execution error: {0}")]
    Execution(String),
}

/// Execution scenario metadata for a benchmark test case.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BenchmarkScenario {
    #[serde(rename = "type")]
    pub scenario_type: String,
    pub execution: String,
}

/// Provenance metadata indicating origin and synthesis method.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BenchmarkProvenance {
    pub class: String,
    pub source: String,
}

/// A single labelled security benchmark test case.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BenchmarkCase {
    pub case_id: String,
    pub language: String,
    pub weakness: String,
    pub expected_vulnerable: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_certainty_cap: Option<EvidenceCertainty>,
    pub expected_rule_ids: Vec<String>,
    pub source_file: String,
    pub source_sha256: String,
    pub scenario: BenchmarkScenario,
    pub provenance: BenchmarkProvenance,
}

impl BenchmarkCase {
    /// Computes the SHA-256 hex digest of the fixture file on disk.
    pub fn compute_fixture_sha256(&self, base_dir: &Path) -> Result<String, BenchmarkError> {
        let fixture_path = base_dir.join(&self.source_file);
        compute_file_sha256(&fixture_path).map_err(|err| match err {
            BenchmarkError::Io(_) => BenchmarkError::FileNotFound {
                case_id: self.case_id.clone(),
                path: fixture_path.display().to_string(),
            },
            other => other,
        })
    }

    /// Verifies that the fixture file exists and its content matches the expected SHA-256.
    pub fn verify_file(&self, base_dir: &Path) -> Result<(), BenchmarkError> {
        let actual = self.compute_fixture_sha256(base_dir)?;
        if !actual.eq_ignore_ascii_case(&self.source_sha256) {
            return Err(BenchmarkError::Sha256Mismatch {
                case_id: self.case_id.clone(),
                expected: self.source_sha256.clone(),
                actual,
            });
        }
        Ok(())
    }
}

/// Manifest structure serializable to/from `benchmark_manifest.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BenchmarkManifest {
    pub version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
    pub cases: Vec<BenchmarkCase>,
}

/// Fully loaded and verified security benchmark dataset.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchmarkCorpus {
    pub manifest_version: String,
    pub root_dir: PathBuf,
    pub cases: Vec<BenchmarkCase>,
    pub dataset_fingerprint: String,
}

impl BenchmarkCorpus {
    /// Loads the benchmark corpus from a directory containing `benchmark_manifest.json`.
    pub fn load_from_dir(dir: impl AsRef<Path>) -> Result<Self, BenchmarkError> {
        let manifest_path = dir.as_ref().join("benchmark_manifest.json");
        Self::load_from_manifest(&manifest_path)
    }

    /// Loads the benchmark corpus from an explicit manifest file path.
    pub fn load_from_manifest(manifest_path: impl AsRef<Path>) -> Result<Self, BenchmarkError> {
        let manifest_path = manifest_path.as_ref();
        let root_dir = manifest_path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .to_path_buf();

        let raw = std::fs::read_to_string(manifest_path)
            .map_err(|e| BenchmarkError::Io(format!("{}: {}", manifest_path.display(), e)))?;

        let manifest: BenchmarkManifest = serde_json::from_str(&raw).map_err(|e| {
            BenchmarkError::ManifestParse(format!("{}: {}", manifest_path.display(), e))
        })?;

        Self::from_manifest(manifest, root_dir)
    }

    /// Creates and verifies a corpus from a parsed manifest and root directory.
    pub fn from_manifest(
        manifest: BenchmarkManifest,
        root_dir: PathBuf,
    ) -> Result<Self, BenchmarkError> {
        // Check for duplicate case IDs
        let mut seen = HashSet::new();
        for case in &manifest.cases {
            if !seen.insert(&case.case_id) {
                return Err(BenchmarkError::DuplicateCaseId(case.case_id.clone()));
            }
        }

        // Verify all fixture files
        for case in &manifest.cases {
            case.verify_file(&root_dir)?;
        }

        let fingerprint =
            Self::compute_dataset_fingerprint(&manifest.version, &manifest.cases, &root_dir)?;

        Ok(Self {
            manifest_version: manifest.version,
            root_dir,
            cases: manifest.cases,
            dataset_fingerprint: fingerprint,
        })
    }

    /// Computes a deterministic SHA-256 fingerprint over the entire dataset.
    /// This hashes the manifest metadata, case definitions, and exact fixture contents.
    pub fn compute_dataset_fingerprint(
        manifest_version: &str,
        cases: &[BenchmarkCase],
        root_dir: &Path,
    ) -> Result<String, BenchmarkError> {
        let mut sorted_cases = cases.to_vec();
        sorted_cases.sort_by(|a, b| a.case_id.cmp(&b.case_id));

        let mut hasher = Sha256::new();
        hasher.update(b"BUG_KILLER_BENCHMARK_CORPUS_V1\n");
        hasher.update(manifest_version.as_bytes());
        hasher.update(b"\n");

        for case in sorted_cases {
            hasher.update(case.case_id.as_bytes());
            hasher.update(b"|");
            hasher.update(case.language.as_bytes());
            hasher.update(b"|");
            hasher.update(case.weakness.as_bytes());
            hasher.update(b"|");
            hasher.update(if case.expected_vulnerable {
                b"1|"
            } else {
                b"0|"
            });
            if let Some(cap) = case.expected_certainty_cap {
                hasher.update(cap.as_str().as_bytes());
            }
            hasher.update(b"|");
            let mut sorted_rules = case.expected_rule_ids.clone();
            sorted_rules.sort();
            for r in sorted_rules {
                hasher.update(r.as_bytes());
                hasher.update(b",");
            }
            hasher.update(b"|");
            hasher.update(case.source_file.as_bytes());
            hasher.update(b"|");
            hasher.update(case.source_sha256.as_bytes());
            hasher.update(b"|");
            hasher.update(case.scenario.scenario_type.as_bytes());
            hasher.update(b"|");
            hasher.update(case.scenario.execution.as_bytes());
            hasher.update(b"|");
            hasher.update(case.provenance.class.as_bytes());
            hasher.update(b"|");
            hasher.update(case.provenance.source.as_bytes());
            hasher.update(b"\n");

            // Hash the actual fixture file bytes on disk
            let fixture_path = root_dir.join(&case.source_file);
            let bytes = std::fs::read(&fixture_path).map_err(|_| BenchmarkError::FileNotFound {
                case_id: case.case_id.clone(),
                path: fixture_path.display().to_string(),
            })?;
            hasher.update(&bytes);
            hasher.update(b"\n---CASE_BOUNDARY---\n");
        }

        let digest = hasher.finalize();
        Ok(crate::to_hex(digest))
    }

    /// Verifies the integrity of all cases and the dataset fingerprint.
    pub fn verify(&self) -> Result<(), BenchmarkError> {
        let mut seen = HashSet::new();
        for case in &self.cases {
            if !seen.insert(&case.case_id) {
                return Err(BenchmarkError::DuplicateCaseId(case.case_id.clone()));
            }
            case.verify_file(&self.root_dir)?;
        }

        let computed =
            Self::compute_dataset_fingerprint(&self.manifest_version, &self.cases, &self.root_dir)?;

        if computed != self.dataset_fingerprint {
            return Err(BenchmarkError::FingerprintMismatch {
                expected: self.dataset_fingerprint.clone(),
                actual: computed,
            });
        }

        Ok(())
    }

    /// Validates that the loaded dataset matches an externally asserted fingerprint.
    pub fn verify_against_fingerprint(&self, expected: &str) -> Result<(), BenchmarkError> {
        self.verify()?;
        if self.dataset_fingerprint != expected {
            return Err(BenchmarkError::FingerprintMismatch {
                expected: expected.to_string(),
                actual: self.dataset_fingerprint.clone(),
            });
        }
        Ok(())
    }

    /// Look up a case by ID.
    pub fn get_case(&self, case_id: &str) -> Option<&BenchmarkCase> {
        self.cases.iter().find(|c| c.case_id == case_id)
    }

    /// Read the string contents of a fixture file.
    pub fn read_fixture(&self, case: &BenchmarkCase) -> Result<String, BenchmarkError> {
        let path = self.root_dir.join(&case.source_file);
        std::fs::read_to_string(&path)
            .map_err(|e| BenchmarkError::Io(format!("{}: {}", path.display(), e)))
    }
}

/// Helper function to compute the SHA-256 hex string of a file on disk.
pub fn compute_file_sha256(path: &Path) -> Result<String, BenchmarkError> {
    let bytes = std::fs::read(path)
        .map_err(|e| BenchmarkError::Io(format!("{}: {}", path.display(), e)))?;
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    Ok(crate::to_hex(hasher.finalize()))
}
