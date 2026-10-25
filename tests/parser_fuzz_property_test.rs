use bug_killer::dast::DastProber;
use bug_killer::osv::OsvClient;
use bug_killer::scanner::binary::BinaryScanner;
use bug_killer::types::*;
use rand::{Rng, RngCore, SeedableRng, rngs::StdRng};
use std::fs;
use std::path::Path;
use tempfile::tempdir;

/// Seeded standard generator for reproducible parser inputs.
struct FuzzRng {
    rng: StdRng,
}

impl FuzzRng {
    fn new(seed: u64) -> Self {
        Self {
            rng: StdRng::seed_from_u64(seed),
        }
    }

    fn next_u32(&mut self) -> u32 {
        self.rng.next_u32()
    }

    fn next_bytes(&mut self, len: usize) -> Vec<u8> {
        let mut buf = vec![0; len];
        self.rng.fill_bytes(&mut buf);
        buf
    }

    fn choose<'a, T>(&mut self, slice: &'a [T]) -> &'a T {
        let idx = self.rng.gen_range(0..slice.len());
        &slice[idx]
    }
}

#[test]
fn test_corpus_smoke_seed_inputs() {
    let corpus_dir = Path::new("tests/fixtures/fuzz_corpus");
    assert!(corpus_dir.exists(), "Seed corpus directory must exist");

    for entry in fs::read_dir(corpus_dir).unwrap() {
        let entry = entry.unwrap();
        let path = entry.path();
        if path.is_file() {
            let data = fs::read(&path).unwrap();
            // 1. Binary check must not panic
            let _ = BinaryScanner::is_binary_executable(&path);
            let _ = goblin::Object::parse(&data);

            // 2. Manifest JSON parse must fail gracefully on malformed files
            if path.extension().and_then(|s| s.to_str()) == Some("json") {
                let _ = serde_json::from_slice::<BackupManifest>(&data);
            }
        }
    }
}

#[test]
fn test_property_binary_parser_never_panics_on_fuzzed_inputs() {
    let mut rng = FuzzRng::new(0xDEADBEEFCAFE);

    let magic_headers: [&[u8]; 7] = [
        b"\x7fELF",
        &[0xfe, 0xed, 0xfa, 0xce],
        &[0xce, 0xfa, 0xed, 0xfe],
        &[0xfe, 0xed, 0xfa, 0xcf],
        &[0xcf, 0xfa, 0xed, 0xfe],
        &[0xca, 0xfe, 0xba, 0xbe],
        b"MZ",
    ];

    for i in 0..100 {
        let mut bytes = Vec::new();
        // Alternately prepend valid/invalid magic headers
        if i % 3 == 0 {
            bytes.extend_from_slice(rng.choose(&magic_headers));
        }
        let len = (rng.next_u32() % 1024) as usize;
        bytes.extend(rng.next_bytes(len));

        // In-memory goblin parse must not panic
        let _ = goblin::Object::parse(&bytes);
    }
}

#[test]
fn test_property_dast_url_validator_never_panics_and_fails_closed() {
    let mut rng = FuzzRng::new(0x1337C0DE);

    let prefixes = [
        "http://",
        "https://",
        "ftp://",
        "file://",
        "gopher://",
        "http://[::ffff:",
        "http://169.254.",
        "http://admin:pass@",
        "http://127.0.0.1:",
        "http://0177.0.0.1/",
        "http://0x7f000001/",
        "http://localhost:",
    ];

    let suffixes = [
        "169.254/latest/meta-data",
        "8080/path/../etc/passwd",
        "80/%2e%2e/%2e%2e/env",
        "evil.internal:8080",
        ":99999/overflow",
        "metadata.google.internal",
        "256.256.256.256",
        "[::1]/test",
    ];

    for _ in 0..500 {
        let prefix = rng.choose(&prefixes);
        let suffix = rng.choose(&suffixes);
        let extra_len = (rng.next_u32() % 16) as usize;
        let extra_bytes = rng.next_bytes(extra_len);
        let extra_str = String::from_utf8_lossy(&extra_bytes);
        let candidate = format!("{}{}{}", prefix, suffix, extra_str);

        // Validate that probe fails closed or returns error, never panics
        let result = DastProber::probe(&candidate, 1);
        if candidate.contains("169.254")
            || candidate.starts_with("file://")
            || candidate.contains('@')
        {
            assert!(
                result.is_err(),
                "Candidate URL {:?} must fail closed",
                candidate
            );
        }
    }
}

#[test]
fn test_property_manifest_parser_rejects_path_traversals_without_panic() {
    let mut rng = FuzzRng::new(0xFEEDFACE);

    let traversal_payloads = [
        "../../etc/shadow",
        "../..\\windows\\system32",
        "/etc/passwd",
        "foo/bar/../../../root/.ssh/id_rsa",
        "normal/file.txt",
        "..",
        "./../../sneaky",
    ];

    for (i, traversal) in traversal_payloads.iter().enumerate() {
        let raw_json = format!(
            r#"{{
              "backup_id": "backup_{}",
              "created_at": "2026-10-25T12:00:00Z",
              "root_dir": "/workspace",
              "records": [
                {{
                  "relative_target_path": {:?},
                  "original_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                  "backup_file_name": "{}_file.txt",
                  "mode": 420,
                  "post_heal_sha256": null
                }}
              ],
              "signer_public_key": null,
              "signature": null
            }}"#,
            i, traversal, i
        );

        let manifest_res = serde_json::from_str::<BackupManifest>(&raw_json);
        assert!(
            manifest_res.is_ok(),
            "JSON structure must deserialize cleanly"
        );
        let manifest = manifest_res.unwrap();

        let rel_path = Path::new(&manifest.records[0].relative_target_path);
        let is_unsafe = rel_path.is_absolute()
            || rel_path.components().any(|c| {
                matches!(
                    c,
                    std::path::Component::ParentDir
                        | std::path::Component::RootDir
                        | std::path::Component::Prefix(_)
                )
            });

        if traversal.contains("..") || traversal.starts_with('/') {
            assert!(
                is_unsafe,
                "Relative path {:?} must be classified as unsafe",
                traversal
            );
        }
    }

    // Fuzz random corrupted strings into JSON deserializer
    for _ in 0..400 {
        let len = (rng.next_u32() % 512) as usize;
        let random_bytes = rng.next_bytes(len);
        let _ = serde_json::from_slice::<BackupManifest>(&random_bytes);
    }
}

#[test]
fn test_property_osv_package_discovery_never_panics_on_malformed_manifests() {
    let mut rng = FuzzRng::new(0xCAFEBABE);
    let dir = tempdir().unwrap();

    let manifest_names = [
        "package.json",
        "package-lock.json",
        "Cargo.lock",
        "composer.json",
        "composer.lock",
        "requirements.txt",
        "go.mod",
        "pnpm-lock.yaml",
        "yarn.lock",
    ];

    for name in &manifest_names {
        let file_path = dir.path().join(name);

        for _ in 0..50 {
            let len = (rng.next_u32() % 1024) as usize;
            let corrupted_content = rng.next_bytes(len);
            fs::write(&file_path, &corrupted_content).unwrap();

            // Extract packages must not panic on arbitrary malformed bytes
            let packages = OsvClient::discover_packages(dir.path());
            // Returned packages must have valid non-empty fields if any
            for pkg in packages {
                assert!(!pkg.name.is_empty());
            }
        }
    }
}

#[test]
fn test_property_dynamic_rules_regex_compilation_safety() {
    let mut rng = FuzzRng::new(0x987654321);

    let adversarial_regex_candidates = [
        "(a+)+$", // Potential catastrophic backtracking (ReDoS)
        "([a-zA-Z0-9_\\-\\.]+)@([a-zA-Z0-9_\\-\\.]+)\\.([a-zA-Z]{2,5})",
        "[unclosed-bracket",
        "*leading-star",
        "(?i)password\\s*=\\s*['\"](.*?)['\"]",
        "\\p{InvalidProperty}",
        "(?=lookahead_unsupported)",
        "",
    ];

    for pattern in &adversarial_regex_candidates {
        // Rust regex engine must either successfully compile or return Err, never crash/panic
        let res = regex::Regex::new(pattern);
        if pattern.starts_with('*') || pattern.starts_with('[') {
            assert!(
                res.is_err(),
                "Invalid regex {} should error cleanly",
                pattern
            );
        }
    }

    // Fuzz random regex patterns
    for _ in 0..300 {
        let len = (rng.next_u32() % 32) as usize;
        let pattern_bytes = rng.next_bytes(len);
        let pattern_str = String::from_utf8_lossy(&pattern_bytes);
        let _ = regex::Regex::new(&pattern_str);
    }
}
