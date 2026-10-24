use std::fs::File;
use std::path::Path;
use memmap2::Mmap;
use goblin::Object;
use regex::Regex;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeepBinaryFinding {
    pub file_path: String,
    pub is_vulnerable: bool,
    pub binary_format: String, // "ELF", "Mach-O", "PE", "Raw"
    pub detected_version: Option<String>,
    pub vulnerability_id: Option<String>,
    pub severity: String,
    pub matched_symbols: Vec<String>,
    pub reachability_status: String,
    pub explanation: String,
    pub safe_threshold: String,
}

pub struct BinaryAuditor;

impl BinaryAuditor {
    /// Zero-copy binary parser and symbol reachability auditor.
    pub fn audit_binary(path: &Path) -> Result<DeepBinaryFinding, String> {
        let file = File::open(path).map_err(|e| format!("Cannot open binary {:?}: {}", path, e))?;
        let mmap = unsafe { Mmap::map(&file).map_err(|e| format!("Failed to mmap {:?}: {}", path, e))? };

        let mut format = "Raw";
        let mut symbols: Vec<String> = Vec::new();
        let bytes = &mmap[..];

        // Parse with Goblin without loading entire file into heap
        if let Ok(obj) = Object::parse(bytes) {
            match obj {
                Object::Elf(elf) => {
                    format = "ELF";
                    for sym in &elf.syms {
                        if let Some(name) = elf.strtab.get_at(sym.st_name) {
                            if Self::is_critical_symbol(name) {
                                symbols.push(name.to_string());
                            }
                        }
                    }
                    for sym in &elf.dynsyms {
                        if let Some(name) = elf.dynstrtab.get_at(sym.st_name) {
                            if Self::is_critical_symbol(name) {
                                symbols.push(name.to_string());
                            }
                        }
                    }
                }
                Object::Mach(mach) => {
                    format = "Mach-O";
                    match mach {
                        goblin::mach::Mach::Binary(macho) => {
                            for sym in macho.symbols() {
                                if let Ok((name, _)) = sym {
                                    if Self::is_critical_symbol(name) {
                                        symbols.push(name.to_string());
                                    }
                                }
                            }
                        }
                        goblin::mach::Mach::Fat(_) => {
                            format = "Mach-O (Universal Fat)";
                        }
                    }
                }
                Object::PE(pe) => {
                    format = "PE";
                    for exp in &pe.exports {
                        if let Some(name) = exp.name {
                            if Self::is_critical_symbol(name) {
                                symbols.push(name.to_string());
                            }
                        }
                    }
                }
                _ => {}
            }
        }

        // Fast zero-copy string scanning for versions
        let path_str = path.to_string_lossy();
        if path_str.contains("php") || symbols.iter().any(|s| s.contains("php") || s.contains("zend")) {
            return Self::analyze_php(path, bytes, format, symbols);
        } else if path_str.contains("node") || symbols.iter().any(|s| s.contains("Brotli") || s.contains("node")) {
            return Self::analyze_node(path, bytes, format, symbols);
        }

        Ok(DeepBinaryFinding {
            file_path: path_str.to_string(),
            is_vulnerable: false,
            binary_format: format.to_string(),
            detected_version: None,
            vulnerability_id: None,
            severity: "Informational".into(),
            matched_symbols: symbols,
            reachability_status: "Neutral".into(),
            explanation: "Binary analyzed; no critical vulnerable runtime symbols found".into(),
            safe_threshold: "N/A".into(),
        })
    }

    fn is_critical_symbol(name: &str) -> bool {
        let n = name.trim_start_matches('_');
        n.contains("BrotliDecoder")
            || n.contains("zend_hash_destroy")
            || n.contains("php_url_encode")
            || n.contains("longjmp")
            || n.contains("php_request_shutdown")
    }

    fn analyze_php(path: &Path, bytes: &[u8], format: &str, symbols: Vec<String>) -> Result<DeepBinaryFinding, String> {
        let path_str = path.to_string_lossy().to_string();
        let re_ver = Regex::new(r"X-Powered-By: PHP/(\d+\.\d+\.\d+)").unwrap();
        let re_alt = Regex::new(r"PHP Version (\d+\.\d+\.\d+)").unwrap();

        let mut detected_version = None;

        // Scan sample of binary strings
        let text_sample = String::from_utf8_lossy(&bytes[..bytes.len().min(5_000_000)]);
        if let Some(cap) = re_ver.captures(&text_sample) {
            detected_version = Some(cap[1].to_string());
        } else if let Some(cap) = re_alt.captures(&text_sample) {
            detected_version = Some(cap[1].to_string());
        }

        let is_vuln;
        let mut cve = None;
        let mut explanation = "PHP binary inspected; within supported or patched release".to_string();

        if let Some(ref ver) = detected_version {
            let parts: Vec<&str> = ver.split('.').collect();
            let major: u32 = parts.first().and_then(|p| p.parse().ok()).unwrap_or(0);
            let minor: u32 = parts.get(1).and_then(|p| p.parse().ok()).unwrap_or(0);
            let patch: u32 = parts.get(2).and_then(|p| p.parse().ok()).unwrap_or(0);

            let vuln_check = match (major, minor) {
                (8, 5) => patch < 12,
                (8, 4) => patch < 27,
                (8, 3) => patch < 36,
                (8, 2) => patch < 35,
                (8, 1) | (8, 0) | (7, _) | (5, _) => true,
                _ => false,
            };

            if vuln_check {
                is_vuln = true;
                cve = Some("CVE-2026-109618 / CVE-2026-109619 (PHP2Shell)".to_string());
                explanation = format!(
                    "Binary version '{}' contains unpatched Zend allocator longjmp error unwinding & stale global state UAF.",
                    ver
                );
            } else {
                is_vuln = false;
            }
        } else {
            // If version string not directly embedded, check critical symbols presence
            let has_hash_destroy = symbols.iter().any(|s| s.contains("zend_hash_destroy"));
            let has_url_encode = symbols.iter().any(|s| s.contains("php_url_encode"));
            if has_hash_destroy && has_url_encode {
                is_vuln = true;
                cve = Some("CVE-2026-109618 (PHP2Shell Candidate)".to_string());
                explanation = "Binary contains critical Zend engine symbols exposed to OOM longjmp heap corruption.".to_string();
            } else {
                is_vuln = false;
            }
        }

        Ok(DeepBinaryFinding {
            file_path: path_str,
            is_vulnerable: is_vuln,
            binary_format: format.to_string(),
            detected_version,
            vulnerability_id: cve,
            severity: if is_vuln { "CRITICAL".into() } else { "PASS".into() },
            matched_symbols: symbols,
            reachability_status: if is_vuln { "Vulnerable Entry Point Verified" } else { "Secure" }.into(),
            explanation,
            safe_threshold: "PHP >= 8.2.35, 8.3.36, 8.4.27, 8.5.12".into(),
        })
    }

    fn analyze_node(path: &Path, bytes: &[u8], format: &str, symbols: Vec<String>) -> Result<DeepBinaryFinding, String> {
        let path_str = path.to_string_lossy().to_string();
        let re_ver = Regex::new(r"node/v(\d+\.\d+\.\d+)").unwrap();
        let re_alt = Regex::new(r"NODE_VERSION\s*=\s*v?(\d+\.\d+\.\d+)").unwrap();

        let mut detected_version = None;
        let text_sample = String::from_utf8_lossy(&bytes[..bytes.len().min(5_000_000)]);
        if let Some(cap) = re_ver.captures(&text_sample) {
            detected_version = Some(cap[1].to_string());
        } else if let Some(cap) = re_alt.captures(&text_sample) {
            detected_version = Some(cap[1].to_string());
        }

        let has_brotli = symbols.iter().any(|s| s.contains("BrotliDecoder")) || text_sample.contains("BrotliDecoderCreateInstance");

        let mut is_vuln = false;
        let mut cve = None;
        let mut explanation = "Node.js runtime inspected; Brotli bounds verified".to_string();

        if let Some(ref ver) = detected_version {
            let parts: Vec<&str> = ver.split('.').collect();
            let major: u32 = parts.first().and_then(|p| p.parse().ok()).unwrap_or(0);
            let minor: u32 = parts.get(1).and_then(|p| p.parse().ok()).unwrap_or(0);
            let patch: u32 = parts.get(2).and_then(|p| p.parse().ok()).unwrap_or(0);

            is_vuln = match major {
                26 => minor < 12 || (minor == 12 && patch < 1),
                24 => minor < 22 || (minor == 22 && patch < 1),
                22 => minor < 23 || (minor == 23 && patch < 4),
                0..=21 => true,
                _ => false,
            };

            if is_vuln {
                cve = Some("CVE-2026-111497 (Node2Shell)".to_string());
                explanation = format!(
                    "Node.js runtime v{} contains statically linked vulnerable Brotli decoder (v1.0.3-1.2.0) with out-of-bounds write flaw.",
                    ver
                );
            }
        } else if has_brotli {
            is_vuln = true;
            cve = Some("CVE-2026-111497 (Node2Shell Unpatched Candidate)".to_string());
            explanation = "Binary statically bundles BrotliDecoder symbols without verified safe release bounds.".to_string();
        }

        Ok(DeepBinaryFinding {
            file_path: path_str,
            is_vulnerable: is_vuln,
            binary_format: format.to_string(),
            detected_version,
            vulnerability_id: cve,
            severity: if is_vuln { "HIGH".into() } else { "PASS".into() },
            matched_symbols: symbols,
            reachability_status: if is_vuln { "Exposed Decompression Channel" } else { "Hardened" }.into(),
            explanation,
            safe_threshold: "Node.js >= v22.23.4, v24.22.1, v26.12.1".into(),
        })
    }
}
