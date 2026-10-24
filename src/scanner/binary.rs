use crate::types::*;
use goblin::Object;
use memmap2::MmapOptions;
use sha2::{Digest, Sha256};
use std::fs::File;
use std::path::Path;

pub struct BinaryScanner;

impl BinaryScanner {
    /// Maximum binary file size allowed for bounded zero-copy inspection (128 MB).
    pub const MAX_INSPECTION_SIZE: u64 = 128 * 1024 * 1024;

    /// Checks whether a file possesses magic headers for ELF, Mach-O, or PE executable formats.
    pub fn is_binary_executable(path: &Path) -> bool {
        let mut file = match File::open(path) {
            Ok(f) => f,
            Err(_) => return false,
        };

        let mut magic = [0u8; 16];
        use std::io::Read;
        if file.read(&mut magic).unwrap_or(0) < 4 {
            return false;
        }

        // ELF
        if &magic[0..4] == b"\x7fELF" {
            return true;
        }

        // Mach-O (32-bit & 64-bit, little and big endian, or fat binary)
        let m4 = [magic[0], magic[1], magic[2], magic[3]];
        if m4 == [0xfe, 0xed, 0xfa, 0xce]
            || m4 == [0xce, 0xfa, 0xed, 0xfe]
            || m4 == [0xfe, 0xed, 0xfa, 0xcf]
            || m4 == [0xcf, 0xfa, 0xed, 0xfe]
            || m4 == [0xca, 0xfe, 0xba, 0xbe]
        {
            return true;
        }

        // PE / COFF
        if &magic[0..2] == b"MZ" {
            return true;
        }

        false
    }

    /// Safely scans a binary executable for embedded symbols and libraries using zero-copy memory mapping.
    pub fn scan_binary(path: &Path) -> Result<Vec<Finding>, String> {
        let mut findings = Vec::new();

        let file = File::open(path)
            .map_err(|e| format!("Cannot open binary {}: {}", path.display(), e))?;
        let metadata = file
            .metadata()
            .map_err(|e| format!("Cannot read metadata for {}: {}", path.display(), e))?;

        if metadata.len() == 0 {
            return Ok(findings);
        }

        if metadata.len() > Self::MAX_INSPECTION_SIZE {
            return Err(format!(
                "Binary {} ({} bytes) exceeds safety inspection limit of {} bytes",
                path.display(),
                metadata.len(),
                Self::MAX_INSPECTION_SIZE
            ));
        }

        let mmap = unsafe {
            MmapOptions::new()
                .map(&file)
                .map_err(|e| format!("Failed to memory map {}: {}", path.display(), e))?
        };

        let parsed = match Object::parse(&mmap) {
            Ok(obj) => obj,
            Err(e) => {
                return Err(format!(
                    "Malformed or truncated binary at {}: {}",
                    path.display(),
                    e
                ));
            }
        };

        let file_digest = format!("{:x}", Sha256::digest(path.to_string_lossy().as_bytes()));
        let mut detected_brotli = false;
        let mut detected_php = false;
        let mut arch_info = "Unknown".to_string();

        match parsed {
            Object::Elf(elf) => {
                arch_info = format!("ELF e_machine={}", elf.header.e_machine);
                // Inspect dynamic symbols
                for sym in elf.dynsyms.iter() {
                    if let Some(name) = elf.dynstrtab.get_at(sym.st_name) {
                        if name.contains("BrotliDecoderCreateInstance")
                            || name.contains("BrotliDecoderDecompress")
                        {
                            detected_brotli = true;
                        }
                        if name.contains("php_execute_script")
                            || name.contains("zend_compile_file")
                            || name.contains("php_request_startup")
                        {
                            detected_php = true;
                        }
                    }
                }
                // Inspect static symbols if present
                for sym in elf.syms.iter() {
                    if let Some(name) = elf.strtab.get_at(sym.st_name) {
                        if name.contains("BrotliDecoderCreateInstance")
                            || name.contains("BrotliDecoderDecompress")
                        {
                            detected_brotli = true;
                        }
                        if name.contains("php_execute_script")
                            || name.contains("zend_compile_file")
                            || name.contains("php_request_startup")
                        {
                            detected_php = true;
                        }
                    }
                }
            }
            Object::Mach(mach) => match mach {
                goblin::mach::Mach::Binary(macho) => {
                    arch_info = format!("Mach-O cputype={:?}", macho.header.cputype);
                    for (name, _) in macho.symbols().flatten() {
                        if name.contains("BrotliDecoderCreateInstance")
                            || name.contains("BrotliDecoderDecompress")
                        {
                            detected_brotli = true;
                        }
                        if name.contains("php_execute_script")
                            || name.contains("zend_compile_file")
                            || name.contains("php_request_startup")
                        {
                            detected_php = true;
                        }
                    }
                    if let Ok(exports) = macho.exports() {
                        for exp in exports {
                            if exp.name.contains("BrotliDecoderCreateInstance")
                                || exp.name.contains("BrotliDecoderDecompress")
                            {
                                detected_brotli = true;
                            }
                            if exp.name.contains("php_execute_script")
                                || exp.name.contains("zend_compile_file")
                            {
                                detected_php = true;
                            }
                        }
                    }
                }
                goblin::mach::Mach::Fat(fat) => {
                    arch_info = format!("Mach-O Fat ({} arches)", fat.narches);
                    for arch in fat.iter_arches().flatten() {
                        if let Ok(macho) = goblin::mach::MachO::parse(&mmap, arch.offset as usize) {
                            for (name, _) in macho.symbols().flatten() {
                                if name.contains("BrotliDecoderCreateInstance")
                                    || name.contains("BrotliDecoderDecompress")
                                {
                                    detected_brotli = true;
                                }
                                if name.contains("php_execute_script")
                                    || name.contains("zend_compile_file")
                                {
                                    detected_php = true;
                                }
                            }
                        }
                    }
                }
            },
            Object::PE(pe) => {
                arch_info = format!("PE machine={:#x}", pe.header.coff_header.machine);
                for export in &pe.exports {
                    if let Some(name) = export.name {
                        if name.contains("BrotliDecoderCreateInstance")
                            || name.contains("BrotliDecoderDecompress")
                        {
                            detected_brotli = true;
                        }
                        if name.contains("php_execute_script") || name.contains("zend_compile_file")
                        {
                            detected_php = true;
                        }
                    }
                }
                for import in &pe.imports {
                    if import.name.contains("BrotliDecoderCreateInstance")
                        || import.dll.to_lowercase().contains("brotli")
                    {
                        detected_brotli = true;
                    }
                    if import.name.contains("php_execute_script")
                        || import.dll.to_lowercase().contains("php")
                    {
                        detected_php = true;
                    }
                }
            }
            _ => {}
        }

        if detected_brotli {
            let mut finding = Finding::new(
                format!("binary-embedded-brotli-{}", &file_digest[..8]),
                CveId::Node2ShellBrotli("CVE-2026-111497".to_string()),
                Severity::Critical,
                TargetKind::BinaryExecutable,
                Some(path.to_path_buf()),
                None,
                format!(
                    "Binary contains embedded/exported Brotli symbols ({})",
                    arch_info
                ),
                "Recompile binary against patched Brotli >= 1.2.0".to_string(),
                format!(
                    "Binary executable at {} contains embedded Brotli decompression symbols vulnerable to heap out-of-bounds execution (CVE-2026-111497).",
                    path.display()
                ),
                "Update vendor toolchain or re-link binary against patched libbrotli >= 1.2.0."
                    .to_string(),
            );
            finding.detector_id = "binary-goblin-scanner".to_string();
            finding.category = "embedded-vulnerable-library".to_string();
            finding.affectedness = Affectedness::ConfirmedAffected;
            finding.reachability = Reachability::PotentiallyReachable;
            finding.confidence = Confidence::High;
            finding.supported_checks = vec!["binary_symbol_inspection".into()];
            finding.installed_build = Some(arch_info.clone());
            finding.compute_dedupe_fingerprint();
            findings.push(finding);
        }

        if detected_php {
            let mut finding = Finding::new(
                format!("binary-embedded-php-{}", &file_digest[..8]),
                CveId::Php2ShellOom("CVE-2026-109618".to_string()),
                Severity::Critical,
                TargetKind::BinaryExecutable,
                Some(path.to_path_buf()),
                None,
                format!("Binary contains embedded PHP runtime symbols ({})", arch_info),
                "Recompile or replace binary with patched PHP core".to_string(),
                format!("Binary executable at {} contains embedded PHP runtime symbols subject to out-of-bounds execution (CVE-2026-109618 / CVE-2026-109619).", path.display()),
                "Upgrade embedded PHP interpreter to patched release or deploy runtime virtual patch.".to_string(),
            );
            finding.detector_id = "binary-goblin-scanner".to_string();
            finding.category = "embedded-vulnerable-library".to_string();
            finding.affectedness = Affectedness::ConfirmedAffected;
            finding.reachability = Reachability::PotentiallyReachable;
            finding.confidence = Confidence::High;
            finding.supported_checks = vec!["binary_symbol_inspection".into()];
            finding.installed_build = Some(arch_info);
            finding.compute_dedupe_fingerprint();
            findings.push(finding);
        }

        Ok(findings)
    }
}
