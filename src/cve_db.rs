use crate::types::*;

pub struct CveDatabase;

impl CveDatabase {
    /// Determines whether a given PHP version string is vulnerable to PHP2Shell.
    ///
    /// Fixed versions:
    /// - 8.2 >= 8.2.35
    /// - 8.3 >= 8.3.36
    /// - 8.4 >= 8.4.27
    /// - 8.5 >= 8.5.12
    ///
    /// Any version <= 8.1 is completely EOL and unpatched.
    pub fn check_php_version(major: u32, minor: u32, patch: u32) -> Option<(CveId, Severity, &'static str)> {
        match (major, minor) {
            (8, 5) => {
                if patch < 12 {
                    Some((
                        CveId::Php2ShellOom("CVE-2026-109618".into()),
                        Severity::Critical,
                        "PHP 8.5.12+",
                    ))
                } else {
                    None
                }
            }
            (8, 4) => {
                if patch < 27 {
                    Some((
                        CveId::Php2ShellOom("CVE-2026-109618".into()),
                        Severity::Critical,
                        "PHP 8.4.27+",
                    ))
                } else {
                    None
                }
            }
            (8, 3) => {
                if patch < 36 {
                    Some((
                        CveId::Php2ShellOom("CVE-2026-109618".into()),
                        Severity::Critical,
                        "PHP 8.3.36+",
                    ))
                } else {
                    None
                }
            }
            (8, 2) => {
                if patch < 35 {
                    Some((
                        CveId::Php2ShellOom("CVE-2026-109618".into()),
                        Severity::Critical,
                        "PHP 8.2.35+",
                    ))
                } else {
                    None
                }
            }
            // EOL branches: 8.1, 8.0, 7.x, 5.x
            (8, 1) | (8, 0) | (7, _) | (5, _) => Some((
                CveId::Php2ShellOom("CVE-2026-109618".into()),
                Severity::Critical,
                "Upgrade to supported branch: PHP 8.2.35+, 8.3.36+, 8.4.27+, or 8.5.12+",
            )),
            _ => None,
        }
    }

    /// Determines whether a given Node.js version string is vulnerable to Node2Shell (Brotli OOB write).
    ///
    /// Fixed versions:
    /// - 22.x >= 22.23.4
    /// - 24.x >= 24.22.1
    /// - 26.x >= 26.12.1
    ///
    /// Any version <= 20.x is EOL and receives no official Brotli patch.
    pub fn check_node_version(major: u32, minor: u32, patch: u32) -> Option<(CveId, Severity, &'static str)> {
        match major {
            26 => {
                if minor < 12 || (minor == 12 && patch < 1) {
                    Some((
                        CveId::Node2ShellBrotli("CVE-2026-111497".into()),
                        Severity::High,
                        "Node.js v26.12.1+",
                    ))
                } else {
                    None
                }
            }
            24 => {
                if minor < 22 || (minor == 22 && patch < 1) {
                    Some((
                        CveId::Node2ShellBrotli("CVE-2026-111497".into()),
                        Severity::High,
                        "Node.js v24.22.1+",
                    ))
                } else {
                    None
                }
            }
            22 => {
                if minor < 23 || (minor == 23 && patch < 4) {
                    Some((
                        CveId::Node2ShellBrotli("CVE-2026-111497".into()),
                        Severity::High,
                        "Node.js v22.23.4+",
                    ))
                } else {
                    None
                }
            }
            // All EOL versions (Node 20, 18, 16, etc.)
            0..=21 => Some((
                CveId::Node2ShellBrotli("CVE-2026-111497".into()),
                Severity::High,
                "Node.js v22.23.4+, v24.22.1+, or v26.12.1+ (Node <= 20 is EOL)",
            )),
            _ => None,
        }
    }

    /// Parses a semantic version string like "8.2.14", "v22.11.0", "8.3.1-fpm", etc.
    pub fn parse_semver(raw: &str) -> Option<(u32, u32, u32)> {
        let clean = raw.trim().trim_start_matches('v').trim_start_matches('^').trim_start_matches('~');
        let parts: Vec<&str> = clean.split('.').collect();
        if parts.len() < 2 {
            return None;
        }

        let major: u32 = parts[0].parse().ok()?;
        let minor_clean: String = parts[1].chars().take_while(|c| c.is_ascii_digit()).collect();
        let minor: u32 = minor_clean.parse().ok()?;

        // Handle patch with suffixes like "14-fpm", "3-alpine", "0"
        let patch_part = parts.get(2).unwrap_or(&"0");
        let patch_clean: String = patch_part.chars().take_while(|c| c.is_ascii_digit()).collect();
        let patch: u32 = if patch_clean.is_empty() {
            0
        } else {
            patch_clean.parse().ok()?
        };

        Some((major, minor, patch))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_php_vulnerability_checks() {
        assert!(CveDatabase::check_php_version(8, 2, 34).is_some());
        assert!(CveDatabase::check_php_version(8, 2, 35).is_none());
        assert!(CveDatabase::check_php_version(8, 3, 35).is_some());
        assert!(CveDatabase::check_php_version(8, 3, 36).is_none());
        assert!(CveDatabase::check_php_version(8, 4, 26).is_some());
        assert!(CveDatabase::check_php_version(8, 4, 27).is_none());
        assert!(CveDatabase::check_php_version(8, 5, 11).is_some());
        assert!(CveDatabase::check_php_version(8, 5, 12).is_none());
        // EOL
        assert!(CveDatabase::check_php_version(7, 4, 33).is_some());
        assert!(CveDatabase::check_php_version(8, 1, 28).is_some());
    }

    #[test]
    fn test_node_brotli_checks() {
        assert!(CveDatabase::check_node_version(22, 23, 3).is_some());
        assert!(CveDatabase::check_node_version(22, 23, 4).is_none());
        assert!(CveDatabase::check_node_version(24, 22, 0).is_some());
        assert!(CveDatabase::check_node_version(24, 22, 1).is_none());
        assert!(CveDatabase::check_node_version(26, 12, 0).is_some());
        assert!(CveDatabase::check_node_version(26, 12, 1).is_none());
        // Node 20 is EOL
        assert!(CveDatabase::check_node_version(20, 18, 0).is_some());
    }
}
