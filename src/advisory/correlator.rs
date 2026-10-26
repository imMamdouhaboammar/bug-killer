use crate::advisory::provider::{AdvisoryRecord, AdvisoryStatus};
use crate::advisory::sbom::{PackageIdentity, ResolutionKind};
use crate::engine::protocol::*;
use sha2::{Digest, Sha256};
use std::cmp::Ordering;
use std::collections::{BTreeSet, HashMap, HashSet};

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Affectedness {
    VersionAffected,
    Inconclusive,
    NotAffected,
    NotPresent,
}

#[derive(Debug, Clone, Default)]
pub struct AffectednessCorrelator;

impl AffectednessCorrelator {
    pub fn new() -> Self {
        Self
    }

    /// Evaluates whether a single package identity is affected by an advisory record.
    pub fn evaluate_affectedness(
        &self,
        pkg: &PackageIdentity,
        advisory: &AdvisoryRecord,
    ) -> Affectedness {
        // Section 03 & Test 8: Withdrawn advisories do not produce active vulnerability findings.
        if advisory.status == AdvisoryStatus::Withdrawn || advisory.withdrawn_at.is_some() {
            return Affectedness::NotAffected;
        }

        // Find affected entries in advisory matching package ecosystem & name
        let matched_affected = advisory.affected.iter().find(|aff| {
            ecosystems_match(&aff.ecosystem, &pkg.ecosystem)
                && names_match(aff.name.as_deref(), aff.purl.as_deref(), &pkg.name)
        });

        let Some(aff) = matched_affected else {
            return Affectedness::NotPresent;
        };

        // Section 03 & Test 2: Declared requirement without lockfile yields Inconclusive
        if pkg.resolution_kind == ResolutionKind::DeclaredRange || pkg.resolved_version.is_none() {
            return Affectedness::Inconclusive;
        }

        let ver = pkg.resolved_version.as_deref().unwrap();

        // If explicitly in fixed_versions list, it's not affected
        if aff.fixed_versions.iter().any(|f| f == ver) {
            return Affectedness::NotAffected;
        }

        if aff.ranges.is_empty() && aff.fixed_versions.is_empty() {
            return Affectedness::Inconclusive;
        }

        let mut any_range_affected = false;
        let mut had_ranges = false;

        for r in &aff.ranges {
            had_ranges = true;
            for ev in &r.events {
                let intro_match = match ev.introduced.as_deref() {
                    Some("0") | None => true,
                    Some(intro) => compare_versions(ver, intro) != Ordering::Less,
                };

                if !intro_match {
                    continue;
                }

                if let Some(ref fix) = ev.fixed {
                    if compare_versions(ver, fix) == Ordering::Less {
                        any_range_affected = true;
                        break;
                    }
                } else if let Some(ref last) = ev.last_affected {
                    if compare_versions(ver, last) != Ordering::Greater {
                        any_range_affected = true;
                        break;
                    }
                } else {
                    // Introduced with no upper boundary means affected
                    any_range_affected = true;
                    break;
                }
            }
            if any_range_affected {
                break;
            }
        }

        if any_range_affected {
            Affectedness::VersionAffected
        } else if had_ranges {
            Affectedness::NotAffected
        } else {
            Affectedness::Inconclusive
        }
    }

    /// Correlates packages against advisories, performs alias deduplication, and generates canonical FindingV1 records.
    pub fn correlate(
        &self,
        run_id: &str,
        snapshot_sha256: &str,
        packages: &[PackageIdentity],
        advisories: &[AdvisoryRecord],
    ) -> Vec<FindingV1> {
        let mut findings = Vec::new();

        for pkg in packages {
            // Find all advisories that affect this package
            let mut affected_advisories = Vec::new();
            for adv in advisories {
                let affectedness = self.evaluate_affectedness(pkg, adv);
                if matches!(
                    affectedness,
                    Affectedness::VersionAffected | Affectedness::Inconclusive
                ) {
                    affected_advisories.push((adv, affectedness));
                }
            }

            if affected_advisories.is_empty() {
                continue;
            }

            // Cluster advisories by shared aliases (Connected Components)
            let clusters = cluster_advisories_by_aliases(&affected_advisories);

            for cluster in clusters {
                let all_aliases: BTreeSet<String> = cluster
                    .iter()
                    .flat_map(|(adv, _)| {
                        let mut set = adv.aliases.clone();
                        set.push(adv.advisory_id.clone());
                        set
                    })
                    .collect();

                let advisory_ids_list: Vec<String> = all_aliases.into_iter().collect();

                // Pick canonical ID: prefer CVE, then GHSA, then first ID
                let canonical_id = advisory_ids_list
                    .iter()
                    .find(|id| id.starts_with("CVE-"))
                    .or_else(|| advisory_ids_list.iter().find(|id| id.starts_with("GHSA-")))
                    .or_else(|| advisory_ids_list.first())
                    .cloned()
                    .unwrap_or_else(|| "UNKNOWN-ADVISORY".to_string());

                let has_version_affected = cluster
                    .iter()
                    .any(|(_, aff)| *aff == Affectedness::VersionAffected);

                let status = if has_version_affected {
                    FindingStatus::VersionAffected
                } else {
                    FindingStatus::Inconclusive
                };

                let certainty = if has_version_affected {
                    EvidenceCertaintyV1::Confirmed
                } else {
                    EvidenceCertaintyV1::Suspected
                };

                let proof = if certainty == EvidenceCertaintyV1::Confirmed {
                    Some(ProofV1 {
                        method: ProofMethod::AuthoritativeRange,
                        artifact_sha256: snapshot_sha256.to_string(),
                        reproduced_on_snapshot: snapshot_sha256.to_string(),
                        limitations: vec![],
                    })
                } else {
                    None
                };

                // Create deterministic finding ID
                let mut hasher = Sha256::new();
                hasher.update(run_id.as_bytes());
                hasher.update(pkg.name.as_bytes());
                hasher.update(canonical_id.as_bytes());
                let finding_hash = crate::to_hex(hasher.finalize());
                let finding_id = format!("finding-{}", &finding_hash[..16]);

                let summary = cluster
                    .first()
                    .and_then(|(adv, _)| adv.summary.clone())
                    .unwrap_or_else(|| {
                        format!("Security advisory {} in {}", canonical_id, pkg.name)
                    });

                let details = cluster
                    .first()
                    .and_then(|(adv, _)| adv.details.clone())
                    .unwrap_or_else(|| {
                        format!(
                            "Package {} is affected by advisory {}",
                            pkg.name, canonical_id
                        )
                    });

                let severity = cluster
                    .iter()
                    .find_map(|(adv, _)| adv.severity.as_deref())
                    .map(|s| match s.to_uppercase().as_str() {
                        "CRITICAL" => NormalizedSeverity::Critical,
                        "HIGH" => NormalizedSeverity::High,
                        "MEDIUM" | "MODERATE" => NormalizedSeverity::Medium,
                        "LOW" => NormalizedSeverity::Low,
                        _ => NormalizedSeverity::High,
                    })
                    .unwrap_or(NormalizedSeverity::High);

                let finding = FindingV1 {
                    schema_version: "1.0".to_string(),
                    run_id: run_id.to_string(),
                    finding_id,
                    fingerprint: Some(finding_hash),
                    kind: FindingKind::KnownAdvisory,
                    status,
                    title: format!("{}: Security advisory in {}", canonical_id, pkg.name),
                    summary: Some(details),
                    severity,
                    evidence_certainty: certainty,
                    rule_id: Some("KNOWN-ADVISORY".to_string()),
                    weakness_ids: vec!["CWE-1395".to_string()],
                    advisory_ids: advisory_ids_list,
                    engine: EngineDescriptor {
                        id: "advisory-correlator".to_string(),
                        version: "1.0.0".to_string(),
                        rule_pack_sha256: None,
                    },
                    target: TargetDescriptor {
                        target_id: format!("pkg-{}", pkg.name),
                        kind: NormalizedTargetKind::Package,
                        path: pkg.path.clone(),
                        package_purl: pkg.purl.clone(),
                        version: pkg.resolved_version.clone(),
                        span: None,
                    },
                    source_snapshot_sha256: snapshot_sha256.to_string(),
                    evidence: vec![EvidenceItemV1 {
                        kind: EvidenceItemKind::AdvisoryMatch,
                        artifact_sha256: snapshot_sha256.to_string(),
                        description: summary,
                        reference: pkg.purl.clone(),
                        limitations: vec![],
                    }],
                    proof,
                    coverage_receipt_ids: vec![format!(
                        "receipt-adv-{}",
                        &canonical_id.to_lowercase()
                    )],
                    uncertainty_reasons: if status == FindingStatus::Inconclusive {
                        vec!["Package has declared range requirement without lockfile".to_string()]
                    } else {
                        vec![]
                    },
                    remediation_plan_id: None,
                    created_at: chrono::Utc::now().to_rfc3339(),
                    updated_at: None,
                    extensions: serde_json::Map::new(),
                };

                findings.push(finding);
            }
        }

        findings
    }
}

fn ecosystems_match(e1: &str, e2: &str) -> bool {
    fn norm(s: &str) -> &str {
        if s.eq_ignore_ascii_case("npm") || s.eq_ignore_ascii_case("node") {
            "npm"
        } else if s.eq_ignore_ascii_case("pypi") || s.eq_ignore_ascii_case("python") {
            "pypi"
        } else if s.eq_ignore_ascii_case("cargo")
            || s.eq_ignore_ascii_case("crates.io")
            || s.eq_ignore_ascii_case("rust")
        {
            "cargo"
        } else if s.eq_ignore_ascii_case("golang") || s.eq_ignore_ascii_case("go") {
            "golang"
        } else if s.eq_ignore_ascii_case("packagist")
            || s.eq_ignore_ascii_case("composer")
            || s.eq_ignore_ascii_case("php")
        {
            "composer"
        } else {
            s
        }
    }
    norm(e1).eq_ignore_ascii_case(norm(e2))
}

fn names_match(aff_name: Option<&str>, aff_purl: Option<&str>, pkg_name: &str) -> bool {
    if let Some(n) = aff_name {
        if n.eq_ignore_ascii_case(pkg_name) {
            return true;
        }
    }
    if let Some(purl) = aff_purl {
        if let Some((_, n, _)) = crate::advisory::sbom::parse_purl(purl) {
            if n.eq_ignore_ascii_case(pkg_name) {
                return true;
            }
        }
    }
    false
}

/// Clusters advisories into connected components based on shared IDs / aliases.
fn cluster_advisories_by_aliases<'a>(
    items: &[(&'a AdvisoryRecord, Affectedness)],
) -> Vec<Vec<(&'a AdvisoryRecord, Affectedness)>> {
    let mut alias_to_indices: HashMap<String, Vec<usize>> = HashMap::new();

    for (idx, (adv, _)) in items.iter().enumerate() {
        alias_to_indices
            .entry(adv.advisory_id.clone())
            .or_default()
            .push(idx);
        for a in &adv.aliases {
            alias_to_indices.entry(a.clone()).or_default().push(idx);
        }
    }

    let mut visited: HashSet<usize> = HashSet::new();
    let mut clusters = Vec::new();

    for start_idx in 0..items.len() {
        if visited.contains(&start_idx) {
            continue;
        }

        let mut component_indices = Vec::new();
        let mut queue = vec![start_idx];
        visited.insert(start_idx);

        while let Some(curr) = queue.pop() {
            component_indices.push(curr);
            let (adv, _) = &items[curr];

            let mut all_ids = adv.aliases.clone();
            all_ids.push(adv.advisory_id.clone());

            for id in all_ids {
                if let Some(neighbors) = alias_to_indices.get(&id) {
                    for &nbr in neighbors {
                        if !visited.contains(&nbr) {
                            visited.insert(nbr);
                            queue.push(nbr);
                        }
                    }
                }
            }
        }

        let cluster: Vec<(&'a AdvisoryRecord, Affectedness)> =
            component_indices.into_iter().map(|i| items[i]).collect();
        clusters.push(cluster);
    }

    clusters
}

/// Robust version comparison supporting SemVer as well as incomplete/custom versions.
pub fn compare_versions(v1: &str, v2: &str) -> Ordering {
    fn clean(v: &str) -> &str {
        v.trim()
            .trim_start_matches('v')
            .trim_start_matches('=')
            .trim()
    }

    let c1 = clean(v1);
    let c2 = clean(v2);

    if c1 == c2 {
        return Ordering::Equal;
    }

    let pad_semver = |s: &str| -> String {
        let parts: Vec<&str> = s.split('.').collect();
        match parts.len() {
            1 => format!("{}.0.0", s),
            2 => format!("{}.0", s),
            _ => s.to_string(),
        }
    };

    let p1 = pad_semver(c1);
    let p2 = pad_semver(c2);

    if let (Ok(sv1), Ok(sv2)) = (semver::Version::parse(&p1), semver::Version::parse(&p2)) {
        return sv1.cmp(&sv2);
    }

    // Segment by segment fallback
    let s1_parts: Vec<&str> = c1.split('.').collect();
    let s2_parts: Vec<&str> = c2.split('.').collect();
    let max_len = s1_parts.len().max(s2_parts.len());

    for i in 0..max_len {
        let seg1 = s1_parts.get(i).unwrap_or(&"0");
        let seg2 = s2_parts.get(i).unwrap_or(&"0");

        if let (Ok(n1), Ok(n2)) = (seg1.parse::<u64>(), seg2.parse::<u64>()) {
            if n1 != n2 {
                return n1.cmp(&n2);
            }
        } else if seg1 != seg2 {
            return seg1.cmp(seg2);
        }
    }

    Ordering::Equal
}
