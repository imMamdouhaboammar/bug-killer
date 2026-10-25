use std::collections::HashSet;

use super::candidate::{DismissalReason, ResearchCandidate};

/// Verifies whether a research hypothesis represents a plausible novel vulnerability
/// or matches an already known CVE/GHSA advisory in the OSV or GHSA intelligence database.
#[derive(Debug, Clone, Default)]
pub struct NoveltyChecker {
    known_advisories: HashSet<String>,
}

impl NoveltyChecker {
    /// Creates a new novelty checker with empty or default known advisory store.
    pub fn new() -> Self {
        Self {
            known_advisories: HashSet::new(),
        }
    }

    /// Registers a known advisory identifier (e.g. `CVE-2023-1234`, `GHSA-xxxx-yyyy-zzzz`).
    pub fn register_known_advisory(&mut self, advisory_id: &str) {
        self.known_advisories.insert(advisory_id.to_uppercase());
    }

    /// Populates known advisories from an iterator.
    pub fn with_known_advisories<I, S>(mut self, advisories: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        for adv in advisories {
            self.known_advisories.insert(adv.as_ref().to_uppercase());
        }
        self
    }

    /// Checks if a hypothesis targets a known advisory.
    ///
    /// If an advisory match is found:
    /// - Transitions candidate state to `CandidateState::Dismissed(DismissalReason::AlreadyKnownAdvisory(...))`.
    /// - Returns `false` (cannot claim false novelty).
    ///
    /// If no matching advisory exists:
    /// - Leaves candidate state unchanged.
    /// - Returns `true` (candidate remains eligible for novel research).
    pub fn evaluate_novelty(
        &self,
        candidate: &mut ResearchCandidate,
        targeted_advisory_id: Option<&str>,
    ) -> bool {
        if let Some(adv) = targeted_advisory_id {
            let upper = adv.to_uppercase();
            if self.known_advisories.contains(&upper)
                || upper.starts_with("CVE-")
                || upper.starts_with("GHSA-")
            {
                candidate.dismiss(DismissalReason::AlreadyKnownAdvisory(adv.to_string()));
                return false;
            }
        }

        // Also check if hypothesis text explicitly references a known advisory
        let hyp_upper = candidate.hypothesis.to_uppercase();
        for known in &self.known_advisories {
            if hyp_upper.contains(known) {
                candidate.dismiss(DismissalReason::AlreadyKnownAdvisory(known.clone()));
                return false;
            }
        }

        true
    }

    /// Checks a candidate against a slice of known advisory IDs.
    pub fn check_against_advisories(
        &self,
        candidate: &mut ResearchCandidate,
        known_advisories: &[&str],
    ) -> bool {
        for adv in known_advisories {
            let upper = adv.to_uppercase();
            if self.known_advisories.contains(&upper)
                || candidate.hypothesis.to_uppercase().contains(&upper)
            {
                candidate.dismiss(DismissalReason::AlreadyKnownAdvisory(adv.to_string()));
                return false;
            }
        }
        true
    }
}
