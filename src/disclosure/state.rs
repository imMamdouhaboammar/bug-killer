//! Disclosure Lifecycle State Machine conforming to Chapter 12 and Card M6.1.
//!
//! Enforces strict coordinated vulnerability disclosure workflows:
//! - Initial private authoring (`PrivateDraft`)
//! - Mandatory human verification gate (`UserReviewed`) before submission
//! - Zero automatic submission from scanners or research candidates
//! - Controlled maintainer coordination lifecycle
//! - Explicit reactivation from terminal outcome states

use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

/// Authoritative lifecycle state of a private vulnerability disclosure packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum DisclosureLifecycleState {
    /// Initial offline draft under authoring and local verification.
    PrivateDraft,
    /// Reviewed and approved by the human operator for private submission.
    UserReviewed,
    /// Submitted privately to upstream maintainers via verified security channel.
    SubmittedPrivately,
    /// Acknowledged and triaged by upstream maintainers.
    MaintainerTriaged,
    /// Validated fix or patch available under private coordination.
    FixAvailable,
    /// Publicly published following coordinated release and embargo conclusion.
    CoordinatedPublished,
    /// Report withdrawn by reporter (e.g. invalid, out of scope).
    Withdrawn,
    /// Upstream confirmed vulnerability is already tracked or duplicate.
    Duplicate,
    /// Rejected by upstream maintainers (e.g. intentional behavior, not a bug).
    Rejected,
    /// Pending response or feedback from maintainers after private submission.
    AwaitingResponse,
    /// Quarantined locally for safety review before proceeding.
    HoldForSafety,
}

impl DisclosureLifecycleState {
    /// Validates whether a transition from `self` to `next` is permitted
    /// under the Chapter 12 and Card M6.1 disclosure state machine.
    ///
    /// Rules enforced:
    /// - `PrivateDraft` -> `UserReviewed`, `Withdrawn`, `Duplicate`, `HoldForSafety`
    /// - `UserReviewed` -> `SubmittedPrivately`, `PrivateDraft`, `Withdrawn`, `Duplicate`
    /// - `SubmittedPrivately` -> `MaintainerTriaged`, `AwaitingResponse`, `Rejected`, `Duplicate`, `Withdrawn`
    /// - `MaintainerTriaged` -> `FixAvailable`, `Rejected`, `Withdrawn`
    /// - `FixAvailable` -> `CoordinatedPublished`
    /// - `AwaitingResponse` -> `MaintainerTriaged`, `Rejected`, `Duplicate`, `Withdrawn`
    /// - `HoldForSafety` -> `PrivateDraft`, `Withdrawn`
    /// - `Withdrawn`, `Duplicate`, `Rejected` are terminal or require explicit reactivation back to `PrivateDraft`
    /// - `CoordinatedPublished` is final and immutable
    pub fn can_transition_to(&self, next: &DisclosureLifecycleState) -> bool {
        match self {
            DisclosureLifecycleState::PrivateDraft => matches!(
                next,
                DisclosureLifecycleState::UserReviewed
                    | DisclosureLifecycleState::Withdrawn
                    | DisclosureLifecycleState::Duplicate
                    | DisclosureLifecycleState::HoldForSafety
            ),
            DisclosureLifecycleState::UserReviewed => matches!(
                next,
                DisclosureLifecycleState::SubmittedPrivately
                    | DisclosureLifecycleState::PrivateDraft
                    | DisclosureLifecycleState::Withdrawn
                    | DisclosureLifecycleState::Duplicate
            ),
            DisclosureLifecycleState::SubmittedPrivately => matches!(
                next,
                DisclosureLifecycleState::MaintainerTriaged
                    | DisclosureLifecycleState::AwaitingResponse
                    | DisclosureLifecycleState::Rejected
                    | DisclosureLifecycleState::Duplicate
                    | DisclosureLifecycleState::Withdrawn
            ),
            DisclosureLifecycleState::MaintainerTriaged => matches!(
                next,
                DisclosureLifecycleState::FixAvailable
                    | DisclosureLifecycleState::Rejected
                    | DisclosureLifecycleState::Withdrawn
            ),
            DisclosureLifecycleState::FixAvailable => {
                matches!(next, DisclosureLifecycleState::CoordinatedPublished)
            }
            DisclosureLifecycleState::AwaitingResponse => matches!(
                next,
                DisclosureLifecycleState::MaintainerTriaged
                    | DisclosureLifecycleState::Rejected
                    | DisclosureLifecycleState::Duplicate
                    | DisclosureLifecycleState::Withdrawn
            ),
            DisclosureLifecycleState::HoldForSafety => matches!(
                next,
                DisclosureLifecycleState::PrivateDraft | DisclosureLifecycleState::Withdrawn
            ),
            DisclosureLifecycleState::Withdrawn
            | DisclosureLifecycleState::Duplicate
            | DisclosureLifecycleState::Rejected => {
                matches!(next, DisclosureLifecycleState::PrivateDraft)
            }
            DisclosureLifecycleState::CoordinatedPublished => false,
        }
    }

    /// Transitions this state to `next`, returning an error if the transition is prohibited.
    pub fn transition_to(
        &mut self,
        next: DisclosureLifecycleState,
    ) -> Result<(), DisclosureStateError> {
        if self.can_transition_to(&next) {
            *self = next;
            Ok(())
        } else {
            Err(DisclosureStateError::InvalidTransition {
                from: *self,
                to: next,
            })
        }
    }

    /// Returns `true` if this state represents a terminal lifecycle endpoint.
    ///
    /// Terminal states include:
    /// - `CoordinatedPublished`: Successfully published coordinated disclosure.
    /// - `Withdrawn`: Reporter withdrew the submission.
    /// - `Duplicate`: Report determined duplicate.
    /// - `Rejected`: Upstream rejected the vulnerability report.
    ///
    /// Note: `Withdrawn`, `Duplicate`, and `Rejected` allow explicit reactivation back to `PrivateDraft`.
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            DisclosureLifecycleState::CoordinatedPublished
                | DisclosureLifecycleState::Withdrawn
                | DisclosureLifecycleState::Duplicate
                | DisclosureLifecycleState::Rejected
        )
    }

    /// Returns `true` if the packet is currently in a submittable state.
    ///
    /// Strict Ponytail Ladder guarantee: Only `UserReviewed` packets can be submitted.
    /// `PrivateDraft`, `HoldForSafety`, `Withdrawn`, `Duplicate`, etc. CANNOT be submitted.
    pub fn is_submittable(&self) -> bool {
        matches!(self, DisclosureLifecycleState::UserReviewed)
    }

    /// Explicitly reactivates a terminal outcome state (`Withdrawn`, `Duplicate`, `Rejected`)
    /// back to `PrivateDraft` for re-investigation or revision.
    pub fn reactivate(&mut self) -> Result<DisclosureLifecycleState, DisclosureStateError> {
        if matches!(
            self,
            DisclosureLifecycleState::Withdrawn
                | DisclosureLifecycleState::Duplicate
                | DisclosureLifecycleState::Rejected
        ) {
            *self = DisclosureLifecycleState::PrivateDraft;
            Ok(*self)
        } else {
            Err(DisclosureStateError::InvalidTransition {
                from: *self,
                to: DisclosureLifecycleState::PrivateDraft,
            })
        }
    }

    /// Returns the static string representation of this state.
    pub fn as_str(&self) -> &'static str {
        match self {
            DisclosureLifecycleState::PrivateDraft => "PrivateDraft",
            DisclosureLifecycleState::UserReviewed => "UserReviewed",
            DisclosureLifecycleState::SubmittedPrivately => "SubmittedPrivately",
            DisclosureLifecycleState::MaintainerTriaged => "MaintainerTriaged",
            DisclosureLifecycleState::FixAvailable => "FixAvailable",
            DisclosureLifecycleState::CoordinatedPublished => "CoordinatedPublished",
            DisclosureLifecycleState::Withdrawn => "Withdrawn",
            DisclosureLifecycleState::Duplicate => "Duplicate",
            DisclosureLifecycleState::Rejected => "Rejected",
            DisclosureLifecycleState::AwaitingResponse => "AwaitingResponse",
            DisclosureLifecycleState::HoldForSafety => "HoldForSafety",
        }
    }
}

impl fmt::Display for DisclosureLifecycleState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl FromStr for DisclosureLifecycleState {
    type Err = DisclosureStateError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim() {
            "PrivateDraft" => Ok(DisclosureLifecycleState::PrivateDraft),
            "UserReviewed" => Ok(DisclosureLifecycleState::UserReviewed),
            "SubmittedPrivately" => Ok(DisclosureLifecycleState::SubmittedPrivately),
            "MaintainerTriaged" => Ok(DisclosureLifecycleState::MaintainerTriaged),
            "FixAvailable" => Ok(DisclosureLifecycleState::FixAvailable),
            "CoordinatedPublished" => Ok(DisclosureLifecycleState::CoordinatedPublished),
            "Withdrawn" => Ok(DisclosureLifecycleState::Withdrawn),
            "Duplicate" => Ok(DisclosureLifecycleState::Duplicate),
            "Rejected" => Ok(DisclosureLifecycleState::Rejected),
            "AwaitingResponse" => Ok(DisclosureLifecycleState::AwaitingResponse),
            "HoldForSafety" => Ok(DisclosureLifecycleState::HoldForSafety),
            other => Err(DisclosureStateError::UnknownState(other.to_string())),
        }
    }
}

/// Errors raised during disclosure lifecycle transitions and validation.
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum DisclosureStateError {
    #[error("Invalid disclosure lifecycle transition from {from} to {to}")]
    InvalidTransition {
        from: DisclosureLifecycleState,
        to: DisclosureLifecycleState,
    },

    #[error(
        "Disclosure packet is not in submittable state: current state is {0}, required state is UserReviewed"
    )]
    NotSubmittable(DisclosureLifecycleState),

    #[error("Unknown disclosure lifecycle state: {0}")]
    UnknownState(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_private_draft_transitions() {
        let state = DisclosureLifecycleState::PrivateDraft;
        assert!(state.can_transition_to(&DisclosureLifecycleState::UserReviewed));
        assert!(state.can_transition_to(&DisclosureLifecycleState::Withdrawn));
        assert!(state.can_transition_to(&DisclosureLifecycleState::Duplicate));
        assert!(state.can_transition_to(&DisclosureLifecycleState::HoldForSafety));

        // Prohibited transitions
        assert!(!state.can_transition_to(&DisclosureLifecycleState::SubmittedPrivately));
        assert!(!state.can_transition_to(&DisclosureLifecycleState::CoordinatedPublished));
        assert!(!state.can_transition_to(&DisclosureLifecycleState::FixAvailable));
        assert!(!state.can_transition_to(&DisclosureLifecycleState::MaintainerTriaged));
    }

    #[test]
    fn test_user_reviewed_transitions() {
        let state = DisclosureLifecycleState::UserReviewed;
        assert!(state.can_transition_to(&DisclosureLifecycleState::SubmittedPrivately));
        assert!(state.can_transition_to(&DisclosureLifecycleState::PrivateDraft));
        assert!(state.can_transition_to(&DisclosureLifecycleState::Withdrawn));
        assert!(state.can_transition_to(&DisclosureLifecycleState::Duplicate));

        // Cannot skip directly to maintainer triage or published
        assert!(!state.can_transition_to(&DisclosureLifecycleState::MaintainerTriaged));
        assert!(!state.can_transition_to(&DisclosureLifecycleState::CoordinatedPublished));
    }

    #[test]
    fn test_submitted_privately_transitions() {
        let state = DisclosureLifecycleState::SubmittedPrivately;
        assert!(state.can_transition_to(&DisclosureLifecycleState::MaintainerTriaged));
        assert!(state.can_transition_to(&DisclosureLifecycleState::AwaitingResponse));
        assert!(state.can_transition_to(&DisclosureLifecycleState::Rejected));
        assert!(state.can_transition_to(&DisclosureLifecycleState::Duplicate));
        assert!(state.can_transition_to(&DisclosureLifecycleState::Withdrawn));

        // Cannot jump backwards to Draft or straight to CoordinatedPublished
        assert!(!state.can_transition_to(&DisclosureLifecycleState::PrivateDraft));
        assert!(!state.can_transition_to(&DisclosureLifecycleState::CoordinatedPublished));
    }

    #[test]
    fn test_maintainer_triaged_transitions() {
        let state = DisclosureLifecycleState::MaintainerTriaged;
        assert!(state.can_transition_to(&DisclosureLifecycleState::FixAvailable));
        assert!(state.can_transition_to(&DisclosureLifecycleState::Rejected));
        assert!(state.can_transition_to(&DisclosureLifecycleState::Withdrawn));

        // Cannot jump directly to CoordinatedPublished without FixAvailable
        assert!(!state.can_transition_to(&DisclosureLifecycleState::CoordinatedPublished));
        assert!(!state.can_transition_to(&DisclosureLifecycleState::PrivateDraft));
    }

    #[test]
    fn test_fix_available_transitions() {
        let state = DisclosureLifecycleState::FixAvailable;
        assert!(state.can_transition_to(&DisclosureLifecycleState::CoordinatedPublished));

        assert!(!state.can_transition_to(&DisclosureLifecycleState::PrivateDraft));
        assert!(!state.can_transition_to(&DisclosureLifecycleState::SubmittedPrivately));
    }

    #[test]
    fn test_hold_for_safety_transitions() {
        let mut state = DisclosureLifecycleState::HoldForSafety;
        assert!(state.can_transition_to(&DisclosureLifecycleState::PrivateDraft));
        assert!(state.can_transition_to(&DisclosureLifecycleState::Withdrawn));
        assert!(!state.can_transition_to(&DisclosureLifecycleState::SubmittedPrivately));

        assert!(
            state
                .transition_to(DisclosureLifecycleState::PrivateDraft)
                .is_ok()
        );
        assert_eq!(state, DisclosureLifecycleState::PrivateDraft);
    }

    #[test]
    fn test_terminal_and_reactivation() {
        let terminal_states = [
            DisclosureLifecycleState::Withdrawn,
            DisclosureLifecycleState::Duplicate,
            DisclosureLifecycleState::Rejected,
        ];

        for &terminal in &terminal_states {
            assert!(terminal.is_terminal());
            assert!(!terminal.is_submittable());

            // Only PrivateDraft is allowed as next state (reactivation)
            assert!(terminal.can_transition_to(&DisclosureLifecycleState::PrivateDraft));
            assert!(!terminal.can_transition_to(&DisclosureLifecycleState::UserReviewed));
            assert!(!terminal.can_transition_to(&DisclosureLifecycleState::SubmittedPrivately));
            assert!(!terminal.can_transition_to(&DisclosureLifecycleState::CoordinatedPublished));

            let mut reactive = terminal;
            assert!(reactive.reactivate().is_ok());
            assert_eq!(reactive, DisclosureLifecycleState::PrivateDraft);
        }

        // CoordinatedPublished is final and cannot be reactivated
        let mut published = DisclosureLifecycleState::CoordinatedPublished;
        assert!(published.is_terminal());
        assert!(!published.is_submittable());
        assert!(!published.can_transition_to(&DisclosureLifecycleState::PrivateDraft));
        assert!(published.reactivate().is_err());
    }

    #[test]
    fn test_submittability_invariants() {
        // Strict invariant: ONLY UserReviewed is submittable!
        let all_states = [
            DisclosureLifecycleState::PrivateDraft,
            DisclosureLifecycleState::UserReviewed,
            DisclosureLifecycleState::SubmittedPrivately,
            DisclosureLifecycleState::MaintainerTriaged,
            DisclosureLifecycleState::FixAvailable,
            DisclosureLifecycleState::CoordinatedPublished,
            DisclosureLifecycleState::Withdrawn,
            DisclosureLifecycleState::Duplicate,
            DisclosureLifecycleState::Rejected,
            DisclosureLifecycleState::AwaitingResponse,
            DisclosureLifecycleState::HoldForSafety,
        ];

        for state in all_states {
            if state == DisclosureLifecycleState::UserReviewed {
                assert!(state.is_submittable(), "UserReviewed must be submittable");
            } else {
                assert!(
                    !state.is_submittable(),
                    "State {:?} must NOT be submittable without user review",
                    state
                );
            }
        }
    }

    #[test]
    fn test_serde_json_roundtrip() {
        let state = DisclosureLifecycleState::SubmittedPrivately;
        let json = serde_json::to_string(&state).unwrap();
        assert_eq!(json, "\"SubmittedPrivately\"");

        let deserialized: DisclosureLifecycleState = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, state);
    }
}
