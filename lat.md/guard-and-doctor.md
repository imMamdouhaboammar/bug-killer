# System Doctor and Security Guard

Bug Killer provides environment health diagnostics, project onboarding, and pre-commit admission gating.

These utilities verify runtime dependencies, manage baseline findings, and enforce fail-closed security policies.

## System Doctor Environment Diagnostics

The doctor evaluates host runtime versions, proxy configurations, and process inspection capabilities.

Diagnostic scans are orchestrated by [[src/doctor/mod.rs#SystemDoctor#diagnose]], producing an itemized [[src/doctor/mod.rs#DoctorReport]] using [[src/doctor/mod.rs#CheckStatus]] indicators.

## Security Guard Baseline Management

The security guard establishes baseline scan snapshots and configures repository security policies.

Initialization returns an [[src/security_guard/mod.rs#InitReceipt]], while ongoing posture is queried through [[src/security_guard/mod.rs#SecurityStatusReport]] via [[src/security_guard/mod.rs#SecurityGuard]].

## Pre-Commit Admission Gating

Git hooks evaluate staged snapshots before commits are accepted into source control.

Commits containing high or critical severity vulnerabilities are rejected by default unless explicit waivers exist.
