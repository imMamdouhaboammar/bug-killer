#![allow(dead_code, clippy::collapsible_if)]

use crate::types::*;
use regex::Regex;
use std::collections::HashSet;
use std::path::Path;
use std::sync::LazyLock;

// An extended regex may need neighboring lines as evidence, but a match must
// be attributed only to the line where it starts. Otherwise a single error
// produces a separate finding on every line in the surrounding window.
fn pattern_starts_here(pattern: &Regex, window: &str, start: usize, end: usize) -> bool {
    pattern
        .find_iter(window)
        .any(|hit| hit.start() >= start && hit.start() < end)
}

// ===========================================================================
// Category 26: Bug Killer-Specific Scanner, Reporter & Healer Safety
// Rules: BK-AI-BKH-001 through BK-AI-BKH-018
// ===========================================================================

const CATEGORY_BKH: &str = "2.26 Bug Killer-specific scanner, reporter and healer safety";

// ---------------------------------------------------------------------------
// Rule Regex Definitions
// ---------------------------------------------------------------------------

/// BK-AI-BKH-001 (CWE-754): Scanner reports "clean" after parser/network/tool failure
static RE_BKH_001_FAIL_CLEAN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?is)(?:if\s+(?:let\s+Err\s*\([^)]*\)\s*=|err\s*!=\s*nil|error\b)[^{]*\{[^}]*?\breturn\s+(?:Ok\s*\(\s*(?:Report|ScanResult|ScanReport)::clean\s*\(\s*\)|(?:Report|ScanResult|ScanReport)::clean\s*\(\s*\)|&?Report\{\s*Status:\s*["']clean["']|Ok\s*\(\s*vec!\[\s*\]\s*\)|\{\s*status:\s*["']clean["']|\{\s*clean:\s*true\b)\b|catch\s*(?:\([^)]*\))?\s*\{[^}]*?\breturn\s+(?:(?:Report|ScanResult|ScanReport)::clean\s*\(\s*\)|(?:Report|ScanResult)::empty\s*\(\s*\)|\{\s*status:\s*["']clean["']|\{\s*clean:\s*true\b|Ok\s*\(\s*vec!\[\s*\]\s*\)|clean\s*\(\s*\))|except\s+[^:]*:\s*[\s\S]*?\breturn\s+(?:ScanResult\.clean\(\)|Report\.clean\(\)|\{\s*['"]clean['"]\s*:\s*True\})|match\s+[a-zA-Z0-9_().]+\s*\{[^}]*?Err\s*\([^)]*\)\s*=>\s*(?:Ok\s*\(\s*(?:Report|ScanResult|ScanReport)::clean\s*\(\s*\)|Ok\s*\(\s*vec!\[\s*\]\s*\))|\b(?:report_clean_on_failure|clean_on_scanner_error|swallow_scan_error_report_clean)\s*[:=]\s*true\b|\breturn\s+Ok\s*\(\s*(?:Report|ScanResult|ScanReport)::clean\s*\(\s*\)|//.*scanner\s+reports\s+["']?clean["']?\s+after\s+(?:parser|network|tool|scanner)\s+failure)"#).unwrap()
});
static RE_BKH_001_GUARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:ScanStatus::Error|ScanStatus::Partial|Status::Error|ScanStatus::Failed|status:\s*["']error["']|status:\s*["']partial["']|status:\s*["']failed["']|return\s+Err\s*\(|throw\s+|raise\s+|logger\.error|log\.Error|record_scan_failure|has_errors:\s*true|emit_error)"#).unwrap()
});

/// BK-AI-BKH-002 (CWE-704): Scanner treats unresolved manifest constraint as installed vulnerable/safe version
static RE_BKH_002_UNRESOLVED_MANIFEST: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:[a-zA-Z0-9_.]*(?:version|ver|constraint)\.unwrap_or\s*\(\s*["'](?:0\.0\.0|latest|\*)["']\s*\)|(?:version|ver|constraint)\s*\|\|\s*["'](?:0\.0\.0|latest|\*)["']|\b(?:assume_safe_if_unpinned|treat_unresolved_as_safe|treat_unresolved_as_installed|assume_unpinned_is_safe|default_unpinned_to_safe)\s*[:=]\s*true\b|if\s+[a-zA-Z0-9_.]*(?:version|constraint)\.is_none\(\)\s*\{[^}]*?\breturn\s+(?:Status::Safe|true|Ok\(Version::Safe\))|//.*treats?\s+unresolved\s+manifest\s+constraint\s+as\s+(?:installed|vulnerable|safe))"#).unwrap()
});
static RE_BKH_002_GUARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:UnresolvedConstraint|Err\(.*Unresolved|Status::Unresolved|Status::Ambiguous|require_lockfile|fail_on_unpinned|lockfile_resolved_version|validate_exact_version|lockfile_lookup)"#).unwrap()
});

/// BK-AI-BKH-003 (CWE-693): Finding goes to healer solely because model believes it is exploitable
static RE_BKH_003_HEALER_ON_MODEL_BELIEF: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:if\s+[a-zA-Z0-9_.]*(?:model\.believes_exploitable|ai_exploitable_assessment|llm\.is_exploitable|llm_believes_vulnerable|ai_confidence\s*>\s*0\.\d+)[^{]*\{[^}]*?\b(?:dispatch_to_healer|healer\.remediate|trigger_auto_heal|send_to_healer|auto_heal)\b|\b(?:dispatch_to_healer|healer\.remediate|trigger_auto_heal|send_to_healer|auto_heal)\s*\([^)]*?(?:model\.believes_exploitable|ai_exploitable|llm\.is_exploitable)[^)]*?\)|\b(?:skip_deterministic_proof|bypass_deterministic_verification|dispatch_healer_without_taint_proof|heal_on_ai_confidence_alone)\s*[:=]\s*true\b|//.*finding\s+goes\s+to\s+healer\s+solely\s+because\s+model\s+believes)"#).unwrap()
});
static RE_BKH_003_GUARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:taint_proof\.is_some|deterministic_proof|require_taint_proof|verify_ast_flow|TaintFlow::Confirmed|deterministic_gate|reproducible_exploit_proof|verify_deterministic_taint)"#).unwrap()
});

/// BK-AI-BKH-004 (CWE-829): New analyzer runs arbitrary repository build/install hooks without consent
static RE_BKH_004_RUN_BUILD_HOOKS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:Command::new\s*\(\s*["'](?:cargo|npm|yarn|pnpm|pip|pip3|make|mvn|gradle)["']\s*\)(?:\.[a-zA-Z0-9_]+\s*\([^)]*\))*\s*\.arg\s*\(\s*["'](?:build|install|compile|package)["']\s*\)|execSync\s*\(\s*["'](?:npm\s+install|cargo\s+build|pip\s+install|make|yarn\s+install)["']\s*[,)]|subprocess\.(?:run|Popen|check_call)\s*\(\s*\[\s*["'](?:cargo|npm|yarn|pip|make)["']\s*,\s*["'](?:build|install|compile)["']|\b(?:execute_build_hooks|run_repo_build_scripts|allow_arbitrary_build_scripts|run_install_hooks_without_sandbox|auto_run_build_scripts)\s*[:=]\s*true\b|//.*analyzer\s+runs\s+arbitrary\s+(?:repo|repository)?\s*build[/\s]install\s+hooks)"#).unwrap()
});
static RE_BKH_004_GUARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:sandbox|nsjail|bwrap|docker|container_runner|user_consent|prompt_user_consent|require_consent|dry_run|skip_build_scripts|read_only_analysis|isolated_environment)"#).unwrap()
});

/// BK-AI-BKH-005 (CWE-918): DAST scanner follows redirect or DNS to out-of-scope network
static RE_BKH_005_UNSCOPED_REDIRECT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:\b(?:follow_redirects_unrestricted|allow_out_of_scope_redirects|allow_external_redirects|redirect_to_any_network)\s*[:=]\s*true\b|\bredirection_scope_validation\s*[:=]\s*false\b|\.redirect\s*\(\s*(?:reqwest::redirect::)?Policy::custom\s*\([^)]*attempt\.follow\s*\(\s*\)\s*\)|\bfollow_redirects\s*[:=]\s*true[^\n;]*?(?:without_validation|unrestricted|any_host)|//.*DAST\s+scanner\s+follows\s+redirect.*out-of-scope)"#).unwrap()
});
static RE_BKH_005_GUARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:is_in_scope|validate_scope|scope_validator|allowed_cidrs|target_in_scope|validate_redirect_target|Policy::none\(\)|cidr_range|scope\.contains)"#).unwrap()
});

/// BK-AI-BKH-006 (CWE-250): External scanner tool/plugin inherits host secrets or admin credentials
static RE_BKH_006_INHERIT_SECRETS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:\.envs\s*\(\s*(?:std::)?env::vars\s*\(\s*\)\s*\)|env:\s*process\.env\b[^\n;]*?(?:plugin|scanner|tool|analyzer)|\b(?:inherit_host_env|inherit_parent_env|pass_all_secrets_to_plugin|inherit_credentials_unfiltered)\s*[:=]\s*true\b|Command::new\s*\(\s*["']sudo["']\s*\)(?:\.[a-zA-Z0-9_]+\s*\([^)]*\))*\s*\.arg\s*\([^)]*?(?:scanner|plugin|analyzer|tool)|//.*scanner\s+tool/plugin\s+inherits\s+host\s+secrets)"#).unwrap()
});
static RE_BKH_006_GUARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:env_clear\(\)|sanitize_env|clean_env|isolated_env|filtered_env|strip_secrets|drop_privileges|unprivileged_user)"#).unwrap()
});

/// BK-AI-BKH-007 (CWE-532): Security report leaks credentials, environment or response body
static RE_BKH_007_REPORT_LEAKS_CREDS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:\b(?:redact_report_secrets|sanitize_report_evidence|mask_credentials_in_report)\s*[:=]\s*false\b|\b(?:include_raw_credentials_in_report|include_raw_secrets|dump_full_env_in_report)\s*[:=]\s*true\b|report\.(?:add_evidence|add_field|insert|metadata\.insert)\s*\([^)]*?(?:authorization|bearer|auth_token|api_key|secret_key|private_key|password)[^)]*?\)|report\.raw_response_body\s*=\s*(?:resp|response)\.body\b|//.*security\s+report\s+leaks\s+(?:credentials|environment|response\s+body))"#).unwrap()
});
static RE_BKH_007_GUARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:redact|mask|sanitize|strip_credentials|redacted_value|\[REDACTED\]|mask_token|truncate_body|hash_credential)"#).unwrap()
});

/// BK-AI-BKH-008 (CWE-22): Auto-fix edits wrong file because matching by basename or ambiguous path
static RE_BKH_008_BASENAME_MATCH: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:\b(?:find_by_basename|lookup_by_basename|match_file_by_basename|patch_by_basename)\b|\b(?:patch_by_basename_only|allow_ambiguous_path_match|match_by_filename_only)\s*[:=]\s*true\b|workspace\.find\s*\([^)]*?\.file_name\s*\(\s*\)[^)]*?\)|//.*auto-fix\s+edits\s+wrong\s+file\s+because\s+matching\s+by\s+basename)"#).unwrap()
});
static RE_BKH_008_GUARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:canonicalize\(\)|canonical_path|canonicalize\(\)\?\.starts_with|exact_relative_path|validate_canonical_target|canonical_match)"#).unwrap()
});

/// BK-AI-BKH-009 (CWE-284): Healing changes unapproved file, service or cloud asset
static RE_BKH_009_UNAPPROVED_MUTATION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:\b(?:allow_modifications_outside_workspace|bypass_workspace_boundary_check|skip_workspace_validation|unrestricted_healer_file_write|heal_unapproved_targets)\s*[:=]\s*true\b|healer\.mutate_unrestricted\s*\(|//.*healing\s+changes\s+unapproved\s+file)"#).unwrap()
});
static RE_BKH_009_GUARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:canonicalize\(\)\?\.starts_with\s*\([^)]*workspace|is_within_workspace|verify_workspace_containment|approved_targets\.contains|assert_within_workspace|validate_target_boundary)"#).unwrap()
});

/// BK-AI-BKH-010 (CWE-345): Backup not independently authenticated or restorable
static RE_BKH_010_UNAUTHENTICATED_BACKUP: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:\b(?:skip_backup_signature|sign_backup_manifest\s*[:=]\s*false|verify_backup_restorable\s*[:=]\s*false|skip_restore_verification\s*[:=]\s*true|allow_unsigned_backup\s*[:=]\s*true)\b|BackupManifest::new_unsigned\s*\(|BackupManifest\s*\{[^}]*?signature:\s*None|//.*backup\s+not\s+independently\s+authenticated\s+or\s+restorable)"#).unwrap()
});
static RE_BKH_010_GUARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:ed25519|signature:\s*Some\(|verify_signature\(|sha256|verify_restorable\(\)|test_restore\(\)|Ed25519Signature|verify_backup_integrity)"#).unwrap()
});

/// BK-AI-BKH-011 (CWE-693): Multi-file healing fails halfway without coherent rollback/state receipt
static RE_BKH_011_NO_BATCH_ROLLBACK: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:\b(?:disable_atomic_batch_rollback|skip_transactional_rollback|rollback_on_batch_failure\s*[:=]\s*false|partial_patch_allowed\s*[:=]\s*true|skip_batch_rollback\s*[:=]\s*true)\b|//.*multi-file\s+healing\s+fails\s+halfway\s+without\s+coherent\s+rollback)"#).unwrap()
});
static RE_BKH_011_GUARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:rollback\s*\(|rollback_all|revert_changes|restore_from_backup|RollbackReceipt|TransactionalPatch|transaction\.rollback|abort_transaction)"#).unwrap()
});

/// BK-AI-BKH-012 (CWE-693): Agent merges or releases a fix despite failing/skipped required tests
static RE_BKH_012_MERGE_WITHOUT_TESTS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:git\s+push\s+[^\n]*?--no-verify\b|["']git["']\s*,\s*&?\[[^\]]*?["']--no-verify["']|\b(?:skip_verification_tests|ignore_test_failures|auto_merge_on_failing_tests|bypass_status_checks|force_merge_without_verification|merge_despite_test_failure)\s*[:=]\s*true\b|//.*agent\s+merges\s+or\s+releases.*despite\s+failing[/\s]skipped\s+required\s+tests)"#).unwrap()
});
static RE_BKH_012_GUARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:require_tests_pass|test_results\.all_passed|require_status_checks\s*[:=]\s*true|assert_tests_green|fail_closed_on_test_failure)"#).unwrap()
});

/// BK-AI-BKH-013 (CWE-1059): Exclusion/suppression never expires or hides entire directory silently
static RE_BKH_013_UNBOUNDED_SUPPRESSION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:\b(?:suppress_all_rules|ignore_all_findings|blanket_suppression_enabled)\s*[:=]\s*true\b|SuppressRule\s*\{[^}]*?rule_id:\s*["']\*["'][^}]*?expires_at:\s*None|ignore_rules\s*[:=]\s*\[\s*["']\*["']\s*\]|\bexpires\s*[:=]\s*["']never["']\b[^\n]*?(?:suppress|ignore|exclude)|//.*exclusion/suppression\s+never\s+expires\s+or\s+hides\s+entire\s+directory)"#).unwrap()
});
static RE_BKH_013_GUARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:expires_at\s*:\s*Some|expires:\s*["']\d{4}-\d{2}-\d{2}|expiration_date|valid_until|review_date|max_suppression_duration)"#).unwrap()
});

/// BK-AI-BKH-014 (CWE-1059): Scanner's source-to-sink claim is only a regex keyword hit
static RE_BKH_014_REGEX_TAINT_CLAIM: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:\b(?:claim_reachability_from_regex_only|regex_only_reachability|taint_from_regex_alone|claim_taint_without_ast)\s*[:=]\s*true\b|(?:regex|re|pattern)\.is_match\([^)]*\)[^;]*?reachability\s*=\s*(?:Reachability::Reachable|Reachability::Confirmed)|(?:regex|re)\.is_match\([^)]*\)[^;]*?taint_flow\s*=\s*TaintFlow::Confirmed|//.*scanner's\s+source-to-sink\s+claim\s+is\s+only\s+a\s+regex\s+keyword\s+hit)"#).unwrap()
});
static RE_BKH_014_GUARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:ast_graph|dfg_trace|control_flow_graph|TaintTracker|DataFlowAnalysis|Reachability::PotentiallyReachable|Reachability::Unknown|downgrade_to_indicator)"#).unwrap()
});

/// BK-AI-BKH-015 (CWE-1059): CI checks Rust crate but skips Go services, nested Cargo workspace or installer
static RE_BKH_015_CI_SKIPS_SERVICES: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:\b(?:skip_go_services|skip_services_test|test_go_services\s*[:=]\s*false|skip_nested_workspaces\s*[:=]\s*true|run_rust_only\s*[:=]\s*true|exclude_services_from_ci\s*[:=]\s*true)\b|//.*CI\s+checks\s+Rust\s+crate\s+but\s+skips\s+Go\s+services)"#).unwrap()
});
static RE_BKH_015_GUARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:services/orchestrator|services/healer|go\s+test\s+\./\.\.\.|matrix:.*include:.*go|all_services_tested\s*[:=]\s*true)"#).unwrap()
});

/// BK-AI-BKH-016 (CWE-770): Remote target scan begins without asset authorization and rate/egress budgets
static RE_BKH_016_UNAUTHORIZED_UNRATED_SCAN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:\b(?:bypass_asset_authorization|require_asset_authorization\s*[:=]\s*false|skip_target_authorization\s*[:=]\s*true)\b|\b(?:unlimited_scan_rate|no_rate_limit|rate_limit_rps\s*[:=]\s*0)\b|scan_remote_target\s*\([^)]*?auth(?:_token)?:\s*None|//.*remote\s+target\s+scan\s+begins\s+without\s+asset\s+authorization)"#).unwrap()
});
static RE_BKH_016_GUARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:verify_asset_ownership|verify_asset_authorization|check_asset_authorization|authorization_token|RateLimiter|rate_limit_rps|token_bucket|egress_budget|scan_remote_target_authorized)"#).unwrap()
});

/// BK-AI-BKH-017 (CWE-362): Parallel healers race on same manifest/config, overwriting each other's changes
static RE_BKH_017_RACING_HEALERS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:\b(?:disable_manifest_file_lock|skip_file_locking|allow_concurrent_manifest_mutations|concurrent_patching_without_lock)\s*[:=]\s*true\b|//.*parallel\s+healers\s+race\s+on\s+same\s+manifest/config)"#).unwrap()
});
static RE_BKH_017_GUARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:FileLock|flock|lock_exclusive|acquire_lock|Mutex|RwLock|atomic_write|fs2::FileExt|advisory_lock)"#).unwrap()
});

/// BK-AI-BKH-018 (CWE-1059): Public README claims support for checks not implemented, validated or enabled
static RE_BKH_018_UNVERIFIED_CLAIM: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:\b(?:claim_unimplemented_as_supported|mock_implementation_declared_supported|publish_stub_as_supported)\s*[:=]\s*true\b|status:\s*["'](?:supported|production[ _]ready|active)["'][^\n]*?(?:TODO|unimplemented|stub|not yet implemented|mock)|(?:TODO|unimplemented|stub|mock)[^\n]*?status:\s*["'](?:supported|production[ _]ready)["']|//.*public\s+README\s+claims\s+support\s+for\s+checks\s+not\s+implemented)"#).unwrap()
});
static RE_BKH_018_GUARD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)(?:status:\s*["'](?:planned|in[ _]development|stub|deprecated)["']|is_implemented:\s*true|has_active_detector|verified_by_tests:\s*true)"#).unwrap()
});

// ---------------------------------------------------------------------------
// Scanner Implementation
// ---------------------------------------------------------------------------

pub struct BkhSafetyScanner;

impl BkhSafetyScanner {
    /// Scans a file's content for Category 26: Bug Killer-specific scanner, reporter and healer safety flaws.
    pub fn scan_source(path: &Path, content: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        let mut seen: HashSet<(&'static str, usize)> = HashSet::new();

        let ext = path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_lowercase();

        let target_kind = match ext.as_str() {
            "js" | "mjs" | "cjs" | "ts" | "tsx" | "jsx" => TargetKind::NodeSourceFile,
            "json" | "yaml" | "yml" | "toml" => TargetKind::GenericConfigFile,
            "env" => TargetKind::EnvironmentFile,
            _ => TargetKind::GenericSourceFile,
        };

        let lines: Vec<&str> = content.lines().collect();
        let total_lines = lines.len();

        for (idx, line) in lines.iter().enumerate() {
            let line_no = idx + 1;
            let trimmed = line.trim();

            if trimmed.is_empty() {
                continue;
            }

            // Window contexts for multi-line analysis (+/- 8 lines)
            let window_start = idx.saturating_sub(8);
            let window_end = (idx + 9).min(total_lines);
            let context_window = lines[window_start..window_end].join("\n");
            let current_start: usize = lines[window_start..idx]
                .iter()
                .map(|previous| previous.len() + 1)
                .sum();
            let current_end = current_start + line.len();

            // 1. BK-AI-BKH-001 (CWE-754): Scanner reports "clean" after parser/network/tool failure
            if (RE_BKH_001_FAIL_CLEAN.is_match(trimmed)
                || pattern_starts_here(
                    &RE_BKH_001_FAIL_CLEAN,
                    &context_window,
                    current_start,
                    current_end,
                ))
                && !RE_BKH_001_GUARD.is_match(&context_window)
            {
                Self::push_finding(
                    &mut findings,
                    &mut seen,
                    "BK-AI-BKH-001",
                    &["CWE-754"],
                    "Scanner reports \"clean\" after parser/network/tool failure",
                    Severity::Critical,
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Propagate scanner failure or return ScanStatus::Error/ScanStatus::Partial instead of clean result",
                    "Scanner swallows parser, network, or execution failure and reports clean or empty findings without flagging an error or partial scan state.",
                    "Retain PARTIAL or ERROR status upon tool/parser failure; do not return clean reports or empty findings on unhandled errors.",
                );
            }

            // 2. BK-AI-BKH-002 (CWE-704): Scanner treats unresolved manifest constraint as installed vulnerable/safe version
            if (RE_BKH_002_UNRESOLVED_MANIFEST.is_match(trimmed)
                || pattern_starts_here(
                    &RE_BKH_002_UNRESOLVED_MANIFEST,
                    &context_window,
                    current_start,
                    current_end,
                ))
                && !RE_BKH_002_GUARD.is_match(&context_window)
            {
                Self::push_finding(
                    &mut findings,
                    &mut seen,
                    "BK-AI-BKH-002",
                    &["CWE-704"],
                    "Scanner treats unresolved manifest constraint as installed vulnerable/safe version",
                    Severity::High,
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Enforce exact lockfile resolution or return Status::UnresolvedConstraint when version is not pinned",
                    "Scanner defaults unresolved, floating, or wildcard dependency constraints to safe or mock version without lockfile verification.",
                    "Differentiate exact installed versions from declared manifest ranges and require lockfile lookup for unresolved constraints.",
                );
            }

            // 3. BK-AI-BKH-003 (CWE-693): Finding goes to healer solely because model believes it is exploitable
            if (RE_BKH_003_HEALER_ON_MODEL_BELIEF.is_match(trimmed)
                || pattern_starts_here(
                    &RE_BKH_003_HEALER_ON_MODEL_BELIEF,
                    &context_window,
                    current_start,
                    current_end,
                ))
                && !RE_BKH_003_GUARD.is_match(&context_window)
            {
                Self::push_finding(
                    &mut findings,
                    &mut seen,
                    "BK-AI-BKH-003",
                    &["CWE-693", "CWE-862"],
                    "Finding goes to healer solely because model believes it is exploitable",
                    Severity::High,
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Require deterministic taint verification (TaintFlow::Confirmed) before dispatching finding to healer",
                    "Automated healing or virtual patching is triggered based solely on LLM/model confidence without deterministic taint analysis or AST proof.",
                    "Enforce independent deterministic policy gate requiring confirmed taint flow before triggering automated healing.",
                );
            }

            // 4. BK-AI-BKH-004 (CWE-829): New analyzer runs arbitrary repository build/install hooks without consent
            if (RE_BKH_004_RUN_BUILD_HOOKS.is_match(trimmed)
                || pattern_starts_here(
                    &RE_BKH_004_RUN_BUILD_HOOKS,
                    &context_window,
                    current_start,
                    current_end,
                ))
                && !RE_BKH_004_GUARD.is_match(&context_window)
            {
                Self::push_finding(
                    &mut findings,
                    &mut seen,
                    "BK-AI-BKH-004",
                    &["CWE-829"],
                    "New analyzer runs arbitrary repository build/install hooks without consent",
                    Severity::Critical,
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Run build hooks only within isolated sandbox with mandatory explicit user consent",
                    "Static analyzer executes arbitrary repository build or install hooks without sandbox isolation or explicit user consent.",
                    "Confine analysis to read-only AST parsing or execute build hooks strictly inside sandboxed containers with user approval.",
                );
            }

            // 5. BK-AI-BKH-005 (CWE-918): DAST scanner follows redirect or DNS to out-of-scope network
            if (RE_BKH_005_UNSCOPED_REDIRECT.is_match(trimmed)
                || pattern_starts_here(
                    &RE_BKH_005_UNSCOPED_REDIRECT,
                    &context_window,
                    current_start,
                    current_end,
                ))
                && !RE_BKH_005_GUARD.is_match(&context_window)
            {
                Self::push_finding(
                    &mut findings,
                    &mut seen,
                    "BK-AI-BKH-005",
                    &["CWE-918"],
                    "DAST scanner follows redirect or DNS to out-of-scope network",
                    Severity::Critical,
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Validate every redirection target against explicit in-scope CIDR ranges before issuing requests",
                    "Dynamic scanner follows HTTP redirects or resolves hostnames without verifying that target IP/domain lies within authorized CIDR boundary.",
                    "Validate per-hop redirection targets against allowed CIDR and domain scope allowlists, failing closed on external networks.",
                );
            }

            // 6. BK-AI-BKH-006 (CWE-250): External scanner tool/plugin inherits host secrets or admin credentials
            if (RE_BKH_006_INHERIT_SECRETS.is_match(trimmed)
                || pattern_starts_here(
                    &RE_BKH_006_INHERIT_SECRETS,
                    &context_window,
                    current_start,
                    current_end,
                ))
                && !RE_BKH_006_GUARD.is_match(&context_window)
            {
                Self::push_finding(
                    &mut findings,
                    &mut seen,
                    "BK-AI-BKH-006",
                    &["CWE-250"],
                    "External scanner tool/plugin inherits host secrets or admin credentials",
                    Severity::High,
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Clear host environment variables and strip all secrets before launching child scanner processes",
                    "Subprocess scanner or external tool inherits host environment variables (including API keys and credentials) or executes with root privileges.",
                    "Sanitize child process environment variables with env_clear() and run external plugins with dropped unprivileged credentials.",
                );
            }

            // 7. BK-AI-BKH-007 (CWE-532): Security report leaks credentials, environment or response body
            if (RE_BKH_007_REPORT_LEAKS_CREDS.is_match(trimmed)
                || pattern_starts_here(
                    &RE_BKH_007_REPORT_LEAKS_CREDS,
                    &context_window,
                    current_start,
                    current_end,
                ))
                && !RE_BKH_007_GUARD.is_match(&context_window)
            {
                Self::push_finding(
                    &mut findings,
                    &mut seen,
                    "BK-AI-BKH-007",
                    &["CWE-532"],
                    "Security report leaks credentials, environment or response body",
                    Severity::High,
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Redact all authorization tokens, passwords, and sensitive keys from report outputs",
                    "Generated security report contains unredacted credentials, authorization tokens, ambient environment dumps, or sensitive raw response payloads.",
                    "Apply strict evidence redaction masking bearer tokens, API keys, and sensitive environment variables in report artifacts.",
                );
            }

            // 8. BK-AI-BKH-008 (CWE-22): Auto-fix edits wrong file because matching by basename or ambiguous path
            if (RE_BKH_008_BASENAME_MATCH.is_match(trimmed)
                || pattern_starts_here(
                    &RE_BKH_008_BASENAME_MATCH,
                    &context_window,
                    current_start,
                    current_end,
                ))
                && !RE_BKH_008_GUARD.is_match(&context_window)
            {
                Self::push_finding(
                    &mut findings,
                    &mut seen,
                    "BK-AI-BKH-008",
                    &["CWE-22", "CWE-73"],
                    "Auto-fix edits wrong file because matching by basename or ambiguous path",
                    Severity::High,
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Resolve file targets strictly through canonicalized workspace-relative paths",
                    "Autonomous healer resolves target file to modify by its basename rather than its canonical path, risking edits to unintended files.",
                    "Always resolve and validate canonical target paths within the workspace root before applying file modifications.",
                );
            }

            // 9. BK-AI-BKH-009 (CWE-284): Healing changes unapproved file, service or cloud asset
            if (RE_BKH_009_UNAPPROVED_MUTATION.is_match(trimmed)
                || pattern_starts_here(
                    &RE_BKH_009_UNAPPROVED_MUTATION,
                    &context_window,
                    current_start,
                    current_end,
                ))
                && !RE_BKH_009_GUARD.is_match(&context_window)
            {
                Self::push_finding(
                    &mut findings,
                    &mut seen,
                    "BK-AI-BKH-009",
                    &["CWE-284", "CWE-862"],
                    "Healing changes unapproved file, service or cloud asset",
                    Severity::Critical,
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Verify target file canonical path strictly resides inside authorized workspace boundary",
                    "Healer applies modifications to files, services, or assets outside the approved repository workspace boundaries or target list.",
                    "Assert that target file canonical path starts with workspace root and matches approved targets before modifying disk state.",
                );
            }

            // 10. BK-AI-BKH-010 (CWE-345): Backup not independently authenticated or restorable
            if (RE_BKH_010_UNAUTHENTICATED_BACKUP.is_match(trimmed)
                || pattern_starts_here(
                    &RE_BKH_010_UNAUTHENTICATED_BACKUP,
                    &context_window,
                    current_start,
                    current_end,
                ))
                && !RE_BKH_010_GUARD.is_match(&context_window)
            {
                Self::push_finding(
                    &mut findings,
                    &mut seen,
                    "BK-AI-BKH-010",
                    &["CWE-345"],
                    "Backup not independently authenticated or restorable",
                    Severity::High,
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Cryptographically sign backup manifest with Ed25519 and verify restorable digest",
                    "Pre-healing backup manifest is created without cryptographic signature or restorable verification checks.",
                    "Sign all backup manifests cryptographically (Ed25519) and verify restorable integrity before executing any virtual patch.",
                );
            }

            // 11. BK-AI-BKH-011 (CWE-693): Multi-file healing fails halfway without coherent rollback/state receipt
            if (RE_BKH_011_NO_BATCH_ROLLBACK.is_match(trimmed)
                || pattern_starts_here(
                    &RE_BKH_011_NO_BATCH_ROLLBACK,
                    &context_window,
                    current_start,
                    current_end,
                ))
                && !RE_BKH_011_GUARD.is_match(&context_window)
            {
                Self::push_finding(
                    &mut findings,
                    &mut seen,
                    "BK-AI-BKH-011",
                    &["CWE-693", "CWE-662"],
                    "Multi-file healing fails halfway without coherent rollback/state receipt",
                    Severity::High,
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Roll back all previously modified files atomically upon any error during multi-file healing",
                    "Batch healing modifies multiple files in sequence but fails mid-process without executing transactional rollback to restore original workspace state.",
                    "Implement transactional atomic rollback across all batch-modified files when an error occurs during multi-file patching.",
                );
            }

            // 12. BK-AI-BKH-012 (CWE-693): Agent merges or releases a fix despite failing/skipped required tests
            if (RE_BKH_012_MERGE_WITHOUT_TESTS.is_match(trimmed)
                || pattern_starts_here(
                    &RE_BKH_012_MERGE_WITHOUT_TESTS,
                    &context_window,
                    current_start,
                    current_end,
                ))
                && !RE_BKH_012_GUARD.is_match(&context_window)
            {
                Self::push_finding(
                    &mut findings,
                    &mut seen,
                    "BK-AI-BKH-012",
                    &["CWE-693"],
                    "Agent merges or releases a fix despite failing/skipped required tests",
                    Severity::Critical,
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Require all test suites and verification gates to be green prior to pushing or merging fixes",
                    "Remediation agent bypasses verification by using --no-verify, ignoring test failures, or auto-merging while test suites are red.",
                    "Enforce strict verification gates blocking git push or PR merge if any required test or quality gate has failed or been skipped.",
                );
            }

            // 13. BK-AI-BKH-013 (CWE-1059): Exclusion/suppression never expires or hides entire directory silently
            if (RE_BKH_013_UNBOUNDED_SUPPRESSION.is_match(trimmed)
                || pattern_starts_here(
                    &RE_BKH_013_UNBOUNDED_SUPPRESSION,
                    &context_window,
                    current_start,
                    current_end,
                ))
                && !RE_BKH_013_GUARD.is_match(&context_window)
            {
                Self::push_finding(
                    &mut findings,
                    &mut seen,
                    "BK-AI-BKH-013",
                    &["CWE-1059"],
                    "Exclusion/suppression never expires or hides entire directory silently",
                    Severity::Medium,
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Enforce explicit expiration dates and specific rule IDs for all suppression directives",
                    "Security finding suppression rule uses unbounded wildcards or omits expiration date and justification, silently blinding scanning.",
                    "Require an explicit expiration date (expires_at), specific rule ID, and documented business justification for every suppression.",
                );
            }

            // 14. BK-AI-BKH-014 (CWE-1059): Scanner's source-to-sink claim is only a regex keyword hit
            if (RE_BKH_014_REGEX_TAINT_CLAIM.is_match(trimmed)
                || pattern_starts_here(
                    &RE_BKH_014_REGEX_TAINT_CLAIM,
                    &context_window,
                    current_start,
                    current_end,
                ))
                && !RE_BKH_014_GUARD.is_match(&context_window)
            {
                Self::push_finding(
                    &mut findings,
                    &mut seen,
                    "BK-AI-BKH-014",
                    &["CWE-1059"],
                    "Scanner's source-to-sink claim is only a regex keyword hit",
                    Severity::High,
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Do not claim confirmed reachability from regex matches alone; require AST data flow verification",
                    "Static scanner claims confirmed source-to-sink taint reachability based solely on regex pattern match without AST data-flow proof.",
                    "Downgrade reachability to PotentiallyReachable or Indicator unless verified by full AST control and data flow graph analysis.",
                );
            }

            // 15. BK-AI-BKH-015 (CWE-1059): CI checks Rust crate but skips Go services, nested Cargo workspace or installer
            if (RE_BKH_015_CI_SKIPS_SERVICES.is_match(trimmed)
                || pattern_starts_here(
                    &RE_BKH_015_CI_SKIPS_SERVICES,
                    &context_window,
                    current_start,
                    current_end,
                ))
                && !RE_BKH_015_GUARD.is_match(&context_window)
            {
                Self::push_finding(
                    &mut findings,
                    &mut seen,
                    "BK-AI-BKH-015",
                    &["CWE-1059"],
                    "CI checks Rust crate but skips Go services, nested Cargo workspace or installer",
                    Severity::Medium,
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Execute test suites across all repository workspaces and Go microservices in CI matrix",
                    "CI pipeline executes test suite for root Rust package while omitting or skipping Go microservices (services/orchestrator, services/healer).",
                    "Include comprehensive component test matrix running both cargo test and go test across all repository services and workspaces.",
                );
            }

            // 16. BK-AI-BKH-016 (CWE-770): Remote target scan begins without asset authorization and rate/egress budgets
            if (RE_BKH_016_UNAUTHORIZED_UNRATED_SCAN.is_match(trimmed)
                || pattern_starts_here(
                    &RE_BKH_016_UNAUTHORIZED_UNRATED_SCAN,
                    &context_window,
                    current_start,
                    current_end,
                ))
                && !RE_BKH_016_GUARD.is_match(&context_window)
            {
                Self::push_finding(
                    &mut findings,
                    &mut seen,
                    "BK-AI-BKH-016",
                    &["CWE-770", "CWE-284"],
                    "Remote target scan begins without asset authorization and rate/egress budgets",
                    Severity::High,
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Validate asset ownership authorization and apply rate limiting budgets prior to external scanning",
                    "DAST or network security scanner initiates external scans without verified asset authorization tokens or request rate budgets.",
                    "Enforce asset ownership verification and token-bucket rate limiting before dispatching external security scan probes.",
                );
            }

            // 17. BK-AI-BKH-017 (CWE-362): Parallel healers race on same manifest/config, overwriting each other's changes
            if (RE_BKH_017_RACING_HEALERS.is_match(trimmed)
                || pattern_starts_here(
                    &RE_BKH_017_RACING_HEALERS,
                    &context_window,
                    current_start,
                    current_end,
                ))
                && !RE_BKH_017_GUARD.is_match(&context_window)
            {
                Self::push_finding(
                    &mut findings,
                    &mut seen,
                    "BK-AI-BKH-017",
                    &["CWE-362"],
                    "Parallel healers race on same manifest/config, overwriting each other's changes",
                    Severity::High,
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Acquire exclusive file lock or mutex before mutating shared manifest or config files",
                    "Multiple concurrent healer threads or processes mutate shared manifest or configuration files without advisory or mutex file locks.",
                    "Acquire exclusive file locks (FileLock / flock / Mutex) before reading, updating, or writing shared manifest files.",
                );
            }

            // 18. BK-AI-BKH-018 (CWE-1059): Public README claims support for checks not implemented, validated or enabled
            if (RE_BKH_018_UNVERIFIED_CLAIM.is_match(trimmed)
                || pattern_starts_here(
                    &RE_BKH_018_UNVERIFIED_CLAIM,
                    &context_window,
                    current_start,
                    current_end,
                ))
                && !RE_BKH_018_GUARD.is_match(&context_window)
            {
                Self::push_finding(
                    &mut findings,
                    &mut seen,
                    "BK-AI-BKH-018",
                    &["CWE-1059"],
                    "Public README claims support for checks not implemented, validated or enabled",
                    Severity::Medium,
                    path,
                    &target_kind,
                    line_no,
                    trimmed,
                    "Only claim supported status for security rules backed by active detectors and passing tests",
                    "Public documentation or README advertises a detector or security check as supported or production ready when it is a stub or unimplemented.",
                    "Synchronize public documentation with active detector implementations and mark unimplemented rules as Planned or In Development.",
                );
            }
        }

        findings
    }

    #[allow(clippy::too_many_arguments)]
    fn push_finding(
        findings: &mut Vec<Finding>,
        seen: &mut HashSet<(&'static str, usize)>,
        rule_id: &'static str,
        cwes: &[&str],
        title: &str,
        severity: Severity,
        path: &Path,
        target_kind: &TargetKind,
        line_no: usize,
        snippet: &str,
        safe_threshold: &str,
        description: &str,
        remediation: &str,
    ) {
        if !seen.insert((rule_id, line_no)) {
            return;
        }

        let file_tag = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("source");
        let short_id = rule_id.trim_start_matches("BK-AI-");
        let finding_id = format!("{}-{}-L{}", short_id, file_tag, line_no);

        let mut finding = Finding::new(
            finding_id,
            CveId::Custom {
                id: rule_id.to_string(),
                title: title.to_string(),
            },
            severity,
            target_kind.clone(),
            Some(path.to_path_buf()),
            Some(line_no),
            snippet,
            safe_threshold,
            description,
            remediation,
        );
        finding.detector_id = "bkh-safety".to_string();
        finding.detector_version = "1.0.0".to_string();
        finding.category = CATEGORY_BKH.to_string();
        finding.affectedness = Affectedness::ConfirmedAffected;
        finding.reachability = Reachability::PotentiallyReachable;
        finding.confidence = Confidence::High;
        finding.evidence_certainty = EvidenceCertainty::StronglySupported;
        let mut advisory_ids: Vec<String> = cwes.iter().map(|c| c.to_string()).collect();
        advisory_ids.push(rule_id.to_string());
        finding.advisory_ids = advisory_ids;
        finding.evidence_refs.push(EvidenceRef {
            location: format!("{}:{}", path.display(), line_no),
            line_number: Some(line_no),
            snippet: Some(snippet.trim().to_string()),
            sha256: None,
        });
        finding.compute_dedupe_fingerprint();
        findings.push(finding);
    }
}
