# Print an optspec for argparse to handle cmd's options that are independent of any subcommand.
function __fish_bug_killer_global_optspecs
    string join \n h/help V/version
end

function __fish_bug_killer_needs_command
    # Figure out if the current invocation already has a command.
    set -l cmd (commandline -opc)
    set -e cmd[1]
    argparse -s (__fish_bug_killer_global_optspecs) -- $cmd 2>/dev/null
    or return
    if set -q argv[1]
        # Also print the command, so this can be used to figure out what it is.
        echo $argv[1]
        return 1
    end
    return 0
end

function __fish_bug_killer_using_subcommand
    set -l cmd (__fish_bug_killer_needs_command)
    test -z "$cmd"
    and return 1
    contains -- $cmd[1] $argv
end

complete -c bug-killer -n "__fish_bug_killer_needs_command" -s h -l help -d 'Print help'
complete -c bug-killer -n "__fish_bug_killer_needs_command" -s V -l version -d 'Print version'
complete -c bug-killer -n "__fish_bug_killer_needs_command" -f -a "shell" -d 'Launch the interactive Bug Killer REPL shell'
complete -c bug-killer -n "__fish_bug_killer_needs_command" -f -a "doctor" -d 'Run diagnostic system and environment health audit'
complete -c bug-killer -n "__fish_bug_killer_needs_command" -f -a "watch" -d 'Start live surveillance monitoring filesystem for security regressions'
complete -c bug-killer -n "__fish_bug_killer_needs_command" -f -a "completion" -d 'Generate shell auto-completion script for bash, zsh, fish, or powershell'
complete -c bug-killer -n "__fish_bug_killer_needs_command" -f -a "scan" -d 'Scan target directories and systems for PHP2Shell (CVE-2026-109618, CVE-2026-109619) and Node2Shell (CVE-2026-111497)'
complete -c bug-killer -n "__fish_bug_killer_needs_command" -f -a "probe" -d 'Defensively probe a live web application endpoint for security posture, headers, and disclosures'
complete -c bug-killer -n "__fish_bug_killer_needs_command" -f -a "osv" -d 'Query open-source vulnerability database (https://osv.dev) for dependencies across npm, Packagist, PyPI, and crates.io'
complete -c bug-killer -n "__fish_bug_killer_needs_command" -f -a "heal" -d 'Plan and automatically heal vulnerable configurations, Dockerfiles, manifests, and web servers'
complete -c bug-killer -n "__fish_bug_killer_needs_command" -f -a "rollback" -d 'Roll back an applied healing session using a backup ID'
complete -c bug-killer -n "__fish_bug_killer_needs_command" -f -a "history" -d 'List all healing snapshots and backups'
complete -c bug-killer -n "__fish_bug_killer_needs_command" -f -a "cve-info" -d 'Display deep technical teardown and remediation blueprint for a specific CVE'
complete -c bug-killer -n "__fish_bug_killer_needs_command" -f -a "agent" -d 'Model-agnostic AI agent investigation and capability diagnostics'
complete -c bug-killer -n "__fish_bug_killer_needs_command" -f -a "evidence" -d 'Retrieve full evidence receipts and cryptographic hashes for a specific finding'
complete -c bug-killer -n "__fish_bug_killer_needs_command" -f -a "plan" -d 'Plan a prospective, non-mutating repair for a finding with cryptographic diff hash'
complete -c bug-killer -n "__fish_bug_killer_needs_command" -f -a "approve" -d 'Issue an operator approval receipt for a planned remediation'
complete -c bug-killer -n "__fish_bug_killer_needs_command" -f -a "operator-public-key" -d 'Display the public key derived from a separately provisioned operator signing key'
complete -c bug-killer -n "__fish_bug_killer_needs_command" -f -a "apply" -d 'Apply an approved prospective remediation plan with operator approval verification'
complete -c bug-killer -n "__fish_bug_killer_needs_command" -f -a "mcp" -d 'Model Context Protocol (MCP) server and integration commands'
complete -c bug-killer -n "__fish_bug_killer_needs_command" -f -a "init" -d 'Initialize Bug Killer in a project, create security configuration, and run baseline scan'
complete -c bug-killer -n "__fish_bug_killer_needs_command" -f -a "security" -d 'Bug Killer Security Guard suite (scan, status, explain, fix, verify, guidance, catalog)'
complete -c bug-killer -n "__fish_bug_killer_needs_command" -f -a "engine" -d 'Sibling & external tool capability broker (doctor, list, explain)'
complete -c bug-killer -n "__fish_bug_killer_needs_command" -f -a "room" -d 'Agentic Security Operations Room (plan, status, evidence)'
complete -c bug-killer -n "__fish_bug_killer_needs_command" -f -a "hunter" -d 'Novel vulnerability hunter & bounded research runner (plan, run, candidate, verify)'
complete -c bug-killer -n "__fish_bug_killer_needs_command" -f -a "hunt" -d 'Autonomous novel vulnerability hunter on target project (full end-to-end research loop)'
complete -c bug-killer -n "__fish_bug_killer_needs_command" -f -a "disclose" -d 'Responsible private disclosure & PVR draft generation (draft)'
complete -c bug-killer -n "__fish_bug_killer_needs_command" -f -a "advisory" -d 'Advisory feeds & dependency vulnerability cache (sync, status)'
complete -c bug-killer -n "__fish_bug_killer_needs_command" -f -a "inventory" -d 'Software asset inventory & CycloneDX / JSON SBOM extraction'
complete -c bug-killer -n "__fish_bug_killer_needs_command" -f -a "deepsec" -d 'DeepSec: Agent-Powered Security Review Harness'
complete -c bug-killer -n "__fish_bug_killer_needs_command" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand shell" -s h -l help -d 'Print help'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand doctor" -l json -d 'Output diagnostic report as JSON'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand doctor" -s h -l help -d 'Print help'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand watch" -s i -l interval -d 'Surveillance polling interval in seconds (default: 3)' -r
complete -c bug-killer -n "__fish_bug_killer_using_subcommand watch" -l rules -d 'Custom path to rules directory or JSON rule file' -r -F
complete -c bug-killer -n "__fish_bug_killer_using_subcommand watch" -l auto-heal -d 'Automatically apply safe healing patches upon detecting vulnerabilities'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand watch" -s h -l help -d 'Print help'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand completion" -s h -l help -d 'Print help'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand scan" -l rules -d 'Custom path to rules directory or JSON rule file' -r -F
complete -c bug-killer -n "__fish_bug_killer_using_subcommand scan" -l json -d 'Output results as JSON'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand scan" -l check-runtime -d 'Also inspect host binary runtimes (php, node) on PATH'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand scan" -l osv -d 'Also query free open vulnerability database (OSV.dev) for dependencies'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand scan" -l taint -d 'Also perform scope-aware taint analysis on source code'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand scan" -s h -l help -d 'Print help'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand probe" -s t -l timeout -d 'Request timeout in seconds (default: 10)' -r
complete -c bug-killer -n "__fish_bug_killer_using_subcommand probe" -l json -d 'Output diagnostic probe report as JSON'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand probe" -l sensitive-paths -d 'Allow probing sensitive endpoints (/.env, /.git/HEAD) on authorized local targets (default: false)'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand probe" -l authorized -d 'Confirm you have permission to probe the exact target URL and host'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand probe" -l allow-private-targets -d 'Include internal/private IP destinations for the explicitly authorized host'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand probe" -s h -l help -d 'Print help'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand osv" -l json -d 'Output results as JSON'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand osv" -s h -l help -d 'Print help'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand heal" -l rules -d 'Custom path to rules directory or JSON rule file' -r -F
complete -c bug-killer -n "__fish_bug_killer_using_subcommand heal" -l dry-run -d 'Show planned patches and diffs without modifying files'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand heal" -l apply -d 'Deprecated unsafe shortcut; rejected in favor of operator-signed approval'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand heal" -l auto-apply -d 'Deprecated unsafe shortcut; rejected in favor of operator-signed approval'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand heal" -l osv -d 'Include OSV open vulnerability database findings in healing'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand heal" -l allow-untrusted-rules -d 'Allow untrusted workspace dynamic rules to be planned and auto-applied'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand heal" -s h -l help -d 'Print help'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand rollback" -s h -l help -d 'Print help'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand history" -s h -l help -d 'Print help'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand cve-info" -s h -l help -d 'Print help'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand agent; and not __fish_seen_subcommand_from doctor investigate help" -s h -l help -d 'Print help'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand agent; and not __fish_seen_subcommand_from doctor investigate help" -f -a "doctor" -d 'Inspect configured model provider capability and health without leaking secrets'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand agent; and not __fish_seen_subcommand_from doctor investigate help" -f -a "investigate" -d 'Run bounded read-only autonomous investigation loop over target workspace'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand agent; and not __fish_seen_subcommand_from doctor investigate help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand agent; and __fish_seen_subcommand_from doctor" -l provider -d 'Provider name (local, openai, deepseek, kimi, minimax, claude, gemini, ollama)' -r
complete -c bug-killer -n "__fish_bug_killer_using_subcommand agent; and __fish_seen_subcommand_from doctor" -l json -d 'Output results as JSON'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand agent; and __fish_seen_subcommand_from doctor" -s h -l help -d 'Print help'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand agent; and __fish_seen_subcommand_from investigate" -l provider -d 'Provider name (local, deepseek, kimi, minimax, claude, gemini, openai, ollama)' -r
complete -c bug-killer -n "__fish_bug_killer_using_subcommand agent; and __fish_seen_subcommand_from investigate" -l model -d 'Model identifier override (e.g. deepseek-chat, gpt-4o, llama3.3)' -r
complete -c bug-killer -n "__fish_bug_killer_using_subcommand agent; and __fish_seen_subcommand_from investigate" -l mode -d 'Execution mode (strictly read-only)' -r
complete -c bug-killer -n "__fish_bug_killer_using_subcommand agent; and __fish_seen_subcommand_from investigate" -l max-steps -d 'Maximum investigation steps before terminal halt (default: 24)' -r
complete -c bug-killer -n "__fish_bug_killer_using_subcommand agent; and __fish_seen_subcommand_from investigate" -l export-profile -d 'Approved export profile name for remote providers (required if allow_remote_data_export is true)' -r
complete -c bug-killer -n "__fish_bug_killer_using_subcommand agent; and __fish_seen_subcommand_from investigate" -l json -d 'Output results as JSON'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand agent; and __fish_seen_subcommand_from investigate" -s h -l help -d 'Print help'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand agent; and __fish_seen_subcommand_from help" -f -a "doctor" -d 'Inspect configured model provider capability and health without leaking secrets'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand agent; and __fish_seen_subcommand_from help" -f -a "investigate" -d 'Run bounded read-only autonomous investigation loop over target workspace'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand agent; and __fish_seen_subcommand_from help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand evidence" -l json -d 'Output results as JSON'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand evidence" -s h -l help -d 'Print help'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand plan" -l json -d 'Output results as JSON'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand plan" -s h -l help -d 'Print help'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand approve" -l approver -d 'Operator email or identity key' -r
complete -c bug-killer -n "__fish_bug_killer_using_subcommand approve" -l validity-mins -d 'Validity duration in minutes (default: 60)' -r
complete -c bug-killer -n "__fish_bug_killer_using_subcommand approve" -l json -d 'Output results as JSON'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand approve" -s h -l help -d 'Print help'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand operator-public-key" -s h -l help -d 'Print help'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand apply" -l approval-file -d 'Explicit path to operator approval receipt file' -r -F
complete -c bug-killer -n "__fish_bug_killer_using_subcommand apply" -s h -l help -d 'Print help'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand mcp; and not __fish_seen_subcommand_from serve config help" -s h -l help -d 'Print help'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand mcp; and not __fish_seen_subcommand_from serve config help" -f -a "serve" -d 'Run the stdio MCP server for external agent integration'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand mcp; and not __fish_seen_subcommand_from serve config help" -f -a "config" -d 'Generate copy-pasteable MCP server configuration snippets for external coding agents'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand mcp; and not __fish_seen_subcommand_from serve config help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand mcp; and __fish_seen_subcommand_from serve" -l transport -d 'Transport protocol (stdio)' -r
complete -c bug-killer -n "__fish_bug_killer_using_subcommand mcp; and __fish_seen_subcommand_from serve" -l read-only -d 'Run in strictly read-only mode prohibiting state mutations (default: true)'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand mcp; and __fish_seen_subcommand_from serve" -s h -l help -d 'Print help'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand mcp; and __fish_seen_subcommand_from config" -l host -d 'Target host agent (claude, codex, gemini, all)' -r
complete -c bug-killer -n "__fish_bug_killer_using_subcommand mcp; and __fish_seen_subcommand_from config" -l binary -d 'Custom path to bug-killer binary' -r
complete -c bug-killer -n "__fish_bug_killer_using_subcommand mcp; and __fish_seen_subcommand_from config" -s h -l help -d 'Print help'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand mcp; and __fish_seen_subcommand_from help" -f -a "serve" -d 'Run the stdio MCP server for external agent integration'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand mcp; and __fish_seen_subcommand_from help" -f -a "config" -d 'Generate copy-pasteable MCP server configuration snippets for external coding agents'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand mcp; and __fish_seen_subcommand_from help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand init" -l hooks -d 'Install Git pre-commit security hook (default: true)' -r -f -a "true\t''
false\t''"
complete -c bug-killer -n "__fish_bug_killer_using_subcommand init" -l json -d 'Output results as JSON'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand init" -s h -l help -d 'Print help'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand security; and not __fish_seen_subcommand_from scan coverage status explain fix verify guidance catalog help" -s h -l help -d 'Print help'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand security; and not __fish_seen_subcommand_from scan coverage status explain fix verify guidance catalog help" -f -a "scan" -d 'Execute security guard scan across all applicable catalog rules'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand security; and not __fish_seen_subcommand_from scan coverage status explain fix verify guidance catalog help" -f -a "coverage" -d 'Inspect workspace rule-target coverage receipts and unassessed gaps'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand security; and not __fish_seen_subcommand_from scan coverage status explain fix verify guidance catalog help" -f -a "status" -d 'Show current workspace security guard status and baseline findings'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand security; and not __fish_seen_subcommand_from scan coverage status explain fix verify guidance catalog help" -f -a "explain" -d 'Explain a finding using the 373-rule AI-Generated Code Security Catalog'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand security; and not __fish_seen_subcommand_from scan coverage status explain fix verify guidance catalog help" -f -a "fix" -d 'Propose or apply an authorized bounded security repair'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand security; and not __fish_seen_subcommand_from scan coverage status explain fix verify guidance catalog help" -f -a "verify" -d 'Independently verify workspace security status and coverage completeness'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand security; and not __fish_seen_subcommand_from scan coverage status explain fix verify guidance catalog help" -f -a "guidance" -d 'Generate pre-generation security guidance for a coding task'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand security; and not __fish_seen_subcommand_from scan coverage status explain fix verify guidance catalog help" -f -a "catalog" -d 'Query or browse the 373-rule AI-Generated Code Security Issues Catalog'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand security; and not __fish_seen_subcommand_from scan coverage status explain fix verify guidance catalog help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand security; and __fish_seen_subcommand_from scan" -l profile -d 'Scan profile (quick, project, ci, deep; default: quick)' -r -f -a "quick\t''
project\t''
ci\t''
deep\t''"
complete -c bug-killer -n "__fish_bug_killer_using_subcommand security; and __fish_seen_subcommand_from scan" -l fail-on -d 'Exit with code 1 for findings at or above this severity' -r -f -a "critical\t''
high\t''
medium\t''
low\t''"
complete -c bug-killer -n "__fish_bug_killer_using_subcommand security; and __fish_seen_subcommand_from scan" -l report-version -d 'Machine-readable report contract version (1 or 2)' -r -f -a "1\t''
2\t''"
complete -c bug-killer -n "__fish_bug_killer_using_subcommand security; and __fish_seen_subcommand_from scan" -l exit-contract -d 'Machine-readable exit-code contract version (v1 or v2)' -r -f -a "v1\t''
v2\t''"
complete -c bug-killer -n "__fish_bug_killer_using_subcommand security; and __fish_seen_subcommand_from scan" -l engine -d 'Optional comma-separated list of specific engines to execute' -r
complete -c bug-killer -n "__fish_bug_killer_using_subcommand security; and __fish_seen_subcommand_from scan" -l changed-only -d 'Scan only git-changed / staged files'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand security; and __fish_seen_subcommand_from scan" -l staged -d 'Scan the exact staged Git index snapshot (for pre-commit enforcement)'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand security; and __fish_seen_subcommand_from scan" -l osv -d 'Also query free open vulnerability database (OSV.dev)'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand security; and __fish_seen_subcommand_from scan" -l json -d 'Output results as JSON'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand security; and __fish_seen_subcommand_from scan" -s h -l help -d 'Print help'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand security; and __fish_seen_subcommand_from coverage" -l per-rule -d 'Report exact per-rule evaluation status'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand security; and __fish_seen_subcommand_from coverage" -l json -d 'Output results as JSON'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand security; and __fish_seen_subcommand_from coverage" -s h -l help -d 'Print help'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand security; and __fish_seen_subcommand_from status" -l json -d 'Output results as JSON'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand security; and __fish_seen_subcommand_from status" -s h -l help -d 'Print help'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand security; and __fish_seen_subcommand_from explain" -l json -d 'Output results as JSON'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand security; and __fish_seen_subcommand_from explain" -s h -l help -d 'Print help'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand security; and __fish_seen_subcommand_from fix" -l receipt -d 'Optional operator approval receipt token (required for Level 3 fixes)' -r
complete -c bug-killer -n "__fish_bug_killer_using_subcommand security; and __fish_seen_subcommand_from fix" -l plan -d 'Generate repair proposal and diff preview without modifying files'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand security; and __fish_seen_subcommand_from fix" -l apply -d 'Apply authorized repair with atomic Ed25519 backup and verification'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand security; and __fish_seen_subcommand_from fix" -l json -d 'Output results as JSON'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand security; and __fish_seen_subcommand_from fix" -s h -l help -d 'Print help'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand security; and __fish_seen_subcommand_from verify" -l json -d 'Output results as JSON'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand security; and __fish_seen_subcommand_from verify" -s h -l help -d 'Print help'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand security; and __fish_seen_subcommand_from guidance" -l language -d 'Target programming language' -r
complete -c bug-killer -n "__fish_bug_killer_using_subcommand security; and __fish_seen_subcommand_from guidance" -l json -d 'Output results as JSON'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand security; and __fish_seen_subcommand_from guidance" -s h -l help -d 'Print help'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand security; and __fish_seen_subcommand_from catalog" -l category -d 'Filter by category number (1 to 27)' -r
complete -c bug-killer -n "__fish_bug_killer_using_subcommand security; and __fish_seen_subcommand_from catalog" -l status -d 'Filter by rule lifecycle status (cataloged, supported_static, review_required, etc.)' -r
complete -c bug-killer -n "__fish_bug_killer_using_subcommand security; and __fish_seen_subcommand_from catalog" -l json -d 'Output results as JSON'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand security; and __fish_seen_subcommand_from catalog" -s h -l help -d 'Print help'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand security; and __fish_seen_subcommand_from help" -f -a "scan" -d 'Execute security guard scan across all applicable catalog rules'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand security; and __fish_seen_subcommand_from help" -f -a "coverage" -d 'Inspect workspace rule-target coverage receipts and unassessed gaps'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand security; and __fish_seen_subcommand_from help" -f -a "status" -d 'Show current workspace security guard status and baseline findings'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand security; and __fish_seen_subcommand_from help" -f -a "explain" -d 'Explain a finding using the 373-rule AI-Generated Code Security Catalog'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand security; and __fish_seen_subcommand_from help" -f -a "fix" -d 'Propose or apply an authorized bounded security repair'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand security; and __fish_seen_subcommand_from help" -f -a "verify" -d 'Independently verify workspace security status and coverage completeness'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand security; and __fish_seen_subcommand_from help" -f -a "guidance" -d 'Generate pre-generation security guidance for a coding task'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand security; and __fish_seen_subcommand_from help" -f -a "catalog" -d 'Query or browse the 373-rule AI-Generated Code Security Issues Catalog'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand security; and __fish_seen_subcommand_from help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand engine; and not __fish_seen_subcommand_from doctor list explain skills help" -s h -l help -d 'Print help'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand engine; and not __fish_seen_subcommand_from doctor list explain skills help" -f -a "doctor" -d 'Check health, versions, and installation status of sibling security engines'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand engine; and not __fish_seen_subcommand_from doctor list explain skills help" -f -a "list" -d 'List all registered sibling tool capabilities and execution transports'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand engine; and not __fish_seen_subcommand_from doctor list explain skills help" -f -a "explain" -d 'Explain which security tools match a specified goal (known, prevention, research)'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand engine; and not __fish_seen_subcommand_from doctor list explain skills help" -f -a "skills" -d 'Query, inspect, and recommend deep cybersecurity skills and MITRE/NIST mappings'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand engine; and not __fish_seen_subcommand_from doctor list explain skills help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand engine; and __fish_seen_subcommand_from doctor" -l json -d 'Output results as JSON'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand engine; and __fish_seen_subcommand_from doctor" -s h -l help -d 'Print help'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand engine; and __fish_seen_subcommand_from list" -l json -d 'Output results as JSON'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand engine; and __fish_seen_subcommand_from list" -s h -l help -d 'Print help'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand engine; and __fish_seen_subcommand_from explain" -l goal -d 'Mission goal: known, prevention, or research' -r
complete -c bug-killer -n "__fish_bug_killer_using_subcommand engine; and __fish_seen_subcommand_from explain" -l target -d 'Target directory path (default: current directory)' -r -F
complete -c bug-killer -n "__fish_bug_killer_using_subcommand engine; and __fish_seen_subcommand_from explain" -l json -d 'Output results as JSON'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand engine; and __fish_seen_subcommand_from explain" -s h -l help -d 'Print help'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand engine; and __fish_seen_subcommand_from skills" -l filter -d 'Filter by subdomain, tag, or MITRE technique ID' -r
complete -c bug-killer -n "__fish_bug_killer_using_subcommand engine; and __fish_seen_subcommand_from skills" -l id -d 'Skill identifier for \'show\' action' -r
complete -c bug-killer -n "__fish_bug_killer_using_subcommand engine; and __fish_seen_subcommand_from skills" -l cve -d 'Target CVE ID or mission goal for \'recommend\' action' -r
complete -c bug-killer -n "__fish_bug_killer_using_subcommand engine; and __fish_seen_subcommand_from skills" -l query -d 'Query string for \'search\' action' -r
complete -c bug-killer -n "__fish_bug_killer_using_subcommand engine; and __fish_seen_subcommand_from skills" -l limit -d 'Maximum results to display (default: 25)' -r
complete -c bug-killer -n "__fish_bug_killer_using_subcommand engine; and __fish_seen_subcommand_from skills" -l json -d 'Output results as JSON'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand engine; and __fish_seen_subcommand_from skills" -s h -l help -d 'Print help'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand engine; and __fish_seen_subcommand_from help" -f -a "doctor" -d 'Check health, versions, and installation status of sibling security engines'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand engine; and __fish_seen_subcommand_from help" -f -a "list" -d 'List all registered sibling tool capabilities and execution transports'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand engine; and __fish_seen_subcommand_from help" -f -a "explain" -d 'Explain which security tools match a specified goal (known, prevention, research)'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand engine; and __fish_seen_subcommand_from help" -f -a "skills" -d 'Query, inspect, and recommend deep cybersecurity skills and MITRE/NIST mappings'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand engine; and __fish_seen_subcommand_from help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand room; and not __fish_seen_subcommand_from plan status evidence help" -s h -l help -d 'Print help'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand room; and not __fish_seen_subcommand_from plan status evidence help" -f -a "plan" -d 'Plan an operations room security run across matching tools'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand room; and not __fish_seen_subcommand_from plan status evidence help" -f -a "status" -d 'Inspect terminal state and per-tool execution receipts of a room run'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand room; and not __fish_seen_subcommand_from plan status evidence help" -f -a "evidence" -d 'Correlate multi-engine evidence and coverage ledger'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand room; and not __fish_seen_subcommand_from plan status evidence help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand room; and __fish_seen_subcommand_from plan" -l goal -d 'Mission goal: known, prevention, or research' -r
complete -c bug-killer -n "__fish_bug_killer_using_subcommand room; and __fish_seen_subcommand_from plan" -l profile -d 'Execution profile: quick, project, ci, or deep' -r
complete -c bug-killer -n "__fish_bug_killer_using_subcommand room; and __fish_seen_subcommand_from plan" -l json -d 'Output plan as JSON'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand room; and __fish_seen_subcommand_from plan" -s h -l help -d 'Print help'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand room; and __fish_seen_subcommand_from status" -l receipts -d 'Include individual tool execution receipts'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand room; and __fish_seen_subcommand_from status" -l json -d 'Output status as JSON'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand room; and __fish_seen_subcommand_from status" -s h -l help -d 'Print help'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand room; and __fish_seen_subcommand_from evidence" -l include-gaps -d 'Include unexamined/skipped rule gaps'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand room; and __fish_seen_subcommand_from evidence" -l json -d 'Output results as JSON'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand room; and __fish_seen_subcommand_from evidence" -s h -l help -d 'Print help'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand room; and __fish_seen_subcommand_from help" -f -a "plan" -d 'Plan an operations room security run across matching tools'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand room; and __fish_seen_subcommand_from help" -f -a "status" -d 'Inspect terminal state and per-tool execution receipts of a room run'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand room; and __fish_seen_subcommand_from help" -f -a "evidence" -d 'Correlate multi-engine evidence and coverage ledger'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand room; and __fish_seen_subcommand_from help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand hunter; and not __fish_seen_subcommand_from hunt plan run candidate verify help" -s h -l help -d 'Print help'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand hunter; and not __fish_seen_subcommand_from hunt plan run candidate verify help" -f -a "hunt" -d 'Run autonomous end-to-end novel vulnerability hunt loop on target project'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand hunter; and not __fish_seen_subcommand_from hunt plan run candidate verify help" -f -a "plan" -d 'Generate bounded research hypotheses for unknown weakness exploration'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand hunter; and not __fish_seen_subcommand_from hunt plan run candidate verify help" -f -a "run" -d 'Run bounded sandboxed fuzzing and experimentation on research candidates'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand hunter; and not __fish_seen_subcommand_from hunt plan run candidate verify help" -f -a "candidate" -d 'Inspect a research candidate or list active candidates in the queue'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand hunter; and not __fish_seen_subcommand_from hunt plan run candidate verify help" -f -a "verify" -d 'Execute isolated deterministic reproduction verification on a candidate'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand hunter; and not __fish_seen_subcommand_from hunt plan run candidate verify help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand hunter; and __fish_seen_subcommand_from hunt" -l max-hypotheses -d 'Maximum hypotheses to evaluate (default: 10)' -r
complete -c bug-killer -n "__fish_bug_killer_using_subcommand hunter; and __fish_seen_subcommand_from hunt" -l json -d 'Output results as JSON'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand hunter; and __fish_seen_subcommand_from hunt" -s h -l help -d 'Print help'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand hunter; and __fish_seen_subcommand_from plan" -l policy -d 'Custom path to policy YAML file' -r -F
complete -c bug-killer -n "__fish_bug_killer_using_subcommand hunter; and __fish_seen_subcommand_from plan" -l json -d 'Output results as JSON'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand hunter; and __fish_seen_subcommand_from plan" -s h -l help -d 'Print help'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand hunter; and __fish_seen_subcommand_from run" -l plan -d 'Research plan identifier' -r
complete -c bug-killer -n "__fish_bug_killer_using_subcommand hunter; and __fish_seen_subcommand_from run" -l sandbox-only -d 'Strictly execute in isolated sandbox without host mutation (default: true)'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand hunter; and __fish_seen_subcommand_from run" -l json -d 'Output results as JSON'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand hunter; and __fish_seen_subcommand_from run" -s h -l help -d 'Print help'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand hunter; and __fish_seen_subcommand_from candidate" -l evidence -d 'Include full reproduction evidence and crash logs'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand hunter; and __fish_seen_subcommand_from candidate" -l json -d 'Output results as JSON'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand hunter; and __fish_seen_subcommand_from candidate" -s h -l help -d 'Print help'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand hunter; and __fish_seen_subcommand_from verify" -l offline -d 'Run in strictly offline mode without network access (default: true)'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand hunter; and __fish_seen_subcommand_from verify" -l json -d 'Output results as JSON'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand hunter; and __fish_seen_subcommand_from verify" -s h -l help -d 'Print help'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand hunter; and __fish_seen_subcommand_from help" -f -a "hunt" -d 'Run autonomous end-to-end novel vulnerability hunt loop on target project'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand hunter; and __fish_seen_subcommand_from help" -f -a "plan" -d 'Generate bounded research hypotheses for unknown weakness exploration'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand hunter; and __fish_seen_subcommand_from help" -f -a "run" -d 'Run bounded sandboxed fuzzing and experimentation on research candidates'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand hunter; and __fish_seen_subcommand_from help" -f -a "candidate" -d 'Inspect a research candidate or list active candidates in the queue'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand hunter; and __fish_seen_subcommand_from help" -f -a "verify" -d 'Execute isolated deterministic reproduction verification on a candidate'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand hunter; and __fish_seen_subcommand_from help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand hunt" -l max-hypotheses -d 'Maximum hypotheses to evaluate (default: 10)' -r
complete -c bug-killer -n "__fish_bug_killer_using_subcommand hunt" -l json -d 'Output diagnostic report as JSON'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand hunt" -s h -l help -d 'Print help'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand disclose; and not __fish_seen_subcommand_from draft help" -s h -l help -d 'Print help'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand disclose; and not __fish_seen_subcommand_from draft help" -f -a "draft" -d 'Synthesize a private responsible disclosure draft (PVR markdown or JSON)'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand disclose; and not __fish_seen_subcommand_from draft help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand disclose; and __fish_seen_subcommand_from draft" -l output -d 'Output file path for generated report (e.g. ./report.md)' -r -F
complete -c bug-killer -n "__fish_bug_killer_using_subcommand disclose; and __fish_seen_subcommand_from draft" -l private -d 'Private draft mode preventing unapproved external network disclosure (default: true)'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand disclose; and __fish_seen_subcommand_from draft" -l json -d 'Output packet as JSON'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand disclose; and __fish_seen_subcommand_from draft" -s h -l help -d 'Print help'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand disclose; and __fish_seen_subcommand_from help" -f -a "draft" -d 'Synthesize a private responsible disclosure draft (PVR markdown or JSON)'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand disclose; and __fish_seen_subcommand_from help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand advisory; and not __fish_seen_subcommand_from sync status help" -s h -l help -d 'Print help'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand advisory; and not __fish_seen_subcommand_from sync status help" -f -a "sync" -d 'Synchronize and cache open-source vulnerability advisory feeds'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand advisory; and not __fish_seen_subcommand_from sync status help" -f -a "status" -d 'Check status and freshness of the local advisory feed cache'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand advisory; and not __fish_seen_subcommand_from sync status help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand advisory; and __fish_seen_subcommand_from sync" -l offline-cache -d 'Custom path to offline cache directory' -r -F
complete -c bug-killer -n "__fish_bug_killer_using_subcommand advisory; and __fish_seen_subcommand_from sync" -l sources -d 'Comma-separated advisory sources (default: osv,ghsa)' -r
complete -c bug-killer -n "__fish_bug_killer_using_subcommand advisory; and __fish_seen_subcommand_from sync" -l json -d 'Output sync receipt as JSON'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand advisory; and __fish_seen_subcommand_from sync" -s h -l help -d 'Print help'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand advisory; and __fish_seen_subcommand_from status" -l json -d 'Output status as JSON'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand advisory; and __fish_seen_subcommand_from status" -s h -l help -d 'Print help'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand advisory; and __fish_seen_subcommand_from help" -f -a "sync" -d 'Synchronize and cache open-source vulnerability advisory feeds'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand advisory; and __fish_seen_subcommand_from help" -f -a "status" -d 'Check status and freshness of the local advisory feed cache'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand advisory; and __fish_seen_subcommand_from help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand inventory" -l sbom -d 'Export CycloneDX SBOM format (default: json)' -r
complete -c bug-killer -n "__fish_bug_killer_using_subcommand inventory" -l json -d 'Output diagnostic report as JSON'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand inventory" -s h -l help -d 'Print help'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand deepsec; and not __fish_seen_subcommand_from init scan process revalidate triage enrich report export status help" -s h -l help -d 'Print help'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand deepsec; and not __fish_seen_subcommand_from init scan process revalidate triage enrich report export status help" -f -a "init" -d 'Initialize deepsec for a codebase, generating INFO.md and running baseline scan'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand deepsec; and not __fish_seen_subcommand_from init scan process revalidate triage enrich report export status help" -f -a "scan" -d 'Fast regex pattern scan across repository'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand deepsec; and not __fish_seen_subcommand_from init scan process revalidate triage enrich report export status help" -f -a "process" -d 'AI investigation of candidate files'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand deepsec; and not __fish_seen_subcommand_from init scan process revalidate triage enrich report export status help" -f -a "revalidate" -d 'Revalidate findings to eliminate false positives and check git fixes'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand deepsec; and not __fish_seen_subcommand_from init scan process revalidate triage enrich report export status help" -f -a "triage" -d 'Prioritize findings into P0/P1/P2 buckets'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand deepsec; and not __fish_seen_subcommand_from init scan process revalidate triage enrich report export status help" -f -a "enrich" -d 'Enrich findings with git committer and authorship history'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand deepsec; and not __fish_seen_subcommand_from init scan process revalidate triage enrich report export status help" -f -a "report" -d 'Render human-readable summary and report'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand deepsec; and not __fish_seen_subcommand_from init scan process revalidate triage enrich report export status help" -f -a "export" -d 'Export findings to JSON or markdown directory'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand deepsec; and not __fish_seen_subcommand_from init scan process revalidate triage enrich report export status help" -f -a "status" -d 'Show data mirror status and file counts'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand deepsec; and not __fish_seen_subcommand_from init scan process revalidate triage enrich report export status help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand deepsec; and __fish_seen_subcommand_from init" -l project-id -r
complete -c bug-killer -n "__fish_bug_killer_using_subcommand deepsec; and __fish_seen_subcommand_from init" -s h -l help -d 'Print help'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand deepsec; and __fish_seen_subcommand_from scan" -l project-id -r
complete -c bug-killer -n "__fish_bug_killer_using_subcommand deepsec; and __fish_seen_subcommand_from scan" -l filter -r
complete -c bug-killer -n "__fish_bug_killer_using_subcommand deepsec; and __fish_seen_subcommand_from scan" -l json
complete -c bug-killer -n "__fish_bug_killer_using_subcommand deepsec; and __fish_seen_subcommand_from scan" -s h -l help -d 'Print help'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand deepsec; and __fish_seen_subcommand_from process" -l project-id -r
complete -c bug-killer -n "__fish_bug_killer_using_subcommand deepsec; and __fish_seen_subcommand_from process" -l batch-size -r
complete -c bug-killer -n "__fish_bug_killer_using_subcommand deepsec; and __fish_seen_subcommand_from process" -l limit -r
complete -c bug-killer -n "__fish_bug_killer_using_subcommand deepsec; and __fish_seen_subcommand_from process" -l filter -r
complete -c bug-killer -n "__fish_bug_killer_using_subcommand deepsec; and __fish_seen_subcommand_from process" -l max-cost-usd -r
complete -c bug-killer -n "__fish_bug_killer_using_subcommand deepsec; and __fish_seen_subcommand_from process" -l model -r
complete -c bug-killer -n "__fish_bug_killer_using_subcommand deepsec; and __fish_seen_subcommand_from process" -l agent -r
complete -c bug-killer -n "__fish_bug_killer_using_subcommand deepsec; and __fish_seen_subcommand_from process" -l json
complete -c bug-killer -n "__fish_bug_killer_using_subcommand deepsec; and __fish_seen_subcommand_from process" -s h -l help -d 'Print help'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand deepsec; and __fish_seen_subcommand_from revalidate" -l project-id -r
complete -c bug-killer -n "__fish_bug_killer_using_subcommand deepsec; and __fish_seen_subcommand_from revalidate" -l model -r
complete -c bug-killer -n "__fish_bug_killer_using_subcommand deepsec; and __fish_seen_subcommand_from revalidate" -l force
complete -c bug-killer -n "__fish_bug_killer_using_subcommand deepsec; and __fish_seen_subcommand_from revalidate" -l json
complete -c bug-killer -n "__fish_bug_killer_using_subcommand deepsec; and __fish_seen_subcommand_from revalidate" -s h -l help -d 'Print help'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand deepsec; and __fish_seen_subcommand_from triage" -l project-id -r
complete -c bug-killer -n "__fish_bug_killer_using_subcommand deepsec; and __fish_seen_subcommand_from triage" -l json
complete -c bug-killer -n "__fish_bug_killer_using_subcommand deepsec; and __fish_seen_subcommand_from triage" -s h -l help -d 'Print help'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand deepsec; and __fish_seen_subcommand_from enrich" -l project-id -r
complete -c bug-killer -n "__fish_bug_killer_using_subcommand deepsec; and __fish_seen_subcommand_from enrich" -l json
complete -c bug-killer -n "__fish_bug_killer_using_subcommand deepsec; and __fish_seen_subcommand_from enrich" -s h -l help -d 'Print help'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand deepsec; and __fish_seen_subcommand_from report" -l project-id -r
complete -c bug-killer -n "__fish_bug_killer_using_subcommand deepsec; and __fish_seen_subcommand_from report" -l json
complete -c bug-killer -n "__fish_bug_killer_using_subcommand deepsec; and __fish_seen_subcommand_from report" -s h -l help -d 'Print help'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand deepsec; and __fish_seen_subcommand_from export" -l project-id -r
complete -c bug-killer -n "__fish_bug_killer_using_subcommand deepsec; and __fish_seen_subcommand_from export" -l format -r
complete -c bug-killer -n "__fish_bug_killer_using_subcommand deepsec; and __fish_seen_subcommand_from export" -l out -r -F
complete -c bug-killer -n "__fish_bug_killer_using_subcommand deepsec; and __fish_seen_subcommand_from export" -s h -l help -d 'Print help'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand deepsec; and __fish_seen_subcommand_from status" -l project-id -r
complete -c bug-killer -n "__fish_bug_killer_using_subcommand deepsec; and __fish_seen_subcommand_from status" -l json
complete -c bug-killer -n "__fish_bug_killer_using_subcommand deepsec; and __fish_seen_subcommand_from status" -s h -l help -d 'Print help'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand deepsec; and __fish_seen_subcommand_from help" -f -a "init" -d 'Initialize deepsec for a codebase, generating INFO.md and running baseline scan'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand deepsec; and __fish_seen_subcommand_from help" -f -a "scan" -d 'Fast regex pattern scan across repository'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand deepsec; and __fish_seen_subcommand_from help" -f -a "process" -d 'AI investigation of candidate files'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand deepsec; and __fish_seen_subcommand_from help" -f -a "revalidate" -d 'Revalidate findings to eliminate false positives and check git fixes'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand deepsec; and __fish_seen_subcommand_from help" -f -a "triage" -d 'Prioritize findings into P0/P1/P2 buckets'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand deepsec; and __fish_seen_subcommand_from help" -f -a "enrich" -d 'Enrich findings with git committer and authorship history'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand deepsec; and __fish_seen_subcommand_from help" -f -a "report" -d 'Render human-readable summary and report'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand deepsec; and __fish_seen_subcommand_from help" -f -a "export" -d 'Export findings to JSON or markdown directory'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand deepsec; and __fish_seen_subcommand_from help" -f -a "status" -d 'Show data mirror status and file counts'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand deepsec; and __fish_seen_subcommand_from help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand help; and not __fish_seen_subcommand_from shell doctor watch completion scan probe osv heal rollback history cve-info agent evidence plan approve operator-public-key apply mcp init security engine room hunter hunt disclose advisory inventory deepsec help" -f -a "shell" -d 'Launch the interactive Bug Killer REPL shell'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand help; and not __fish_seen_subcommand_from shell doctor watch completion scan probe osv heal rollback history cve-info agent evidence plan approve operator-public-key apply mcp init security engine room hunter hunt disclose advisory inventory deepsec help" -f -a "doctor" -d 'Run diagnostic system and environment health audit'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand help; and not __fish_seen_subcommand_from shell doctor watch completion scan probe osv heal rollback history cve-info agent evidence plan approve operator-public-key apply mcp init security engine room hunter hunt disclose advisory inventory deepsec help" -f -a "watch" -d 'Start live surveillance monitoring filesystem for security regressions'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand help; and not __fish_seen_subcommand_from shell doctor watch completion scan probe osv heal rollback history cve-info agent evidence plan approve operator-public-key apply mcp init security engine room hunter hunt disclose advisory inventory deepsec help" -f -a "completion" -d 'Generate shell auto-completion script for bash, zsh, fish, or powershell'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand help; and not __fish_seen_subcommand_from shell doctor watch completion scan probe osv heal rollback history cve-info agent evidence plan approve operator-public-key apply mcp init security engine room hunter hunt disclose advisory inventory deepsec help" -f -a "scan" -d 'Scan target directories and systems for PHP2Shell (CVE-2026-109618, CVE-2026-109619) and Node2Shell (CVE-2026-111497)'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand help; and not __fish_seen_subcommand_from shell doctor watch completion scan probe osv heal rollback history cve-info agent evidence plan approve operator-public-key apply mcp init security engine room hunter hunt disclose advisory inventory deepsec help" -f -a "probe" -d 'Defensively probe a live web application endpoint for security posture, headers, and disclosures'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand help; and not __fish_seen_subcommand_from shell doctor watch completion scan probe osv heal rollback history cve-info agent evidence plan approve operator-public-key apply mcp init security engine room hunter hunt disclose advisory inventory deepsec help" -f -a "osv" -d 'Query open-source vulnerability database (https://osv.dev) for dependencies across npm, Packagist, PyPI, and crates.io'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand help; and not __fish_seen_subcommand_from shell doctor watch completion scan probe osv heal rollback history cve-info agent evidence plan approve operator-public-key apply mcp init security engine room hunter hunt disclose advisory inventory deepsec help" -f -a "heal" -d 'Plan and automatically heal vulnerable configurations, Dockerfiles, manifests, and web servers'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand help; and not __fish_seen_subcommand_from shell doctor watch completion scan probe osv heal rollback history cve-info agent evidence plan approve operator-public-key apply mcp init security engine room hunter hunt disclose advisory inventory deepsec help" -f -a "rollback" -d 'Roll back an applied healing session using a backup ID'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand help; and not __fish_seen_subcommand_from shell doctor watch completion scan probe osv heal rollback history cve-info agent evidence plan approve operator-public-key apply mcp init security engine room hunter hunt disclose advisory inventory deepsec help" -f -a "history" -d 'List all healing snapshots and backups'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand help; and not __fish_seen_subcommand_from shell doctor watch completion scan probe osv heal rollback history cve-info agent evidence plan approve operator-public-key apply mcp init security engine room hunter hunt disclose advisory inventory deepsec help" -f -a "cve-info" -d 'Display deep technical teardown and remediation blueprint for a specific CVE'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand help; and not __fish_seen_subcommand_from shell doctor watch completion scan probe osv heal rollback history cve-info agent evidence plan approve operator-public-key apply mcp init security engine room hunter hunt disclose advisory inventory deepsec help" -f -a "agent" -d 'Model-agnostic AI agent investigation and capability diagnostics'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand help; and not __fish_seen_subcommand_from shell doctor watch completion scan probe osv heal rollback history cve-info agent evidence plan approve operator-public-key apply mcp init security engine room hunter hunt disclose advisory inventory deepsec help" -f -a "evidence" -d 'Retrieve full evidence receipts and cryptographic hashes for a specific finding'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand help; and not __fish_seen_subcommand_from shell doctor watch completion scan probe osv heal rollback history cve-info agent evidence plan approve operator-public-key apply mcp init security engine room hunter hunt disclose advisory inventory deepsec help" -f -a "plan" -d 'Plan a prospective, non-mutating repair for a finding with cryptographic diff hash'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand help; and not __fish_seen_subcommand_from shell doctor watch completion scan probe osv heal rollback history cve-info agent evidence plan approve operator-public-key apply mcp init security engine room hunter hunt disclose advisory inventory deepsec help" -f -a "approve" -d 'Issue an operator approval receipt for a planned remediation'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand help; and not __fish_seen_subcommand_from shell doctor watch completion scan probe osv heal rollback history cve-info agent evidence plan approve operator-public-key apply mcp init security engine room hunter hunt disclose advisory inventory deepsec help" -f -a "operator-public-key" -d 'Display the public key derived from a separately provisioned operator signing key'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand help; and not __fish_seen_subcommand_from shell doctor watch completion scan probe osv heal rollback history cve-info agent evidence plan approve operator-public-key apply mcp init security engine room hunter hunt disclose advisory inventory deepsec help" -f -a "apply" -d 'Apply an approved prospective remediation plan with operator approval verification'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand help; and not __fish_seen_subcommand_from shell doctor watch completion scan probe osv heal rollback history cve-info agent evidence plan approve operator-public-key apply mcp init security engine room hunter hunt disclose advisory inventory deepsec help" -f -a "mcp" -d 'Model Context Protocol (MCP) server and integration commands'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand help; and not __fish_seen_subcommand_from shell doctor watch completion scan probe osv heal rollback history cve-info agent evidence plan approve operator-public-key apply mcp init security engine room hunter hunt disclose advisory inventory deepsec help" -f -a "init" -d 'Initialize Bug Killer in a project, create security configuration, and run baseline scan'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand help; and not __fish_seen_subcommand_from shell doctor watch completion scan probe osv heal rollback history cve-info agent evidence plan approve operator-public-key apply mcp init security engine room hunter hunt disclose advisory inventory deepsec help" -f -a "security" -d 'Bug Killer Security Guard suite (scan, status, explain, fix, verify, guidance, catalog)'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand help; and not __fish_seen_subcommand_from shell doctor watch completion scan probe osv heal rollback history cve-info agent evidence plan approve operator-public-key apply mcp init security engine room hunter hunt disclose advisory inventory deepsec help" -f -a "engine" -d 'Sibling & external tool capability broker (doctor, list, explain)'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand help; and not __fish_seen_subcommand_from shell doctor watch completion scan probe osv heal rollback history cve-info agent evidence plan approve operator-public-key apply mcp init security engine room hunter hunt disclose advisory inventory deepsec help" -f -a "room" -d 'Agentic Security Operations Room (plan, status, evidence)'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand help; and not __fish_seen_subcommand_from shell doctor watch completion scan probe osv heal rollback history cve-info agent evidence plan approve operator-public-key apply mcp init security engine room hunter hunt disclose advisory inventory deepsec help" -f -a "hunter" -d 'Novel vulnerability hunter & bounded research runner (plan, run, candidate, verify)'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand help; and not __fish_seen_subcommand_from shell doctor watch completion scan probe osv heal rollback history cve-info agent evidence plan approve operator-public-key apply mcp init security engine room hunter hunt disclose advisory inventory deepsec help" -f -a "hunt" -d 'Autonomous novel vulnerability hunter on target project (full end-to-end research loop)'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand help; and not __fish_seen_subcommand_from shell doctor watch completion scan probe osv heal rollback history cve-info agent evidence plan approve operator-public-key apply mcp init security engine room hunter hunt disclose advisory inventory deepsec help" -f -a "disclose" -d 'Responsible private disclosure & PVR draft generation (draft)'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand help; and not __fish_seen_subcommand_from shell doctor watch completion scan probe osv heal rollback history cve-info agent evidence plan approve operator-public-key apply mcp init security engine room hunter hunt disclose advisory inventory deepsec help" -f -a "advisory" -d 'Advisory feeds & dependency vulnerability cache (sync, status)'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand help; and not __fish_seen_subcommand_from shell doctor watch completion scan probe osv heal rollback history cve-info agent evidence plan approve operator-public-key apply mcp init security engine room hunter hunt disclose advisory inventory deepsec help" -f -a "inventory" -d 'Software asset inventory & CycloneDX / JSON SBOM extraction'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand help; and not __fish_seen_subcommand_from shell doctor watch completion scan probe osv heal rollback history cve-info agent evidence plan approve operator-public-key apply mcp init security engine room hunter hunt disclose advisory inventory deepsec help" -f -a "deepsec" -d 'DeepSec: Agent-Powered Security Review Harness'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand help; and not __fish_seen_subcommand_from shell doctor watch completion scan probe osv heal rollback history cve-info agent evidence plan approve operator-public-key apply mcp init security engine room hunter hunt disclose advisory inventory deepsec help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand help; and __fish_seen_subcommand_from agent" -f -a "doctor" -d 'Inspect configured model provider capability and health without leaking secrets'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand help; and __fish_seen_subcommand_from agent" -f -a "investigate" -d 'Run bounded read-only autonomous investigation loop over target workspace'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand help; and __fish_seen_subcommand_from mcp" -f -a "serve" -d 'Run the stdio MCP server for external agent integration'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand help; and __fish_seen_subcommand_from mcp" -f -a "config" -d 'Generate copy-pasteable MCP server configuration snippets for external coding agents'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand help; and __fish_seen_subcommand_from security" -f -a "scan" -d 'Execute security guard scan across all applicable catalog rules'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand help; and __fish_seen_subcommand_from security" -f -a "coverage" -d 'Inspect workspace rule-target coverage receipts and unassessed gaps'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand help; and __fish_seen_subcommand_from security" -f -a "status" -d 'Show current workspace security guard status and baseline findings'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand help; and __fish_seen_subcommand_from security" -f -a "explain" -d 'Explain a finding using the 373-rule AI-Generated Code Security Catalog'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand help; and __fish_seen_subcommand_from security" -f -a "fix" -d 'Propose or apply an authorized bounded security repair'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand help; and __fish_seen_subcommand_from security" -f -a "verify" -d 'Independently verify workspace security status and coverage completeness'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand help; and __fish_seen_subcommand_from security" -f -a "guidance" -d 'Generate pre-generation security guidance for a coding task'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand help; and __fish_seen_subcommand_from security" -f -a "catalog" -d 'Query or browse the 373-rule AI-Generated Code Security Issues Catalog'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand help; and __fish_seen_subcommand_from engine" -f -a "doctor" -d 'Check health, versions, and installation status of sibling security engines'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand help; and __fish_seen_subcommand_from engine" -f -a "list" -d 'List all registered sibling tool capabilities and execution transports'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand help; and __fish_seen_subcommand_from engine" -f -a "explain" -d 'Explain which security tools match a specified goal (known, prevention, research)'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand help; and __fish_seen_subcommand_from engine" -f -a "skills" -d 'Query, inspect, and recommend deep cybersecurity skills and MITRE/NIST mappings'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand help; and __fish_seen_subcommand_from room" -f -a "plan" -d 'Plan an operations room security run across matching tools'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand help; and __fish_seen_subcommand_from room" -f -a "status" -d 'Inspect terminal state and per-tool execution receipts of a room run'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand help; and __fish_seen_subcommand_from room" -f -a "evidence" -d 'Correlate multi-engine evidence and coverage ledger'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand help; and __fish_seen_subcommand_from hunter" -f -a "hunt" -d 'Run autonomous end-to-end novel vulnerability hunt loop on target project'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand help; and __fish_seen_subcommand_from hunter" -f -a "plan" -d 'Generate bounded research hypotheses for unknown weakness exploration'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand help; and __fish_seen_subcommand_from hunter" -f -a "run" -d 'Run bounded sandboxed fuzzing and experimentation on research candidates'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand help; and __fish_seen_subcommand_from hunter" -f -a "candidate" -d 'Inspect a research candidate or list active candidates in the queue'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand help; and __fish_seen_subcommand_from hunter" -f -a "verify" -d 'Execute isolated deterministic reproduction verification on a candidate'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand help; and __fish_seen_subcommand_from disclose" -f -a "draft" -d 'Synthesize a private responsible disclosure draft (PVR markdown or JSON)'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand help; and __fish_seen_subcommand_from advisory" -f -a "sync" -d 'Synchronize and cache open-source vulnerability advisory feeds'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand help; and __fish_seen_subcommand_from advisory" -f -a "status" -d 'Check status and freshness of the local advisory feed cache'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand help; and __fish_seen_subcommand_from deepsec" -f -a "init" -d 'Initialize deepsec for a codebase, generating INFO.md and running baseline scan'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand help; and __fish_seen_subcommand_from deepsec" -f -a "scan" -d 'Fast regex pattern scan across repository'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand help; and __fish_seen_subcommand_from deepsec" -f -a "process" -d 'AI investigation of candidate files'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand help; and __fish_seen_subcommand_from deepsec" -f -a "revalidate" -d 'Revalidate findings to eliminate false positives and check git fixes'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand help; and __fish_seen_subcommand_from deepsec" -f -a "triage" -d 'Prioritize findings into P0/P1/P2 buckets'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand help; and __fish_seen_subcommand_from deepsec" -f -a "enrich" -d 'Enrich findings with git committer and authorship history'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand help; and __fish_seen_subcommand_from deepsec" -f -a "report" -d 'Render human-readable summary and report'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand help; and __fish_seen_subcommand_from deepsec" -f -a "export" -d 'Export findings to JSON or markdown directory'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand help; and __fish_seen_subcommand_from deepsec" -f -a "status" -d 'Show data mirror status and file counts'
