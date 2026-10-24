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
complete -c bug-killer -n "__fish_bug_killer_needs_command" -f -a "apply" -d 'Apply an approved prospective remediation plan with operator approval verification'
complete -c bug-killer -n "__fish_bug_killer_needs_command" -f -a "mcp" -d 'Model Context Protocol (MCP) server and integration commands'
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
complete -c bug-killer -n "__fish_bug_killer_using_subcommand probe" -s h -l help -d 'Print help'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand osv" -l json -d 'Output results as JSON'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand osv" -s h -l help -d 'Print help'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand heal" -l rules -d 'Custom path to rules directory or JSON rule file' -r -F
complete -c bug-killer -n "__fish_bug_killer_using_subcommand heal" -l dry-run -d 'Show planned patches and diffs without modifying files'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand heal" -l apply -d 'Apply planned safe patches to filesystem (Default: false, plan-only mode)'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand heal" -l auto-apply -d 'Automatically apply all safe patches (Alias for --apply, Default: false)'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand heal" -l osv -d 'Include OSV open vulnerability database findings in healing'
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
complete -c bug-killer -n "__fish_bug_killer_using_subcommand help; and not __fish_seen_subcommand_from shell doctor watch completion scan probe osv heal rollback history cve-info agent evidence plan approve apply mcp help" -f -a "shell" -d 'Launch the interactive Bug Killer REPL shell'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand help; and not __fish_seen_subcommand_from shell doctor watch completion scan probe osv heal rollback history cve-info agent evidence plan approve apply mcp help" -f -a "doctor" -d 'Run diagnostic system and environment health audit'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand help; and not __fish_seen_subcommand_from shell doctor watch completion scan probe osv heal rollback history cve-info agent evidence plan approve apply mcp help" -f -a "watch" -d 'Start live surveillance monitoring filesystem for security regressions'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand help; and not __fish_seen_subcommand_from shell doctor watch completion scan probe osv heal rollback history cve-info agent evidence plan approve apply mcp help" -f -a "completion" -d 'Generate shell auto-completion script for bash, zsh, fish, or powershell'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand help; and not __fish_seen_subcommand_from shell doctor watch completion scan probe osv heal rollback history cve-info agent evidence plan approve apply mcp help" -f -a "scan" -d 'Scan target directories and systems for PHP2Shell (CVE-2026-109618, CVE-2026-109619) and Node2Shell (CVE-2026-111497)'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand help; and not __fish_seen_subcommand_from shell doctor watch completion scan probe osv heal rollback history cve-info agent evidence plan approve apply mcp help" -f -a "probe" -d 'Defensively probe a live web application endpoint for security posture, headers, and disclosures'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand help; and not __fish_seen_subcommand_from shell doctor watch completion scan probe osv heal rollback history cve-info agent evidence plan approve apply mcp help" -f -a "osv" -d 'Query open-source vulnerability database (https://osv.dev) for dependencies across npm, Packagist, PyPI, and crates.io'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand help; and not __fish_seen_subcommand_from shell doctor watch completion scan probe osv heal rollback history cve-info agent evidence plan approve apply mcp help" -f -a "heal" -d 'Plan and automatically heal vulnerable configurations, Dockerfiles, manifests, and web servers'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand help; and not __fish_seen_subcommand_from shell doctor watch completion scan probe osv heal rollback history cve-info agent evidence plan approve apply mcp help" -f -a "rollback" -d 'Roll back an applied healing session using a backup ID'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand help; and not __fish_seen_subcommand_from shell doctor watch completion scan probe osv heal rollback history cve-info agent evidence plan approve apply mcp help" -f -a "history" -d 'List all healing snapshots and backups'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand help; and not __fish_seen_subcommand_from shell doctor watch completion scan probe osv heal rollback history cve-info agent evidence plan approve apply mcp help" -f -a "cve-info" -d 'Display deep technical teardown and remediation blueprint for a specific CVE'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand help; and not __fish_seen_subcommand_from shell doctor watch completion scan probe osv heal rollback history cve-info agent evidence plan approve apply mcp help" -f -a "agent" -d 'Model-agnostic AI agent investigation and capability diagnostics'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand help; and not __fish_seen_subcommand_from shell doctor watch completion scan probe osv heal rollback history cve-info agent evidence plan approve apply mcp help" -f -a "evidence" -d 'Retrieve full evidence receipts and cryptographic hashes for a specific finding'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand help; and not __fish_seen_subcommand_from shell doctor watch completion scan probe osv heal rollback history cve-info agent evidence plan approve apply mcp help" -f -a "plan" -d 'Plan a prospective, non-mutating repair for a finding with cryptographic diff hash'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand help; and not __fish_seen_subcommand_from shell doctor watch completion scan probe osv heal rollback history cve-info agent evidence plan approve apply mcp help" -f -a "approve" -d 'Issue an operator approval receipt for a planned remediation'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand help; and not __fish_seen_subcommand_from shell doctor watch completion scan probe osv heal rollback history cve-info agent evidence plan approve apply mcp help" -f -a "apply" -d 'Apply an approved prospective remediation plan with operator approval verification'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand help; and not __fish_seen_subcommand_from shell doctor watch completion scan probe osv heal rollback history cve-info agent evidence plan approve apply mcp help" -f -a "mcp" -d 'Model Context Protocol (MCP) server and integration commands'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand help; and not __fish_seen_subcommand_from shell doctor watch completion scan probe osv heal rollback history cve-info agent evidence plan approve apply mcp help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand help; and __fish_seen_subcommand_from agent" -f -a "doctor" -d 'Inspect configured model provider capability and health without leaking secrets'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand help; and __fish_seen_subcommand_from agent" -f -a "investigate" -d 'Run bounded read-only autonomous investigation loop over target workspace'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand help; and __fish_seen_subcommand_from mcp" -f -a "serve" -d 'Run the stdio MCP server for external agent integration'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand help; and __fish_seen_subcommand_from mcp" -f -a "config" -d 'Generate copy-pasteable MCP server configuration snippets for external coding agents'
