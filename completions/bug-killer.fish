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
complete -c bug-killer -n "__fish_bug_killer_needs_command" -f -a "heal" -d 'Plan and automatically heal vulnerable configurations, Dockerfiles, manifests, and web servers'
complete -c bug-killer -n "__fish_bug_killer_needs_command" -f -a "rollback" -d 'Roll back an applied healing session using a backup ID'
complete -c bug-killer -n "__fish_bug_killer_needs_command" -f -a "history" -d 'List all healing snapshots and backups'
complete -c bug-killer -n "__fish_bug_killer_needs_command" -f -a "cve-info" -d 'Display deep technical teardown and remediation blueprint for a specific CVE'
complete -c bug-killer -n "__fish_bug_killer_needs_command" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand shell" -s h -l help -d 'Print help'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand doctor" -l json -d 'Output diagnostic report as JSON'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand doctor" -s h -l help -d 'Print help'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand watch" -s i -l interval -d 'Surveillance polling interval in seconds (default: 3)' -r
complete -c bug-killer -n "__fish_bug_killer_using_subcommand watch" -l auto-heal -d 'Automatically apply safe healing patches upon detecting vulnerabilities'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand watch" -s h -l help -d 'Print help'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand completion" -s h -l help -d 'Print help'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand scan" -l json -d 'Output results as JSON'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand scan" -l check-runtime -d 'Also inspect host binary runtimes (php, node) on PATH'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand scan" -s h -l help -d 'Print help'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand heal" -l dry-run -d 'Show planned patches and diffs without modifying files'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand heal" -l auto-apply -d 'Automatically apply all safe patches without confirmation'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand heal" -s h -l help -d 'Print help'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand rollback" -s h -l help -d 'Print help'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand history" -s h -l help -d 'Print help'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand cve-info" -s h -l help -d 'Print help'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand help; and not __fish_seen_subcommand_from shell doctor watch completion scan heal rollback history cve-info help" -f -a "shell" -d 'Launch the interactive Bug Killer REPL shell'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand help; and not __fish_seen_subcommand_from shell doctor watch completion scan heal rollback history cve-info help" -f -a "doctor" -d 'Run diagnostic system and environment health audit'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand help; and not __fish_seen_subcommand_from shell doctor watch completion scan heal rollback history cve-info help" -f -a "watch" -d 'Start live surveillance monitoring filesystem for security regressions'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand help; and not __fish_seen_subcommand_from shell doctor watch completion scan heal rollback history cve-info help" -f -a "completion" -d 'Generate shell auto-completion script for bash, zsh, fish, or powershell'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand help; and not __fish_seen_subcommand_from shell doctor watch completion scan heal rollback history cve-info help" -f -a "scan" -d 'Scan target directories and systems for PHP2Shell (CVE-2026-109618, CVE-2026-109619) and Node2Shell (CVE-2026-111497)'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand help; and not __fish_seen_subcommand_from shell doctor watch completion scan heal rollback history cve-info help" -f -a "heal" -d 'Plan and automatically heal vulnerable configurations, Dockerfiles, manifests, and web servers'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand help; and not __fish_seen_subcommand_from shell doctor watch completion scan heal rollback history cve-info help" -f -a "rollback" -d 'Roll back an applied healing session using a backup ID'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand help; and not __fish_seen_subcommand_from shell doctor watch completion scan heal rollback history cve-info help" -f -a "history" -d 'List all healing snapshots and backups'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand help; and not __fish_seen_subcommand_from shell doctor watch completion scan heal rollback history cve-info help" -f -a "cve-info" -d 'Display deep technical teardown and remediation blueprint for a specific CVE'
complete -c bug-killer -n "__fish_bug_killer_using_subcommand help; and not __fish_seen_subcommand_from shell doctor watch completion scan heal rollback history cve-info help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
