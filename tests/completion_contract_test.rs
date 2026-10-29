use std::process::Command;

#[test]
fn cli_generates_bash_zsh_and_fish_completions() {
    for (shell, marker) in [
        ("bash", "complete -F"),
        ("zsh", "#compdef"),
        ("fish", "complete -c"),
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_bug-killer"))
            .args(["completion", shell])
            .output()
            .expect("completion CLI must launch");
        assert!(
            output.status.success(),
            "{shell} completion failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let script = String::from_utf8(output.stdout).expect("completion output must be UTF-8");
        assert!(
            script.contains(marker) && script.contains("bug-killer"),
            "{shell} completion output must register the bug-killer command"
        );
    }
}

#[test]
fn cli_rejects_unknown_completion_shell() {
    let output = Command::new(env!("CARGO_BIN_EXE_bug-killer"))
        .args(["completion", "unsupported_shell"])
        .output()
        .expect("completion CLI must launch");
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("Unsupported shell"));
}
