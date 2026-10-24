use std::io;
use clap::Command;
use clap_complete::{generate, Shell};

pub struct CompletionGenerator;

impl CompletionGenerator {
    pub fn generate_completion(shell_name: &str, cmd: &mut Command) -> Result<(), String> {
        let shell = match shell_name.to_lowercase().as_str() {
            "bash" => Shell::Bash,
            "zsh" => Shell::Zsh,
            "fish" => Shell::Fish,
            "powershell" | "ps" => Shell::PowerShell,
            "elvish" => Shell::Elvish,
            _ => {
                return Err(format!(
                    "Unsupported shell: '{}'. Supported: bash, zsh, fish, powershell, elvish",
                    shell_name
                ));
            }
        };

        generate(shell, cmd, "bug-killer", &mut io::stdout());
        Ok(())
    }
}
