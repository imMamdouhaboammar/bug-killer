use clap::Command;
use clap_complete::{Shell, generate};
use std::io;

pub struct CompletionGenerator;

impl CompletionGenerator {
    pub fn generate_completion(shell_name: &str, cmd: &mut Command) -> Result<(), String> {
        Self::generate_completion_to_writer(shell_name, cmd, &mut io::stdout())
    }

    pub fn generate_completion_to_writer<W: io::Write>(
        shell_name: &str,
        cmd: &mut Command,
        writer: &mut W,
    ) -> Result<(), String> {
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

        generate(shell, cmd, "bug-killer", writer);
        Ok(())
    }
}
