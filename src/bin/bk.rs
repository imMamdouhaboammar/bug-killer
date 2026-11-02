use bug_killer::cli::{Cli, run};
use clap::Parser;

fn main() {
    let cli = Cli::parse();
    let code = run(cli);
    if code != 0 {
        std::process::exit(code);
    }
}
