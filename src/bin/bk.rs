use bug_killer::cli::{run, Cli};
use clap::Parser;

fn main() {
    let cli = Cli::parse();
    let code = run(cli);
    if code != 0 {
        std::process::exit(code);
    }
}
