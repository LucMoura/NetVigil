mod cli;

use clap::Parser;
use cli::{Cli, Commands};

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Scan(args) => {
            println!("Scanning is not implemented yet (target: {}).", args.target);
        }
    }
}
