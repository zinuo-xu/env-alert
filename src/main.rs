mod scanner;
mod rules;
mod patterns;
mod reporter;
mod config;

use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::process;

#[derive(Parser)]
#[command(name = "env-alert")]
#[command(about = "Detect exposed secrets, API keys, and credentials in your codebase")]
#[command(version, long_version = "0.1.0")]
#[command(author = "zinuo-xu")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Scan a directory for exposed secrets
    Scan {
        /// Path to the directory to scan
        #[arg(default_value = ".", value_hint = clap::ValueHint::DirPath)]
        path: PathBuf,

        /// Output format (terminal, json)
        #[arg(short, long, default_value = "terminal")]
        format: String,

        /// Path to config file
        #[arg(short, long)]
        config: Option<PathBuf>,

        /// Skip .gitignore rules
        #[arg(long)]
        no_gitignore: bool,
    },
    /// Install the pre-commit hook
    InstallHook {
        /// Path to the .git/hooks directory
        #[arg(default_value = ".git/hooks", value_hint = clap::ValueHint::DirPath)]
        hook_dir: PathBuf,
    },
    /// Initialize a default config file
    Init {
        /// Path to write the config
        #[arg(default_value = ".env-alert.toml")]
        path: PathBuf,
    },
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Scan { path, format, config, no_gitignore } => {
            let cfg = if let Some(config_path) = &config {
                match config::load_config(config_path) {
                    Ok(c) => c,
                    Err(e) => {
                        eprintln!("Error loading config: {}", e);
                        process::exit(1);
                    }
                }
            } else {
                config::try_load_default().unwrap_or_default()
            };

            let use_gitignore = !no_gitignore;

            let results = scanner::scan_directory(&path, &cfg, use_gitignore);

            if results.is_empty() {
                reporter::print_success("No secrets or exposed credentials detected. Your codebase looks clean!");
                process::exit(0);
            }

            match format.as_str() {
                "json" => {
                    reporter::output_json(&results);
                }
                _ => {
                    reporter::print_results(&results);
                }
            }

            process::exit(if results.iter().any(|r| r.severity == "high") {
                2
            } else {
                1
            });
        }
        Commands::InstallHook { hook_dir } => {
            match scanner::install_pre_commit_hook(&hook_dir) {
                Ok(path) => {
                    println!("Pre-commit hook installed at: {}", path.display());
                }
                Err(e) => {
                    eprintln!("Failed to install pre-commit hook: {}", e);
                    process::exit(1);
                }
            }
        }
        Commands::Init { path } => {
            match config::write_default_config(&path) {
                Ok(()) => {
                    println!("Default config written to: {}", path.display());
                }
                Err(e) => {
                    eprintln!("Failed to write config: {}", e);
                    process::exit(1);
                }
            }
        }
    }
}
