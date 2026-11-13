//! `cargo xtask`: project tooling, written in Rust like everything else here.

use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use xtask::score::score;
use xtask::synth::{Truth, generate};

#[derive(Parser)]
#[command(name = "xtask", about = "Project tooling for rollcall")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Generate a synthetic breach dataset with a ground-truth file
    Synth {
        #[arg(long, default_value_t = 1)]
        seed: u64,
        /// Number of main subjects; spouses are added on top
        #[arg(long, default_value_t = 300)]
        people: usize,
        /// Folder to create; receives `evidence/` and `truth.json`
        #[arg(long)]
        out: PathBuf,
    },
    /// Score a notification list (exported with `--values full`) against ground truth
    Score {
        #[arg(long)]
        truth: PathBuf,
        #[arg(long)]
        list: PathBuf,
    },
}

fn main() -> ExitCode {
    match run(Cli::parse().command) {
        Ok(passed) => {
            if passed {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(2)
            }
        }
        Err(error) => {
            eprintln!("error: {error:#}");
            ExitCode::FAILURE
        }
    }
}

fn run(command: Command) -> Result<bool> {
    match command {
        Command::Synth { seed, people, out } => {
            if out.exists() {
                anyhow::bail!("{} already exists; choose a new folder", out.display());
            }
            let truth = generate(seed, people, &out)?;
            println!(
                "Wrote {} files about {} people to {}",
                truth.files.len(),
                truth.people.len(),
                out.join("evidence").display()
            );
            println!("Ground truth: {}", out.join("truth.json").display());
            Ok(true)
        }
        Command::Score { truth, list } => {
            let truth: Truth = serde_json::from_slice(
                &fs::read(&truth).with_context(|| format!("could not read {}", truth.display()))?,
            )
            .context("the truth file is not valid")?;
            let list = fs::read_to_string(&list)
                .with_context(|| format!("could not read {}", list.display()))?;
            let result = score(&truth, &list)?;
            print!("{}", result.report());
            println!("{}", if result.is_perfect() { "PASS" } else { "FAIL" });
            Ok(result.is_perfect())
        }
    }
}
