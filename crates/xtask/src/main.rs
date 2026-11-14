#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used))]
mod assets;
mod notices;
mod package;
mod provenance;
mod util;
mod verify;

use std::path::PathBuf;
use std::process::{Command, ExitCode};

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "xtask", about = "PII Explorer development and packaging tasks")]
struct Cli {
    #[command(subcommand)]
    command: Task,
}

#[derive(Subcommand)]
enum Task {
    /// Download and verify only the pinned entries in scripts/assets.json.
    Assets,
    /// Run formatting, clippy, and tests for the Rust workspace.
    Test,
    /// Build release binaries and stage a fresh dist/<target> directory.
    Package {
        /// Rust target triple. Defaults to the host reported by rustc.
        #[arg(long)]
        target: Option<String>,
    },
    /// Verify a staged package and its SHA256SUMS file.
    Verify {
        /// Package directory. Defaults to dist/<host-target>.
        #[arg(value_name = "PACKAGE_DIR", conflicts_with = "target")]
        path: Option<PathBuf>,
        /// Rust target triple to verify under dist.
        #[arg(long)]
        target: Option<String>,
    },
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error:#}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<()> {
    let root = util::project_root()?;
    match Cli::parse().command {
        Task::Assets => assets::download(&root),
        Task::Test => test_workspace(&root),
        Task::Package { target } => {
            let target = util::target_triple(target)?;
            package::package(&root, &target)
        }
        Task::Verify { path, target } => {
            let package_dir = match (path, target) {
                (Some(path), None) => path,
                (None, target) => {
                    let target = util::target_triple(target)?;
                    root.join("dist").join(target)
                }
                (Some(_), Some(_)) => bail!("choose either PACKAGE_DIR or --target"),
            };
            verify::verify(&package_dir)
        }
    }
}

fn test_workspace(root: &std::path::Path) -> Result<()> {
    run_cargo(root, &["fmt", "--all", "--", "--check"])?;
    run_cargo(
        root,
        &[
            "clippy",
            "--workspace",
            "--all-targets",
            "--all-features",
            "--locked",
            "--",
            "-D",
            "warnings",
        ],
    )?;
    run_cargo(root, &["test", "--workspace", "--all-features", "--locked"])?;
    run_cargo(
        root,
        &[
            "test",
            "--package",
            "pii-explorer-core",
            "--no-default-features",
            "--locked",
        ],
    )?;
    run_cargo(
        root,
        &[
            "test",
            "--package",
            "pii-explorer-cli",
            "--no-default-features",
            "--locked",
        ],
    )
}

fn run_cargo(root: &std::path::Path, args: &[&str]) -> Result<()> {
    let status = Command::new("cargo")
        .args(args)
        .current_dir(root)
        .status()
        .with_context(|| format!("failed to start cargo {}", args.join(" ")))?;
    if !status.success() {
        bail!("cargo {} failed with {status}", args.join(" "));
    }
    Ok(())
}
