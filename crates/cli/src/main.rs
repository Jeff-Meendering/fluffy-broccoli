//! `rollcall`: from a folder of stolen files to a list of the people affected.

use std::fmt::Write as _;
use std::fs::OpenOptions;
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use rollcall_case::{Case, IngestOptions, Values, export_csv, ingest, summarise};

#[derive(Parser)]
#[command(
    name = "rollcall",
    version,
    about = "Breach-response data mining: who was affected, and which of their data was exposed.",
    long_about = "Reads a folder of exfiltrated files into a case and produces a notification \
                  list. Everything runs locally. Use only on data you are authorized to inspect."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Read an evidence folder into a case. Safe to repeat: unchanged files are not read again
    Ingest {
        /// Folder holding the exfiltrated files
        evidence: PathBuf,
        /// Case file to create or update; keep it outside the evidence folder
        #[arg(long)]
        case: PathBuf,
        /// Files larger than this many MiB are hashed and reported, but not read
        #[arg(long, default_value_t = 512, value_parser = clap::value_parser!(u64).range(1..=4096))]
        max_file_mib: u64,
    },
    /// Show the person records in a case, with sensitive identifiers masked
    People {
        #[arg(long)]
        case: PathBuf,
        /// Most rows to print
        #[arg(long, default_value_t = 50)]
        limit: usize,
    },
    /// List evidence that was not, or not fully, turned into person records
    Gaps {
        #[arg(long)]
        case: PathBuf,
    },
    /// Write the notification list as CSV
    Export {
        #[arg(long)]
        case: PathBuf,
        /// File to create; an existing file is never overwritten
        #[arg(long)]
        out: PathBuf,
        /// Whether sensitive identifiers are masked to their last four characters
        #[arg(long, value_enum, default_value_t = ValueMode::Masked)]
        values: ValueMode,
    },
}

#[derive(Clone, Copy, ValueEnum)]
enum ValueMode {
    Masked,
    Full,
}

fn main() -> ExitCode {
    match run(Cli::parse().command) {
        Ok(text) => {
            // A closed pipe (`rollcall people | head`) is not an error worth reporting.
            let _ = std::io::stdout().write_all(text.as_bytes());
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("error: {error:#}");
            ExitCode::FAILURE
        }
    }
}

fn run(command: Command) -> Result<String> {
    match command {
        Command::Ingest {
            evidence,
            case,
            max_file_mib,
        } => ingest_command(&evidence, &case, max_file_mib),
        Command::People { case, limit } => people_command(&case, limit),
        Command::Gaps { case } => gaps_command(&case),
        Command::Export { case, out, values } => {
            let values = match values {
                ValueMode::Masked => Values::Masked,
                ValueMode::Full => Values::Full,
            };
            export_command(&case, &out, values)
        }
    }
}

fn ingest_command(evidence: &Path, case_path: &Path, max_file_mib: u64) -> Result<String> {
    let mut case = Case::create_or_open(case_path)?;
    let options = IngestOptions {
        max_file_bytes: max_file_mib * 1024 * 1024,
        ..IngestOptions::default()
    };
    let summary = ingest(&mut case, evidence, &options)?;
    let mut text = String::new();
    writeln!(text, "Files found:      {}", summary.discovered)?;
    writeln!(text, "  read this run:  {}", summary.read)?;
    writeln!(text, "  unchanged:      {}", summary.reused)?;
    writeln!(text, "  not read:       {}", summary.not_read)?;
    if summary.missing > 0 {
        writeln!(text, "Files no longer in the folder: {}", summary.missing)?;
    }
    writeln!(
        text,
        "Person records:   {} ({} new)",
        summary.total_records, summary.new_records
    )?;
    writeln!(text, "Coverage gaps:    {}", summary.total_gaps)?;
    if summary.total_gaps > 0 {
        writeln!(
            text,
            "\nSome evidence did not become person records. Review it with:\n  rollcall gaps --case {}",
            case_path.display()
        )?;
    }
    Ok(text)
}

fn people_command(case_path: &Path, limit: usize) -> Result<String> {
    let case = Case::open_existing(case_path)?;
    let mut rows = vec![[
        "ID".to_owned(),
        "NAME".to_owned(),
        "EXPOSED".to_owned(),
        "SOURCE".to_owned(),
    ]];
    let mut total = 0_usize;
    case.for_each_record(|record| {
        total += 1;
        if total > limit {
            return Ok(());
        }
        let summary = summarise(&record);
        let mut name = match (summary.name(), &record.relation) {
            ("", _) => "(no name)".to_owned(),
            (name, None) => name.to_owned(),
            (name, Some(relation)) => format!("{name} [{relation}]"),
        };
        if !summary.needs_review.is_empty() {
            name.push_str(" (!)");
        }
        let exposed: Vec<&str> = summary.exposed().iter().map(|kind| kind.as_str()).collect();
        let sheet = record
            .scope
            .as_deref()
            .map(|scope| format!(" [{scope}]"))
            .unwrap_or_default();
        rows.push([
            record.id.to_string(),
            name,
            exposed.join(", "),
            format!("{}{sheet} row {}", record.path, u64::from(record.row) + 1),
        ]);
        Ok(())
    })?;

    let mut text = String::new();
    let widths: Vec<usize> = (0..3)
        .map(|column| {
            rows.iter()
                .map(|row| row[column].chars().count())
                .max()
                .unwrap_or(0)
                .min(48)
        })
        .collect();
    for row in &rows {
        for (cell, width) in row.iter().zip(&widths) {
            let shown: String = cell.chars().take(*width).collect();
            write!(text, "{shown:<width$}  ")?;
        }
        writeln!(text, "{}", row[3])?;
    }
    writeln!(
        text,
        "\n{total} person records; showing {}.",
        total.min(limit)
    )?;
    writeln!(
        text,
        "(!) marks a record with a value that failed validation and needs review."
    )?;
    Ok(text)
}

fn gaps_command(case_path: &Path) -> Result<String> {
    let case = Case::open_existing(case_path)?;
    let gaps = case.gaps()?;
    let mut text = String::new();
    for gap in &gaps {
        let sheet = gap
            .scope
            .as_deref()
            .map(|scope| format!(" [{scope}]"))
            .unwrap_or_default();
        writeln!(
            text,
            "{:<12} {}{sheet}\n             {}",
            gap.kind.as_str(),
            gap.path,
            gap.detail
        )?;
    }
    if gaps.is_empty() {
        writeln!(
            text,
            "No coverage gaps: every file found was read into person records."
        )?;
    } else {
        writeln!(
            text,
            "\nCoverage gaps: {}. Each one is evidence that still needs a person to look at it.",
            gaps.len()
        )?;
    }
    Ok(text)
}

fn export_command(case_path: &Path, out: &Path, values: Values) -> Result<String> {
    let case = Case::open_existing(case_path)?;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // The list holds personal data: readable by its owner only.
        options.mode(0o600);
    }
    let file = options.open(out).with_context(|| {
        format!(
            "could not create {} (existing files are not overwritten)",
            out.display()
        )
    })?;
    let mut writer = BufWriter::new(file);
    let rows = export_csv(&case, &mut writer, values)?;
    writer.flush()?;
    let gaps = case.counts()?.gaps;
    let mut text = format!("Wrote {rows} person records to {}.\n", out.display());
    if values == Values::Full {
        text.push_str("Identifiers are written in full: store and share this file accordingly.\n");
    }
    if gaps > 0 {
        writeln!(
            text,
            "Coverage gaps remaining: {gaps}. The list is not complete until they are reviewed."
        )?;
    }
    Ok(text)
}
