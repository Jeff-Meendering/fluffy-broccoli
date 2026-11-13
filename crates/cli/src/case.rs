use std::collections::BTreeMap;
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::{Arc, atomic::AtomicBool};

use anyhow::Result;
use clap::{Args, Subcommand, ValueEnum};
use pii_explorer_case::{CaseScanOptions, CaseStore, ReviewStatus, scan_case};
use pii_explorer_core::{Scanner, hash::sha256_reader};
use serde_json::{Value, json};

#[derive(Debug, Args)]
pub struct CaseArgs {
    #[command(subcommand)]
    command: CaseCommand,
}

#[derive(Debug, Subcommand)]
enum CaseCommand {
    /// Capture to a new case, or resume/incrementally scan an existing case with --resume.
    Scan {
        path: PathBuf,
        #[arg(long)]
        case: PathBuf,
        #[arg(long)]
        resume: bool,
        /// Bypass content/configuration cache while retaining earlier runs.
        #[arg(long)]
        refresh: bool,
        #[command(flatten)]
        engine: crate::EngineArgs,
        #[arg(long)]
        fail_on_findings: bool,
        #[arg(long)]
        fail_on_attention: bool,
        #[arg(long)]
        include_excluded: bool,
    },
    /// Page through findings without loading an entire case into memory.
    Show {
        case: PathBuf,
        #[arg(long)]
        run: Option<i64>,
        #[arg(long, default_value_t = 0)]
        after: i64,
        #[arg(long, default_value_t = 100, value_parser=clap::value_parser!(u16).range(1..=1000))]
        limit: u16,
        #[arg(long)]
        status: Option<ReviewChoice>,
        #[arg(long = "type")]
        entity: Option<String>,
    },
    /// Show the latest 1,000 scan runs and their configuration fingerprints.
    Runs { case: PathBuf },
    /// Export one run as JSONL, including partial coverage and additive review metadata.
    Export {
        case: PathBuf,
        output: PathBuf,
        #[arg(long)]
        run: Option<i64>,
    },
    /// Persist a review decision for an exact finding in an unchanged source snapshot.
    Review {
        case: PathBuf,
        finding: i64,
        #[arg(long)]
        status: ReviewChoice,
        #[arg(long, default_value = "")]
        note: String,
        #[arg(long, default_value = "local")]
        reviewer: String,
    },
    /// Check SQLite structure, captured finding hashes and the review audit chain.
    Integrity { case: PathBuf },
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum ReviewChoice {
    Unreviewed,
    Confirmed,
    FalsePositive,
    NeedsReview,
}
impl From<ReviewChoice> for ReviewStatus {
    fn from(value: ReviewChoice) -> Self {
        match value {
            ReviewChoice::Unreviewed => Self::Unreviewed,
            ReviewChoice::Confirmed => Self::Confirmed,
            ReviewChoice::FalsePositive => Self::FalsePositive,
            ReviewChoice::NeedsReview => Self::NeedsReview,
        }
    }
}

pub fn run(args: CaseArgs, cancelled: Arc<AtomicBool>) -> Result<ExitCode> {
    let value = match args.command {
        CaseCommand::Scan {
            path,
            case,
            resume,
            refresh,
            engine,
            fail_on_findings,
            fail_on_attention,
            include_excluded,
        } => {
            let mut options = engine.options()?;
            if include_excluded {
                options.excluded_directories.clear();
            }
            let scanner = engine.scanner(options)?;
            let engine = fingerprint(&scanner, engine.in_process)?;
            let summary = scan_case(
                scanner,
                &path,
                &case,
                CaseScanOptions {
                    resume,
                    refresh,
                    engine,
                },
                cancelled,
            )?;
            write_json(&summary)?;
            return Ok(if summary.status != "complete" {
                ExitCode::from(2)
            } else if fail_on_attention && summary.attention > 0 {
                ExitCode::from(3)
            } else if fail_on_findings && summary.findings > 0 {
                ExitCode::from(4)
            } else {
                ExitCode::SUCCESS
            });
        }
        CaseCommand::Show {
            case,
            run,
            after,
            limit,
            status,
            entity,
        } => {
            let entity = entity
                .map(|entity| crate::parse_types(&[entity]))
                .transpose()?;
            let entity = entity
                .as_ref()
                .and_then(|entities| entities.first())
                .map(|kind| kind.as_str());
            serde_json::to_value(CaseStore::open(&case, true)?.findings(
                run,
                after,
                usize::from(limit),
                status.map(Into::into),
                entity,
            )?)?
        }
        CaseCommand::Runs { case } => json!({"runs": CaseStore::open(&case,true)?.runs()?}),
        CaseCommand::Export { case, output, run } => {
            let store = CaseStore::open(&case, true)?;
            let mut writer = crate::create_writer(Some(&output))?;
            store.export_jsonl(run, &mut writer)?;
            return Ok(ExitCode::SUCCESS);
        }
        CaseCommand::Review {
            case,
            finding,
            status,
            note,
            reviewer,
        } => {
            CaseStore::open(&case, false)?.review(finding, status.into(), &note, &reviewer)?;
            json!({"finding_id":finding,"status":ReviewStatus::from(status),"saved":true})
        }
        CaseCommand::Integrity { case } => CaseStore::open(&case, true)?.integrity()?,
    };
    write_json(&value)?;
    Ok(ExitCode::SUCCESS)
}

fn write_json(value: &impl serde::Serialize) -> Result<()> {
    let mut writer = std::io::stdout().lock();
    serde_json::to_writer_pretty(&mut writer, value)?;
    writer.write_all(b"\n")?;
    Ok(())
}

fn fingerprint(scanner: &Scanner, in_process: bool) -> Result<Value> {
    let options = scanner.options();
    let mut assets = BTreeMap::new();
    if !in_process {
        assets.insert(
            "extraction_worker".into(),
            sha256_reader(&mut File::open(pii_explorer_isolation::default_worker()?)?)?,
        );
    }
    if options.detect_names {
        for (name, path) in [
            ("name_model", scanner.model_path()),
            ("name_vocab", scanner.vocab_path()),
        ] {
            if let Some(path) = path.filter(|path| path.is_file()) {
                assets.insert(name.to_owned(), sha256_reader(&mut File::open(path)?)?);
            }
        }
        if let Some(directory) = scanner
            .model_path()
            .and_then(|path| path.parent().map(ToOwned::to_owned))
        {
            for name in ["config.json", "tokenizer_config.json"] {
                let path = directory.join(name);
                if path.is_file() {
                    assets.insert(name.to_owned(), sha256_reader(&mut File::open(path)?)?);
                }
            }
        }
    }
    if options.ocr {
        if let Some(executable) = &options.tesseract_path {
            assets.insert(
                "tesseract_executable".into(),
                sha256_reader(&mut File::open(executable)?)?,
            );
        }
        if let Some(directory) = &options.tessdata_path {
            for name in ["eng.traineddata", "osd.traineddata"] {
                let path = directory.join(name);
                if path.is_file() {
                    assets.insert(name.to_owned(), sha256_reader(&mut File::open(path)?)?);
                }
            }
        }
    }
    Ok(json!({
        "version":pii_explorer_core::ENGINE_VERSION,
        "executable_sha256":sha256_reader(&mut File::open(std::env::current_exe()?)?)?,
        "extraction":{"mode":if in_process {"in-process"} else {"worker"},"controls":pii_explorer_isolation::ISOLATION_DESCRIPTION},
        "model_available":scanner.name_model_available(),
        "assets":assets,
        "os":std::env::consts::OS,"architecture":std::env::consts::ARCH,
        "features":{"formats":cfg!(feature="formats"),"archives":cfg!(feature="archives"),"ocr":cfg!(feature="ocr"),"ner":cfg!(feature="ner"),"report":cfg!(feature="report")},
        "limits":"Fingerprints cover the executable, selected assets and recorded settings; transitive system libraries and acquisition authenticity are not established."
    }))
}
