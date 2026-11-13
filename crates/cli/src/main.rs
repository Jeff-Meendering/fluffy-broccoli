#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used))]
mod case;
mod output;
mod predict;
mod review;

use std::collections::BTreeSet;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use clap::{Args, Parser, Subcommand};
use output::{OutputFormat, Redaction};
use pii_explorer_core::custom::CustomRule;
use pii_explorer_core::detectors::EntitySpan;
use pii_explorer_core::evaluation::{
    EvaluationOptions, evaluate_jsonl_with_options, save_evaluation_json,
};
#[cfg(feature = "report")]
use pii_explorer_core::report::{ReportOptions, save_pdf_report};
use pii_explorer_core::{EntityType, ScanEvent, ScanOptions, ScanResult, Scanner, Utf16Index};

#[derive(Debug, Parser)]
#[command(
    name = "pii-explorer",
    version,
    about = "Fast, local PII and credential discovery for authorized security assessments"
)]
#[command(
    long_about = "PII Explorer scans files, archives, documents, images, or stdin without network access. Findings retain occurrence-level provenance. Use only on data you are authorized to inspect."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Scan a file or directory recursively. Use '-' to read UTF-8 text from stdin.
    Scan(ScanArgs),
    /// Detect PII in a literal argument or stdin, without document extraction.
    Detect(DetectArgs),
    /// Evaluate exact UTF-16 spans against a labelled JSONL corpus.
    Evaluate(EvaluateArgs),
    /// Generate a fresh PDF from a saved JSON or JSONL scan.
    #[cfg(feature = "report")]
    Report(ReportArgs),
    /// Rank resources and count distinct values in a saved scan without printing PII values.
    Triage(review::TriageArgs),
    /// Compare unfiltered, unredacted saved scans for an assessment retest.
    Compare(review::CompareArgs),
    /// Capture resumable cases, page through findings and retain analyst review decisions.
    Case(case::CaseArgs),
    /// Compare saved source SHA-256 hashes with the original evidence directory.
    Verify(VerifyArgs),
    /// Predict exact spans for a text-only benchmark (Id/Text JSONL, without gold labels).
    Predict(PredictArgs),
}

#[derive(Debug, Args)]
struct EngineArgs {
    /// Run parsers in this process instead of the default extraction helper (trusted inputs only).
    #[arg(long, global = true)]
    in_process: bool,
    /// Directory containing models/ and ocr/ assets.
    #[arg(long, global = true)]
    assets: Option<PathBuf>,
    /// Disable local model-backed person detection (labelled names still run).
    #[arg(long, global = true)]
    no_names: bool,
    /// Disable local Tesseract OCR.
    #[arg(long, global = true)]
    no_ocr: bool,
    /// Number of file workers (1-8).
    #[arg(long, global = true)]
    jobs: Option<usize>,
    /// Maximum root file or archive member size.
    #[arg(long, global = true, default_value_t = 100)]
    max_file_mib: u64,
    /// Per-root-file deadline, including nested content.
    #[arg(long, global = true, default_value_t = 180)]
    timeout_secs: u64,
    /// Comma-separated libphonenumber region codes.
    #[arg(long, global = true, default_value = "US,GB", value_delimiter = ',')]
    phone_regions: Vec<String>,
    /// JSON file containing an array of declarative custom rules; repeatable.
    #[arg(long, global = true)]
    rules: Vec<PathBuf>,
    /// Do not retain surrounding context in findings.
    #[arg(long, global = true)]
    no_context: bool,
}

#[derive(Debug, Args)]
struct OutputArgs {
    /// Output format. JSONL streams by default during scans.
    #[arg(long, global = true, default_value = "jsonl")]
    format: OutputFormat,
    /// Write to a new file instead of stdout. Existing files are never replaced.
    #[arg(short, long, global = true)]
    output: Option<PathBuf>,
    /// Mask values and omit context, or replace values with SHA-256 fingerprints.
    #[arg(long, global = true, default_value = "none")]
    redact: Redaction,
    /// Emit only these comma-separated entity types (filtering, not detection configuration).
    #[arg(long = "type", global = true, value_delimiter = ',')]
    types: Vec<String>,
    /// Buffer JSONL output until the scan completes.
    #[arg(long, global = true)]
    no_stream: bool,
    /// Exit 4 when any finding is detected.
    #[arg(long, global = true)]
    fail_on_findings: bool,
    /// Exit 3 when any attention item is reported.
    #[arg(long, global = true)]
    fail_on_attention: bool,
}

#[derive(Debug, Args)]
struct ScanArgs {
    /// File, directory, or '-' for stdin.
    path: PathBuf,
    #[command(flatten)]
    engine: EngineArgs,
    #[command(flatten)]
    output: OutputArgs,
    /// Scan default-excluded dependency, VCS, and system directories too.
    #[arg(long)]
    include_excluded: bool,
    /// Exclude directories by exact basename; repeatable, without wildcards.
    #[arg(long = "exclude-dir")]
    exclude_directories: Vec<String>,
}

#[derive(Debug, Args)]
struct DetectArgs {
    /// Literal text or '-' for stdin. Prefer stdin for sensitive data; arguments may enter shell history.
    text: String,
    #[command(flatten)]
    engine: EngineArgs,
    #[command(flatten)]
    output: OutputArgs,
}

#[derive(Debug, Args)]
struct EvaluateArgs {
    /// JSONL corpus with text and entities arrays.
    corpus: PathBuf,
    /// New JSON report path; never overwritten.
    output: PathBuf,
    #[command(flatten)]
    engine: EngineArgs,
}

#[derive(Debug, Args)]
struct PredictArgs {
    input: PathBuf,
    output: PathBuf,
    #[command(flatten)]
    engine: EngineArgs,
}

#[derive(Debug, Args)]
struct VerifyArgs {
    /// Saved CLI JSON/JSONL or desktop JSON scan.
    input: PathBuf,
    /// Original evidence directory (or parent directory of a single scanned file).
    root: PathBuf,
    /// New JSON report path; defaults to stdout.
    #[arg(short, long)]
    output: Option<PathBuf>,
}

#[derive(Debug, Args)]
#[cfg(feature = "report")]
struct ReportArgs {
    /// Saved scan JSON or streaming JSONL.
    input: PathBuf,
    /// New PDF path; never overwritten.
    output: PathBuf,
    /// Original scan root used only to remove host path prefixes.
    #[arg(long)]
    root: Option<PathBuf>,
    /// Replace resource and stream names with stable aliases.
    #[arg(long)]
    hide_file_names: bool,
    /// Include captured context in the PDF.
    #[arg(long)]
    include_context: bool,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(code) => code,
        Err(error) => {
            eprintln!("error: {error:#}");
            ExitCode::from(1)
        }
    }
}

fn run(cli: Cli) -> Result<ExitCode> {
    let cancelled = Arc::new(AtomicBool::new(false));
    let signal = cancelled.clone();
    ctrlc::set_handler(move || {
        signal.store(true, Ordering::SeqCst);
    })
    .context("install Ctrl-C handler")?;

    let (result, output_args) = match cli.command {
        Command::Scan(args) => {
            let ScanArgs {
                path,
                engine,
                output,
                include_excluded,
                exclude_directories,
            } = args;
            parse_types(&output.types)?;
            let mut options = engine.options()?;
            if include_excluded {
                options.excluded_directories.clear();
            }
            for directory in exclude_directories {
                if directory.is_empty()
                    || matches!(directory.as_str(), "." | "..")
                    || directory.contains(['/', '\\'])
                {
                    bail!("exclude-dir must be a directory basename, without path separators");
                }
                options.excluded_directories.insert(directory);
            }
            let scanner = engine.scanner(options.clone())?.with_result_retention(
                !(path != Path::new("-")
                    && output.format == OutputFormat::Jsonl
                    && !output.no_stream),
            );
            if path == Path::new("-") {
                let text = read_stdin(options.max_file_bytes)?;
                (scan_text(&scanner, &text, cancelled, &output)?, output)
            } else {
                if !path.exists() {
                    bail!("scan root does not exist or is not accessible");
                }
                (scan_path(&scanner, &path, cancelled, &output)?, output)
            }
        }
        Command::Detect(args) => {
            let DetectArgs {
                text,
                engine,
                output,
            } = args;
            parse_types(&output.types)?;
            let options = engine.options()?;
            let scanner = engine.scanner(options)?;
            let input = if text == "-" {
                read_stdin(scanner.options().max_file_bytes)?
            } else {
                if text.encode_utf16().count() > 100_000 {
                    bail!(
                        "literal text exceeds the 100,000 UTF-16-unit limit; use a file for larger input"
                    );
                }
                text
            };
            (scan_text(&scanner, &input, cancelled, &output)?, output)
        }
        Command::Evaluate(args) => return evaluate(args, cancelled),
        #[cfg(feature = "report")]
        Command::Report(args) => return generate_report(args),
        Command::Triage(args) => return review::triage(args),
        Command::Compare(args) => return review::compare(args),
        Command::Case(args) => return case::run(args, cancelled),
        Command::Predict(args) => {
            let scanner = args.engine.scanner(args.engine.options()?)?;
            predict::run(&scanner, &args.input, &args.output, cancelled)?;
            return Ok(ExitCode::SUCCESS);
        }
        Command::Verify(args) => {
            let result = pii_explorer_core::storage::load_scan(&args.input)?;
            let report =
                pii_explorer_core::verify::verify_sources(&result, &args.root, &cancelled)?;
            let mut writer = create_writer(args.output.as_deref())?;
            serde_json::to_writer_pretty(&mut writer, &report)?;
            writer.write_all(b"\n")?;
            writer.flush()?;
            return Ok(if report.cancelled {
                ExitCode::from(2)
            } else if report.all_match() {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(5)
            });
        }
    };
    Ok(exit_code(&result, &output_args))
}

fn evaluate(args: EvaluateArgs, cancelled: Arc<AtomicBool>) -> Result<ExitCode> {
    let options = args.engine.options()?;
    if options.detect_names {
        // Evaluation must not silently turn a missing model into false negatives.
        let scanner = args.engine.scanner(options.clone())?;
        if !scanner.name_model_available() {
            bail!(
                "the name model is required for this evaluation; install pinned assets or pass --no-names"
            );
        }
        return evaluate_with_scanner(&args, scanner, options, cancelled);
    }
    let scanner = args.engine.scanner(options.clone())?;
    evaluate_with_scanner(&args, scanner, options, cancelled)
}

fn evaluate_with_scanner(
    args: &EvaluateArgs,
    scanner: Scanner,
    options: ScanOptions,
    cancelled: Arc<AtomicBool>,
) -> Result<ExitCode> {
    let model_path = scanner.model_path();
    let vocab_path = scanner.vocab_path();
    let mut config = serde_json::to_vec(&serde_json::json!({
        "engineVersion": pii_explorer_core::ENGINE_VERSION,
        "namesEnabled": options.detect_names,
        "phoneRegions": &options.phone_regions,
        "customRules": &options.custom_rules,
    }))?;
    if let Some(model) = &model_path
        && let Some(directory) = model.parent()
    {
        for name in ["config.json", "tokenizer_config.json"] {
            let path = directory.join(name);
            if path.is_file() {
                let bytes = std::fs::read(&path)
                    .with_context(|| format!("read model configuration {name}"))?;
                config.extend_from_slice(name.as_bytes());
                config.extend_from_slice(&bytes);
            }
        }
    }
    let evaluation_options = EvaluationOptions {
        names_enabled: options.detect_names,
        model_path,
        vocab_path,
        config: Some(config),
    };
    let detection_cancelled = cancelled.clone();
    let report = evaluate_jsonl_with_options(&args.corpus, evaluation_options, move |text| {
        let result = scanner.detect_text(text, detection_cancelled.clone());
        let index = Utf16Index::new(text);
        result
            .findings
            .into_iter()
            .filter_map(|finding| {
                let start = index.byte_offset(finding.start as usize)?;
                let end = index.byte_offset((finding.start + finding.length) as usize)?;
                Some(EntitySpan::new(
                    finding.entity_type,
                    start,
                    end.checked_sub(start)?,
                    finding.confidence,
                    finding.method,
                ))
            })
            .collect()
    })
    .context("evaluate corpus")?;
    if cancelled.load(Ordering::Relaxed) {
        bail!("evaluation was cancelled; no report was saved");
    }
    save_evaluation_json(&args.output, &report).context("save evaluation report")?;
    let stdout = std::io::stdout();
    let mut output = stdout.lock();
    serde_json::to_writer_pretty(&mut output, &report)?;
    output.write_all(b"\n")?;
    Ok(ExitCode::SUCCESS)
}

#[cfg(feature = "report")]
fn generate_report(args: ReportArgs) -> Result<ExitCode> {
    let mut result = pii_explorer_core::storage::load_scan(&args.input)?;
    result.summary.findings = result.findings.len();
    result.summary.attention = result.attention.len();
    let root = args.root.unwrap_or_default();
    save_pdf_report(
        &args.output,
        &root,
        &result,
        &result.settings,
        ReportOptions::new(args.hide_file_names, args.include_context),
    )
    .context("save PDF report")?;
    eprintln!(
        "Saved a new PDF report with {} findings and {} attention items.",
        result.findings.len(),
        result.attention.len()
    );
    Ok(ExitCode::SUCCESS)
}

fn scan_path(
    scanner: &Scanner,
    path: &Path,
    cancelled: Arc<AtomicBool>,
    output: &OutputArgs,
) -> Result<ScanResult> {
    let stream = output.format == OutputFormat::Jsonl && !output.no_stream;
    if stream {
        if let Some(destination) = output
            .output
            .as_deref()
            .filter(|path| *path != Path::new("-"))
        {
            let parent = destination
                .parent()
                .filter(|parent| !parent.as_os_str().is_empty())
                .unwrap_or(Path::new("."));
            let destination = parent
                .canonicalize()?
                .join(destination.file_name().context("output filename")?);
            let root = path.canonicalize()?;
            if root.is_dir() && destination.starts_with(&root) {
                bail!(
                    "place streaming output outside the scanned directory, or pass --no-stream to save after scanning"
                );
            }
        }
        let writer = create_writer(output.output.as_deref())?;
        let writer = Arc::new(Mutex::new(writer));
        {
            let mut guard = writer
                .lock()
                .map_err(|_| anyhow!("output lock was poisoned"))?;
            output::write_jsonl_settings(&mut **guard, scanner.options())?;
            guard.flush()?;
        }
        let failure = Arc::new(Mutex::new(None::<String>));
        let types = parse_types(&output.types)?;
        let callback_writer = writer.clone();
        let callback_failure = failure.clone();
        let callback_cancelled = cancelled.clone();
        let callback_types = types.clone();
        let redaction = output.redact;
        let result = scanner.scan_with_events(path, cancelled, move |event| {
            let mut guard = match callback_writer.lock() {
                Ok(guard) => guard,
                Err(_) => {
                    callback_cancelled.store(true, Ordering::Relaxed);
                    return;
                }
            };
            let write_result = match event {
                ScanEvent::Findings(findings) => findings.iter().try_for_each(|finding| {
                    output::write_jsonl_finding(&mut *guard, finding, redaction, &callback_types)
                }),
                ScanEvent::Attention(attention) => attention
                    .iter()
                    .try_for_each(|item| output::write_jsonl_attention(&mut *guard, item)),
                ScanEvent::Sources(sources) => sources
                    .iter()
                    .try_for_each(|source| output::write_jsonl_source(&mut *guard, source)),
                ScanEvent::Progress(_) => Ok(()),
            };
            if let Err(error) = write_result.and_then(|()| guard.flush().map_err(Into::into)) {
                *callback_failure
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(error.to_string());
                callback_cancelled.store(true, Ordering::Relaxed);
            }
        })?;
        if let Some(error) = failure
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
        {
            return Err(anyhow!("output failed: {error}"));
        }
        let mut writer = writer
            .lock()
            .map_err(|_| anyhow!("output lock was poisoned"))?;
        output::write_jsonl_summary(&mut **writer, &result.summary)?;
        writer.flush()?;
        Ok(result)
    } else {
        let result = scanner.scan(path, cancelled)?;
        write_complete(&result, output)?;
        Ok(result)
    }
}

fn scan_text(
    scanner: &Scanner,
    text: &str,
    cancelled: Arc<AtomicBool>,
    output: &OutputArgs,
) -> Result<ScanResult> {
    // Text detection is bounded and normally fast; a complete document avoids interleaving
    // records with unrelated processes writing to the same stdout.
    let result = scanner.detect_text(text, cancelled);
    write_complete(&result, output)?;
    Ok(result)
}

fn write_complete(result: &ScanResult, output: &OutputArgs) -> Result<()> {
    let types = parse_types(&output.types)?;
    let mut writer = create_writer(output.output.as_deref())?;
    output::write_result(&mut *writer, result, output.format, output.redact, &types)?;
    writer.flush()?;
    Ok(())
}

fn create_writer(path: Option<&Path>) -> Result<Box<dyn Write + Send>> {
    match path {
        None => Ok(Box::new(std::io::BufWriter::new(std::io::stdout()))),
        Some(path) if path == Path::new("-") => {
            Ok(Box::new(std::io::BufWriter::new(std::io::stdout())))
        }
        Some(path) => {
            let file = pii_explorer_core::storage::create_private_file(path)
                .with_context(|| format!("create new output file {}", path.display()))?;
            Ok(Box::new(std::io::BufWriter::new(file)))
        }
    }
}

fn read_stdin(limit: u64) -> Result<String> {
    let mut bytes = Vec::new();
    std::io::stdin()
        .take(limit.saturating_add(1))
        .read_to_end(&mut bytes)
        .context("read stdin")?;
    if bytes.len() as u64 > limit {
        bail!("stdin exceeds the configured file-size limit");
    }
    String::from_utf8(bytes).context("stdin must be UTF-8; use a file path for other encodings")
}

impl EngineArgs {
    fn scanner(&self, options: ScanOptions) -> Result<Scanner> {
        let scanner = Scanner::new(options).context("configure scanner")?;
        if self.in_process {
            return Ok(scanner);
        }
        let worker =
            pii_explorer_isolation::WorkerPool::new(pii_explorer_isolation::default_worker()?)?;
        Ok(scanner.with_extractor(Arc::new(worker)))
    }

    fn options(&self) -> Result<ScanOptions> {
        let mut options = ScanOptions {
            detect_names: cfg!(feature = "ner") && !self.no_names,
            ocr: cfg!(feature = "ocr") && !self.no_ocr,
            include_context: !self.no_context,
            max_file_bytes: self
                .max_file_mib
                .checked_mul(1024 * 1024)
                .context("file-size limit overflows")?,
            ..ScanOptions::default()
        };
        if options.max_file_bytes == 0 || options.max_file_bytes > 2 * 1024 * 1024 * 1024 {
            bail!("max-file-mib must be between 1 and 2048");
        }
        if self.timeout_secs == 0 {
            bail!("timeout-secs must be positive");
        }
        options.file_timeout = Duration::from_secs(self.timeout_secs);
        if let Some(jobs) = self.jobs {
            if !(1..=8).contains(&jobs) {
                bail!("jobs must be between 1 and 8");
            }
            options.workers = jobs;
        }
        options.phone_regions = self
            .phone_regions
            .iter()
            .map(|region| region.trim().to_ascii_uppercase())
            .filter(|region| !region.is_empty())
            .collect();
        if options.phone_regions.is_empty() {
            bail!("at least one phone region is required");
        }
        for path in &self.rules {
            let metadata = std::fs::metadata(path)
                .with_context(|| format!("read custom rules from {}", path.display()))?;
            if metadata.len() > 1024 * 1024 {
                bail!("custom rule file exceeds 1 MiB");
            }
            let text = std::fs::read_to_string(path)?;
            let mut rules: Vec<CustomRule> = serde_json::from_str(&text)
                .with_context(|| format!("parse custom rules in {}", path.display()))?;
            options.custom_rules.append(&mut rules);
        }
        if let Some(assets) = &self.assets {
            options.model_path = Some(assets.join("models/model_quantized.onnx"));
            options.vocab_path = Some(assets.join("models/vocab.txt"));
            let tesseract = if cfg!(windows) {
                assets.join("ocr/tesseract.exe")
            } else {
                assets.join("ocr/tesseract")
            };
            // The pinned asset manifest contains language data, not a platform executable.
            // Fall back to system Tesseract unless the package explicitly bundles one.
            options.tesseract_path = tesseract.is_file().then_some(tesseract);
            options.tessdata_path = Some(assets.join("ocr/tessdata"));
        }
        Ok(options)
    }
}

fn parse_types(values: &[String]) -> Result<BTreeSet<EntityType>> {
    values
        .iter()
        .map(|value| {
            let normalized = value.trim();
            EntityType::parse(normalized)
                .or_else(|| match normalized.to_ascii_lowercase().as_str() {
                    "ssn" => Some(EntityType::SocialSecurityNumber),
                    "card" | "credit-card" => Some(EntityType::PaymentCard),
                    "dob" => Some(EntityType::DateOfBirth),
                    "ip" => Some(EntityType::IpAddress),
                    "mac" => Some(EntityType::MacAddress),
                    "iban" => Some(EntityType::Iban),
                    "national-id" => Some(EntityType::NationalId),
                    "wallet" | "crypto" => Some(EntityType::CryptoWallet),
                    "secret" | "secrets" => Some(EntityType::Credential),
                    _ => EntityType::ALL
                        .into_iter()
                        .find(|kind| kind.as_str().eq_ignore_ascii_case(normalized)),
                })
                .ok_or_else(|| anyhow!("unknown entity type '{value}'"))
        })
        .collect()
}

fn exit_code(result: &ScanResult, output: &OutputArgs) -> ExitCode {
    if result.summary.cancelled {
        ExitCode::from(2)
    } else if output.fail_on_attention && result.summary.attention > 0 {
        ExitCode::from(3)
    } else if output.fail_on_findings && result.summary.findings > 0 {
        ExitCode::from(4)
    } else {
        ExitCode::SUCCESS
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn type_aliases_and_exact_names_parse() {
        let types = parse_types(&["email,ssn".into()]).expect_err("delimiter is handled by clap");
        assert!(types.to_string().contains("unknown"));
        let types = parse_types(&["email".into(), "ssn".into(), "Date of birth".into()])
            .expect("known types");
        assert_eq!(types.len(), 3);
    }

    #[test]
    fn exit_policies_are_explicit() {
        let output = OutputArgs {
            format: OutputFormat::Jsonl,
            output: None,
            redact: Redaction::None,
            types: Vec::new(),
            no_stream: false,
            fail_on_findings: true,
            fail_on_attention: true,
        };
        let mut result = ScanResult::default();
        assert_eq!(exit_code(&result, &output), ExitCode::SUCCESS);
        result.findings.push(pii_explorer_core::Finding {
            entity_type: EntityType::Email,
            value: "alice@example.com".into(),
            start: 0,
            length: 17,
            context: String::new(),
            context_start: 0,
            detector_start: 0,
            detector_length: 17,
            confidence: 1.0,
            method: "test".into(),
            origin: pii_explorer_core::EvidenceOrigin::text("test", "body", "decoded-text"),
        });
        result.summary.findings = 1;
        assert_eq!(exit_code(&result, &output), ExitCode::from(4));
        result.summary.cancelled = true;
        assert_eq!(exit_code(&result, &output), ExitCode::from(2));
    }
}
