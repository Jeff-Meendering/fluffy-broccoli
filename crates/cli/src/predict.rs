//! Text-only benchmark adapter. Gold annotations are never passed to this process.

use std::collections::HashSet;
use std::fs::File;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::Path;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::Instant;

use anyhow::{Context, Result, bail};
use pii_explorer_core::{
    Scanner,
    hash::{sha256_hex, sha256_reader},
};
use serde::Deserialize;
use serde_json::json;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    #[serde(rename = "Id")]
    id: String,
    #[serde(rename = "Text")]
    text: String,
}

pub fn run(
    scanner: &Scanner,
    input: &Path,
    output: &Path,
    cancelled: Arc<AtomicBool>,
) -> Result<()> {
    if scanner.options().detect_names && !scanner.name_model_available() {
        bail!("prediction requires the pinned name model; install assets or pass --no-names");
    }
    if output.exists() {
        bail!("prediction output already exists; choose a new filename");
    }
    let parent = output
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let mut temporary = tempfile::Builder::new()
        .prefix(".pii-prediction-")
        .tempfile_in(parent)?;
    let mut reader = BufReader::new(File::open(input).context("open text prediction inputs")?);
    let mut ids = HashSet::new();
    let mut line_number = 0_u64;
    loop {
        if cancelled.load(Ordering::Relaxed) {
            bail!("prediction cancelled; no complete output was saved");
        }
        let mut line = String::new();
        let read = reader.by_ref().take(2_048_001).read_line(&mut line)?;
        if read == 0 {
            break;
        }
        line_number += 1;
        if read > 2_048_000 {
            bail!("prediction record at line {line_number} exceeds 2,048,000 bytes");
        }
        if line.trim().is_empty() {
            continue;
        }
        let row: Input = serde_json::from_str(&line).map_err(|_| {
            anyhow::anyhow!(
                "invalid prediction input at line {line_number}; expected only Id and Text"
            )
        })?;
        if row.id.is_empty()
            || row.id.len() > 1024
            || row.text.encode_utf16().count() > 100_000
            || !ids.insert(row.id.clone())
            || ids.len() > 1_000_000
        {
            bail!("invalid, oversized, or duplicate prediction input at line {line_number}");
        }
        let started = Instant::now();
        let result = scanner.detect_text(&row.text, cancelled.clone());
        if result.summary.cancelled || !result.attention.is_empty() {
            bail!("detection was incomplete at line {line_number}; no complete output was saved");
        }
        let entities = result
            .findings
            .iter()
            .map(|finding| {
                json!({
                    "Type": finding.entity_type, "Start": finding.start, "Length": finding.length,
                })
            })
            .collect::<Vec<_>>();
        serde_json::to_writer(
            &mut temporary,
            &json!({
                "Id": row.id, "TextSha256": sha256_hex(row.text.as_bytes()),
                "Entities": entities, "Seconds": started.elapsed().as_secs_f64(),
            }),
        )?;
        temporary.write_all(b"\n")?;
    }
    if ids.is_empty() {
        bail!("prediction input is empty");
    }
    if cancelled.load(Ordering::Relaxed) {
        bail!("prediction cancelled; no complete output was saved");
    }
    let mut assets = std::collections::BTreeMap::new();
    for path in [scanner.model_path(), scanner.vocab_path()]
        .into_iter()
        .flatten()
    {
        if scanner.options().detect_names {
            let name = path
                .file_name()
                .context("asset filename")?
                .to_string_lossy()
                .into_owned();
            assets.insert(name, sha256_reader(&mut File::open(path)?)?);
        }
    }
    let executable_hash = sha256_reader(&mut File::open(std::env::current_exe()?)?)?;
    temporary.flush()?;
    temporary.as_file().sync_all()?;
    temporary
        .persist_noclobber(output)
        .context("save complete predictions without overwriting")?;
    let stdout = std::io::stdout();
    let mut writer = stdout.lock();
    serde_json::to_writer(
        &mut writer,
        &json!({
            "engine": "PII Explorer Rust", "version": pii_explorer_core::ENGINE_VERSION,
            "names": scanner.options().detect_names, "phoneRegions": scanner.options().phone_regions,
            "cases": ids.len(), "assets": assets, "executableSha256": executable_hash,
            "networking": "local inference only",
        }),
    )?;
    writer.write_all(b"\n")?;
    Ok(())
}
