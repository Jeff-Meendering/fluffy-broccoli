//! Import saved CLI JSON/JSONL and desktop JSON without re-reading source evidence.

use std::fs::File;
use std::io::{self, BufRead, BufReader, Read};
use std::path::Path;

use serde::Deserialize;
use thiserror::Error;

use crate::{AttentionItem, Finding, ScanOptions, ScanResult, ScanSummary, SourceRecord};

const MAX_IMPORT_BYTES: u64 = 256 * 1024 * 1024;
const MAX_RECORD_BYTES: u64 = 8 * 1024 * 1024;
const MAX_ITEMS: usize = 1_000_000;

/// Never overwrite an existing export. On Unix, newly captured PII is owner-readable only.
pub fn create_private_file(path: &Path) -> io::Result<File> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)
}

#[derive(Debug, Error)]
pub enum ImportError {
    #[error("Saved scan could not be read: {0}")]
    Io(#[from] io::Error),
    #[error(
        "Saved scan exceeds an import limit (256 MiB, 8 MiB per JSONL record, one million items)."
    )]
    Limit,
    #[error("Input is not a supported saved scan, or has an unsupported format version.")]
    InvalidDocument,
    #[error("Invalid saved scan record at line {0}.")]
    InvalidRecord(u64),
    #[error("Saved scan records appear after the final summary at line {0}.")]
    AfterSummary(u64),
}

#[derive(Deserialize)]
struct Document {
    format_version: Option<u32>,
    result: Option<ScanResult>,
    settings: Option<ScanOptions>,
    findings: Option<Vec<Finding>>,
    attention: Option<Vec<AttentionItem>>,
    sources: Option<Vec<SourceRecord>>,
    summary: Option<ScanSummary>,
}

impl Document {
    fn into_result(self) -> Result<ScanResult, ImportError> {
        if self.format_version.is_some_and(|version| version != 1) {
            return Err(ImportError::InvalidDocument);
        }
        if let Some(result) = self.result {
            return Ok(result);
        }
        Ok(ScanResult {
            settings: self.settings.unwrap_or_default(),
            findings: self.findings.ok_or(ImportError::InvalidDocument)?,
            attention: self.attention.ok_or(ImportError::InvalidDocument)?,
            sources: self.sources.ok_or(ImportError::InvalidDocument)?,
            summary: self.summary.ok_or(ImportError::InvalidDocument)?,
        })
    }
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum Record {
    Finding { finding: Finding },
    Attention { attention: AttentionItem },
    Source { source: SourceRecord },
    Summary { summary: ScanSummary },
    Settings { settings: Box<ScanOptions> },
}

/// A missing JSONL summary is preserved as an incomplete scan. Malformed records are errors;
/// their contents are deliberately excluded from diagnostics because they may contain PII.
pub fn load_scan(path: &Path) -> Result<ScanResult, ImportError> {
    let file = File::open(path)?;
    if file.metadata()?.len() > MAX_IMPORT_BYTES {
        return Err(ImportError::Limit);
    }
    let document =
        serde_json::from_reader::<_, Document>(BufReader::new(file.take(MAX_IMPORT_BYTES + 1)));
    if let Ok(document) = document
        && (document.result.is_some() || document.findings.is_some())
    {
        let result = document.into_result()?;
        check_items(&result)?;
        return Ok(result);
    }

    let mut reader = BufReader::new(File::open(path)?.take(MAX_IMPORT_BYTES + 1));
    let mut result = ScanResult::default();
    let mut summary = false;
    let mut settings = false;
    let mut total = 0_u64;
    let mut line_number = 0_u64;
    loop {
        let mut line = String::new();
        let read = reader
            .by_ref()
            .take(MAX_RECORD_BYTES + 1)
            .read_line(&mut line)?;
        if read == 0 {
            break;
        }
        total += read as u64;
        line_number += 1;
        if total > MAX_IMPORT_BYTES || read as u64 > MAX_RECORD_BYTES {
            return Err(ImportError::Limit);
        }
        if line.trim().is_empty() {
            continue;
        }
        if summary {
            return Err(ImportError::AfterSummary(line_number));
        }
        let record =
            serde_json::from_str(&line).map_err(|_| ImportError::InvalidRecord(line_number))?;
        match record {
            Record::Finding { finding } => result.findings.push(finding),
            Record::Attention { attention } => result.attention.push(attention),
            Record::Source { source } => result.sources.push(source),
            Record::Summary { summary: value } => {
                result.summary = value;
                summary = true;
            }
            Record::Settings { settings: value } => {
                if settings
                    || !result.findings.is_empty()
                    || !result.attention.is_empty()
                    || !result.sources.is_empty()
                {
                    return Err(ImportError::InvalidRecord(line_number));
                }
                result.settings = *value;
                settings = true;
            }
        }
        check_items(&result)?;
    }
    if !summary {
        if !settings
            && result.findings.is_empty()
            && result.attention.is_empty()
            && result.sources.is_empty()
        {
            return Err(ImportError::InvalidDocument);
        }
        result.summary.cancelled = true;
        result.summary.limit_reached = Some("missing stream summary".into());
    }
    result.sort_deterministically();
    Ok(result)
}

fn check_items(result: &ScanResult) -> Result<(), ImportError> {
    if result
        .findings
        .len()
        .saturating_add(result.attention.len())
        .saturating_add(result.sources.len())
        > MAX_ITEMS
    {
        Err(ImportError::Limit)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn load(text: &str) -> Result<ScanResult, ImportError> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("scan.json");
        std::fs::write(&path, text)?;
        load_scan(&path)
    }

    #[test]
    fn imports_both_cli_and_desktop_documents() {
        let result = ScanResult::default();
        let cli = serde_json::to_string(&result).expect("serialize CLI");
        load(&cli).expect("load CLI JSON");
        let desktop = serde_json::json!({"format_version": 1, "scan_root": "/private/case", "result": result});
        load(&desktop.to_string()).expect("load desktop JSON");
        let unsupported = serde_json::json!({"format_version": 999, "result": result});
        assert!(load(&unsupported.to_string()).is_err());
    }

    #[test]
    fn incomplete_streams_are_never_reported_as_complete() {
        let settings = serde_json::json!({"kind": "settings", "settings": ScanOptions::default()});
        let result = load(&format!("{settings}\n")).expect("partial stream");
        assert!(result.summary.cancelled);
        let summary = serde_json::json!({"kind": "summary", "summary": ScanSummary::default()});
        let result = load(&format!("{settings}\n{summary}\n")).expect("complete stream");
        assert!(!result.summary.cancelled);
        assert!(load(&format!("{summary}\n{settings}\n")).is_err());
    }

    #[test]
    fn malformed_records_do_not_echo_sensitive_input() {
        let error =
            load("{\"secret\":\"sensitive@example.com\"}\ninvalid").expect_err("invalid stream");
        assert!(!error.to_string().contains("sensitive"));
        assert!(load("").is_err());
    }
}
