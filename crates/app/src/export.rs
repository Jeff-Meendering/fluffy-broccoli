use std::io::{self, BufWriter, Write};
use std::path::Path;

use anyhow::{Context, bail};
use pii_explorer_core::ScanResult;
use pii_explorer_core::report::{PdfReport, ReportOptions, ReportSnapshot};

/// Writes every finding, attention item, source hash, and summary, regardless of GUI filters.
pub fn export_json(destination: &Path, root: &Path, result: &ScanResult) -> anyhow::Result<()> {
    let file = pii_explorer_core::storage::create_private_file(destination).with_context(|| {
        match destination.exists() {
            true => format!(
                "{} already exists. Choose a new filename; existing exports are never overwritten.",
                destination.display()
            ),
            false => format!("Could not create {}.", destination.display()),
        }
    })?;
    let mut writer = BufWriter::new(file);
    // Stream the outer object too: `serde_json::to_value` would duplicate every finding string.
    writer.write_all(b"{\n  \"format_version\": 1,\n  \"engine_version\": ")?;
    serde_json::to_writer(&mut writer, pii_explorer_core::ENGINE_VERSION)?;
    writer.write_all(b",\n  \"scan_root\": ")?;
    serde_json::to_writer(&mut writer, &root.to_string_lossy())?;
    writer.write_all(b",\n  \"result\": ")?;
    serde_json::to_writer_pretty(&mut writer, result)
        .context("Could not serialize the scan export.")?;
    writer.write_all(b"\n}\n")?;
    writer
        .flush()
        .context("Could not finish writing the JSON export.")?;
    Ok(())
}

/// Single integration point for core's metadata-free, non-overwriting PDF report writer.
pub fn export_pdf(
    destination: &Path,
    root: &Path,
    result: &ScanResult,
    hide_file_names: bool,
    include_context: bool,
) -> io::Result<()> {
    PdfReport::save(
        destination,
        &ReportSnapshot::from_result(
            root,
            result,
            ReportOptions::new(hide_file_names, include_context),
        ),
    )
}

pub fn ensure_json_extension(path: &mut std::path::PathBuf) {
    if path
        .extension()
        .is_none_or(|extension| !extension.eq_ignore_ascii_case("json"))
    {
        path.set_extension("json");
    }
}

pub fn ensure_pdf_extension(path: &mut std::path::PathBuf) {
    if path
        .extension()
        .is_none_or(|extension| !extension.eq_ignore_ascii_case("pdf"))
    {
        path.set_extension("pdf");
    }
}

pub fn validate_export_destination(path: &Path) -> anyhow::Result<()> {
    if path.as_os_str().is_empty() {
        bail!("Choose a destination filename.");
    }
    if path.is_dir() {
        bail!("The export destination is a folder. Choose a new export filename.");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use pii_explorer_core::{AttentionItem, ScanOptions, ScanSummary};

    use super::*;

    static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

    fn temporary_directory() -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!(
            "pii-explorer-app-test-{}-{}",
            std::process::id(),
            NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).expect("create temporary test directory");
        path
    }

    #[test]
    fn json_export_contains_the_complete_unfiltered_result() {
        let directory = temporary_directory();
        let destination = directory.join("findings.json");
        let result = ScanResult {
            findings: Vec::new(),
            attention: vec![AttentionItem {
                resource_id: "hidden-by-filter.txt".into(),
                message: "This item must still be exported".into(),
            }],
            sources: Vec::new(),
            settings: ScanOptions::default(),
            summary: ScanSummary {
                discovered: 4,
                completed: 3,
                findings: 0,
                attention: 1,
                cancelled: true,
                limit_reached: None,
                elapsed_ms: 12,
            },
        };
        export_json(&destination, Path::new("/scan"), &result).expect("export JSON");
        let value: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&destination).expect("read exported JSON"))
                .expect("parse exported JSON");
        assert_eq!(
            value["result"]["attention"][0]["resource_id"],
            "hidden-by-filter.txt"
        );
        assert_eq!(value["result"]["summary"]["completed"], 3);

        let error = export_json(&destination, Path::new("/scan"), &result)
            .expect_err("existing destination must not be replaced");
        assert!(error.to_string().contains("already exists"));
        std::fs::remove_dir_all(directory).expect("remove temporary test directory");
    }

    #[test]
    fn json_extension_is_added_or_normalized() {
        let mut path = std::path::PathBuf::from("report");
        ensure_json_extension(&mut path);
        assert_eq!(path, std::path::PathBuf::from("report.json"));
        let mut path = std::path::PathBuf::from("report.txt");
        ensure_json_extension(&mut path);
        assert_eq!(path, std::path::PathBuf::from("report.json"));
        let mut path = std::path::PathBuf::from("report.JSON");
        ensure_json_extension(&mut path);
        assert_eq!(path, std::path::PathBuf::from("report.JSON"));
    }
}
