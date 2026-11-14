#![allow(clippy::expect_used, clippy::unwrap_used)]
//! Exercise the shipped command boundary rather than duplicating detector unit tests.

use std::io::Write;
use std::path::Path;
use std::process::{Command, Output, Stdio};

use serde_json::Value;
use tempfile::TempDir;

fn cli() -> Command {
    Command::new(env!("CARGO_BIN_EXE_pii-explorer"))
}

fn success(output: Output) -> Output {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

fn save_scan(root: &Path, destination: &Path) {
    success(
        cli()
            .arg("scan")
            .arg(root)
            .args(["--no-names", "--no-ocr", "--format", "json"])
            .arg("--output")
            .arg(destination)
            .output()
            .expect("scan process"),
    );
}

#[test]
fn stdin_jsonl_has_utf16_spans_settings_hashes_and_final_summary() {
    let mut child = cli()
        .args(["scan", "-", "--no-names", "--no-ocr"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("process");
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all("😀 alice@example.com".as_bytes())
        .expect("input");
    let output = success(child.wait_with_output().expect("output"));
    let records: Vec<Value> = String::from_utf8(output.stdout)
        .expect("UTF-8")
        .lines()
        .map(|line| serde_json::from_str(line).expect("JSONL record"))
        .collect();
    assert_eq!(records.first().expect("settings")["kind"], "settings");
    assert_eq!(records.last().expect("summary")["kind"], "summary");
    let finding = records
        .iter()
        .find(|row| row["kind"] == "finding")
        .expect("finding");
    assert_eq!(finding["finding"]["start"], 3);
    let source = records
        .iter()
        .find(|row| row["kind"] == "source")
        .expect("source");
    assert_eq!(source["source"]["sha256"].as_str().expect("hash").len(), 64);
}

#[test]
fn streamed_outputs_cannot_scan_themselves_and_existing_exports_survive() {
    let directory = TempDir::new().expect("directory");
    std::fs::write(directory.path().join("input.txt"), "alice@example.com").expect("fixture");
    let destination = directory.path().join("output.jsonl");
    let output = cli()
        .arg("scan")
        .arg(directory.path())
        .args(["--no-names", "--no-ocr"])
        .arg("-o")
        .arg(&destination)
        .output()
        .expect("process");
    assert_eq!(output.status.code(), Some(1));
    assert!(!destination.exists());
    std::fs::write(&destination, "original").expect("existing export");
    let output = cli()
        .args(["detect", "alice@example.com", "--no-names", "--no-ocr"])
        .arg("-o")
        .arg(&destination)
        .output()
        .expect("process");
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(
        std::fs::read_to_string(destination).expect("existing export"),
        "original"
    );
}

#[test]
fn scan_retest_triage_and_verification_work_from_saved_artifacts() {
    let directory = TempDir::new().expect("directory");
    let evidence = directory.path().join("evidence");
    std::fs::create_dir(&evidence).expect("evidence directory");
    let file = evidence.join("records.txt");
    std::fs::write(&file, "a@example.com a@example.com b@example.org").expect("before");
    let before = directory.path().join("before.json");
    let after = directory.path().join("after.json");
    save_scan(&evidence, &before);
    success(
        cli()
            .arg("verify")
            .arg(&before)
            .arg(&evidence)
            .output()
            .expect("verify"),
    );
    std::fs::write(&file, "inserted a@example.com c@example.net").expect("after");
    let verification = cli()
        .arg("verify")
        .arg(&before)
        .arg(&evidence)
        .output()
        .expect("verify changes");
    assert_eq!(verification.status.code(), Some(5));
    save_scan(&evidence, &after);
    let output = cli()
        .arg("compare")
        .arg(&before)
        .arg(&after)
        .arg("--fail-on-new")
        .output()
        .expect("compare");
    assert_eq!(output.status.code(), Some(4));
    let report: Value = serde_json::from_slice(&output.stdout).expect("comparison JSON");
    assert_eq!(report["unchanged_occurrences"], 1);
    assert_eq!(report["current_only_occurrences"], 1);
    assert_eq!(report["baseline_only_occurrences"], 2);
    assert!(!String::from_utf8_lossy(&output.stdout).contains("@example"));
    let output = success(cli().arg("triage").arg(&before).output().expect("triage"));
    let report: Value = serde_json::from_slice(&output.stdout).expect("triage JSON");
    assert_eq!(report["by_type"]["Email"]["distinct_values"], 2);
    assert_eq!(report["top_resources"][0]["occurrences"], 3);
}

#[test]
fn masking_filters_and_exit_policies_apply_across_output_formats() {
    for format in ["json", "jsonl", "csv", "sarif", "text"] {
        let output = cli()
            .args([
                "detect",
                "alice@example.com",
                "--no-names",
                "--no-ocr",
                "--format",
                format,
                "--redact",
                "mask",
                "--fail-on-findings",
            ])
            .output()
            .expect("redacted output");
        assert_eq!(output.status.code(), Some(4), "{format}");
        let text = String::from_utf8(output.stdout).expect("output");
        assert!(!text.contains("alice@example.com"), "{format}: {text}");
    }
    let output = cli()
        .args([
            "detect",
            "alice@example.com",
            "--no-names",
            "--no-ocr",
            "--format",
            "json",
            "--type",
            "ssn",
            "--fail-on-findings",
        ])
        .output()
        .expect("filtered output");
    // Filtering changes presentation only; it must not hide detections from an exit policy.
    assert_eq!(output.status.code(), Some(4));
    let report: Value = serde_json::from_slice(&output.stdout).expect("JSON");
    assert_eq!(report["findings"].as_array().expect("findings").len(), 0);
    assert_eq!(report["summary"]["findings"], 1);
}

#[test]
fn csv_neutralizes_formula_in_attacker_controlled_paths() {
    let directory = TempDir::new().expect("directory");
    std::fs::write(directory.path().join("=SUM(1).txt"), "alice@example.com").expect("fixture");
    let output = success(
        cli()
            .arg("scan")
            .arg(directory.path())
            .args(["--no-names", "--no-ocr", "--format", "csv"])
            .output()
            .expect("CSV process"),
    );
    let text = String::from_utf8(output.stdout).expect("CSV");
    assert!(text.contains("'=SUM(1).txt"));
}

#[test]
fn durable_case_commands_capture_review_resume_page_and_export() {
    let directory = TempDir::new().expect("directory");
    let root = directory.path().join("evidence");
    std::fs::create_dir(&root).expect("root");
    std::fs::write(root.join("contacts.txt"), "a@example.com a@example.com").expect("fixture");
    let case = directory.path().join("assessment.piicase");
    let scan = |resume: bool| {
        let mut command = cli();
        command
            .args(["case", "scan"])
            .arg(&root)
            .arg("--case")
            .arg(&case)
            .args(["--no-names", "--no-ocr"]);
        if resume {
            command.arg("--resume");
        }
        let output = success(command.output().expect("capture"));
        serde_json::from_slice::<Value>(&output.stdout).expect("summary")
    };
    assert_eq!(scan(false)["findings"], 2);
    let output = success(
        cli()
            .args(["case", "show"])
            .arg(&case)
            .args(["--limit", "1"])
            .output()
            .expect("page"),
    );
    let page: Value = serde_json::from_slice(&output.stdout).expect("page JSON");
    let id = page["findings"][0]["id"].as_i64().expect("finding ID");
    assert!(page["next_after"].is_number());
    success(
        cli()
            .args(["case", "review"])
            .arg(&case)
            .arg(id.to_string())
            .args([
                "--status",
                "confirmed",
                "--note",
                "checked with synthetic data",
            ])
            .output()
            .expect("review"),
    );
    assert_eq!(scan(true)["reused"], 1);
    let output = success(
        cli()
            .args(["case", "show"])
            .arg(&case)
            .args(["--status", "confirmed", "--type", "email"])
            .output()
            .expect("reviewed page"),
    );
    let page: Value = serde_json::from_slice(&output.stdout).expect("page JSON");
    assert_eq!(page["findings"].as_array().expect("findings").len(), 1);
    let export = directory.path().join("case.jsonl");
    success(
        cli()
            .args(["case", "export"])
            .arg(&case)
            .arg(&export)
            .output()
            .expect("export"),
    );
    let restored =
        pii_explorer_core::storage::load_scan(&export).expect("read complete case export");
    assert_eq!(restored.findings.len(), 2);
    assert!(!restored.summary.cancelled);
    success(
        cli()
            .args(["case", "integrity"])
            .arg(&case)
            .output()
            .expect("integrity"),
    );
}

#[cfg(feature = "report")]
#[test]
fn saved_jsonl_can_generate_a_new_pdf_without_source_access() {
    let directory = TempDir::new().expect("directory");
    let saved = directory.path().join("scan.jsonl");
    success(
        cli()
            .args(["detect", "alice@example.com", "--no-names", "--no-ocr"])
            .arg("-o")
            .arg(&saved)
            .output()
            .expect("capture"),
    );
    let report = directory.path().join("report.pdf");
    success(
        cli()
            .arg("report")
            .arg(saved)
            .arg(&report)
            .output()
            .expect("report"),
    );
    assert!(std::fs::read(report).expect("PDF").starts_with(b"%PDF-"));
}
