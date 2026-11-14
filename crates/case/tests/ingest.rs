//! End-to-end behaviour of a case: ingest, reuse, change detection and export.

// Test helpers fail the test by panicking, like the tests themselves.
#![allow(clippy::unwrap_used)]

use std::fs;
use std::path::Path;

use rollcall_case::{Case, IngestOptions, Values, export_records_csv as export_csv, ingest};
use rollcall_model::GapKind;
use tempfile::TempDir;

const STAFF: &str = "Name,SSN,Email\nJane Doe,219-09-9999,jane@example.com\nJohn Roe,219-09-9998,john@example.com\n";

fn evidence() -> TempDir {
    let folder = tempfile::tempdir().unwrap();
    fs::create_dir_all(folder.path().join("hr")).unwrap();
    fs::write(folder.path().join("hr/staff.csv"), STAFF).unwrap();
    fs::write(folder.path().join("stock.csv"), "SKU,Qty\nA-1,4\n").unwrap();
    fs::write(folder.path().join("memo.pdf"), b"not read yet").unwrap();
    folder
}

fn export(case: &Case, values: Values) -> String {
    let mut output = Vec::new();
    export_csv(case, &mut output, values).unwrap();
    String::from_utf8(output).unwrap()
}

fn run(case: &mut Case, folder: &Path) -> rollcall_case::IngestSummary {
    ingest(case, folder, &IngestOptions::default()).unwrap()
}

#[test]
fn every_file_is_either_read_into_records_or_listed_as_a_gap() {
    let folder = evidence();
    let home = tempfile::tempdir().unwrap();
    let mut case = Case::create_or_open(&home.path().join("case.rollcall")).unwrap();

    let summary = run(&mut case, folder.path());
    assert_eq!(
        (summary.discovered, summary.read, summary.reused),
        (3, 3, 0)
    );
    assert_eq!((summary.new_records, summary.total_records), (2, 2));

    let gaps = case.gaps().unwrap();
    let listed: Vec<(&str, GapKind)> = gaps
        .iter()
        .map(|gap| (gap.path.as_str(), gap.kind))
        .collect();
    assert_eq!(
        listed,
        vec![
            ("memo.pdf", GapKind::Unsupported),
            ("stock.csv", GapKind::Unrecognised)
        ]
    );
    let documents = case.documents().unwrap();
    assert_eq!(documents.len(), 3);
    assert!(documents.iter().all(|document| {
        document
            .sha256
            .as_ref()
            .is_some_and(|hash| hash.len() == 64)
    }));

    let list = export(&case, Values::Full);
    assert!(list.contains("Jane Doe,,name; ssn; email,219-09-9999,"));
    assert!(list.contains(",hr/staff.csv,,2,"));
    let masked = export(&case, Values::Masked);
    assert!(masked.contains("***-**-9999") && !masked.contains("219-09-9999"));
}

#[test]
fn unchanged_files_are_reused_and_the_export_is_identical() {
    let folder = evidence();
    let home = tempfile::tempdir().unwrap();
    let path = home.path().join("case.rollcall");
    let mut case = Case::create_or_open(&path).unwrap();
    run(&mut case, folder.path());
    let first = export(&case, Values::Full);
    drop(case);

    let mut reopened = Case::open_existing(&path).unwrap();
    let summary = run(&mut reopened, folder.path());
    assert_eq!(
        (summary.read, summary.reused, summary.new_records),
        (0, 3, 0)
    );
    assert_eq!(summary.total_records, 2);
    assert_eq!(export(&reopened, Values::Full), first);
    assert_eq!(reopened.gaps().unwrap().len(), 2);
}

#[test]
fn changed_files_replace_their_records_and_removed_files_are_reported() {
    let folder = evidence();
    let home = tempfile::tempdir().unwrap();
    let mut case = Case::create_or_open(&home.path().join("case.rollcall")).unwrap();
    run(&mut case, folder.path());

    fs::write(
        folder.path().join("hr/staff.csv"),
        "Name,SSN\nAnn Poe,219-09-9997\n",
    )
    .unwrap();
    fs::remove_file(folder.path().join("stock.csv")).unwrap();
    let summary = run(&mut case, folder.path());
    assert_eq!((summary.read, summary.reused, summary.missing), (1, 1, 1));
    assert_eq!((summary.new_records, summary.total_records), (1, 1));

    let list = export(&case, Values::Full);
    assert!(list.contains("Ann Poe") && !list.contains("Jane Doe"));
    let gaps = case.gaps().unwrap();
    assert!(
        gaps.iter()
            .any(|gap| gap.path == "stock.csv" && gap.kind == GapKind::Missing)
    );

    // Once the file is back, it is no longer reported missing.
    fs::write(folder.path().join("stock.csv"), "SKU,Qty\nA-1,4\n").unwrap();
    run(&mut case, folder.path());
    assert!(
        !case
            .gaps()
            .unwrap()
            .iter()
            .any(|gap| gap.kind == GapKind::Missing)
    );
}

#[test]
fn oversized_files_are_hashed_and_reported_without_being_read() {
    let folder = evidence();
    let home = tempfile::tempdir().unwrap();
    let mut case = Case::create_or_open(&home.path().join("case.rollcall")).unwrap();
    let options = IngestOptions {
        max_file_bytes: 20,
        ..IngestOptions::default()
    };
    let summary = ingest(&mut case, folder.path(), &options).unwrap();
    assert_eq!((summary.read, summary.not_read), (2, 1));
    let gaps = case.gaps().unwrap();
    assert!(
        gaps.iter()
            .any(|gap| gap.path == "hr/staff.csv" && gap.kind == GapKind::Truncated)
    );
    let staff = case
        .documents()
        .unwrap()
        .into_iter()
        .find(|document| document.path == "hr/staff.csv");
    assert_eq!(
        staff.map(|document| (document.status, document.bytes)),
        Some(("not_read".to_owned(), STAFF.len() as u64))
    );
}

#[test]
fn the_case_must_live_outside_the_evidence() {
    let folder = evidence();
    let mut case = Case::create_or_open(&folder.path().join("case.rollcall")).unwrap();
    let error = ingest(&mut case, folder.path(), &IngestOptions::default()).unwrap_err();
    assert!(error.to_string().contains("outside the evidence folder"));
}

#[cfg(unix)]
#[test]
fn symbolic_links_are_reported_and_case_files_are_private() {
    use std::os::unix::fs::PermissionsExt;

    let folder = evidence();
    std::os::unix::fs::symlink("/etc/hosts", folder.path().join("link.csv")).unwrap();
    let home = tempfile::tempdir().unwrap();
    let path = home.path().join("case.rollcall");
    let mut case = Case::create_or_open(&path).unwrap();
    let summary = run(&mut case, folder.path());
    assert_eq!(summary.discovered, 3);
    assert!(
        case.gaps()
            .unwrap()
            .iter()
            .any(|gap| gap.path == "link.csv")
    );
    assert_eq!(
        fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
}

#[test]
fn files_that_are_not_cases_are_refused() {
    let home = tempfile::tempdir().unwrap();
    let path = home.path().join("notes.txt");
    fs::write(&path, "just text").unwrap();
    assert!(Case::open_existing(&path).is_err());
    assert!(Case::open_existing(&home.path().join("absent.rollcall")).is_err());
}
