#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::path::{Path, PathBuf};
use std::sync::{Arc, atomic::AtomicBool};

use pii_explorer_case::{CaseScanOptions, CaseStore, ReviewStatus, scan_case};
use pii_explorer_core::{ScanOptions, Scanner};
use serde_json::json;

fn fixture() -> (tempfile::TempDir, PathBuf, PathBuf) {
    let directory = tempfile::tempdir().expect("directory");
    let root = directory.path().join("evidence");
    std::fs::create_dir(&root).expect("root");
    std::fs::write(root.join("a.txt"), "a@example.com a@example.com").expect("source");
    std::fs::write(root.join("b.txt"), "b@example.org").expect("source");
    let case = directory.path().join("assessment.piicase");
    (directory, root, case)
}

fn capture(
    root: &Path,
    case: &Path,
    resume: bool,
    engine: u32,
    limit: usize,
) -> pii_explorer_case::CaseSummary {
    let scanner = Scanner::new(ScanOptions {
        detect_names: false,
        ocr: false,
        workers: 2,
        max_findings: limit,
        ..ScanOptions::default()
    })
    .expect("scanner");
    scan_case(
        scanner,
        root,
        case,
        CaseScanOptions {
            resume,
            refresh: false,
            engine: json!({"test_engine":engine}),
        },
        Arc::new(AtomicBool::new(false)),
    )
    .expect("case capture")
}

#[test]
fn unchanged_sources_reuse_durable_snapshots_after_reopening() {
    let (_directory, root, case) = fixture();
    let first = capture(&root, &case, false, 1, 500_000);
    assert_eq!(
        (
            first.discovered,
            first.completed,
            first.reused,
            first.findings
        ),
        (2, 2, 0, 3)
    );
    let second = capture(&root, &case, true, 1, 500_000);
    assert_eq!(
        (second.completed, second.reused, second.findings),
        (2, 2, 3)
    );
    assert_eq!(
        CaseStore::open(&case, true)
            .expect("reopen")
            .runs()
            .expect("history")
            .len(),
        2
    );
}

#[test]
fn byte_changes_invalidate_cache_even_with_equal_size_and_restored_timestamp() {
    let (_directory, root, case) = fixture();
    capture(&root, &case, false, 1, 500_000);
    let path = root.join("b.txt");
    let modified = std::fs::metadata(&path)
        .expect("metadata")
        .modified()
        .expect("timestamp");
    std::fs::write(&path, "c@example.net").expect("same-sized edit");
    std::fs::File::options()
        .write(true)
        .open(path)
        .expect("file")
        .set_times(std::fs::FileTimes::new().set_modified(modified))
        .expect("restore mtime");
    let changed = capture(&root, &case, true, 1, 500_000);
    assert_eq!(changed.reused, 1);
    let store = CaseStore::open(&case, true).expect("case");
    let page = store.findings(None, 0, 100, None, None).expect("page");
    assert!(
        page.findings
            .iter()
            .any(|row| row.finding.value == "c@example.net")
    );
    assert!(
        !page
            .findings
            .iter()
            .any(|row| row.finding.value == "b@example.org")
    );
}

#[test]
fn engine_configuration_changes_invalidate_every_cached_snapshot() {
    let (_directory, root, case) = fixture();
    capture(&root, &case, false, 1, 500_000);
    let changed = capture(&root, &case, true, 2, 500_000);
    assert_eq!(changed.reused, 0);
    assert_eq!(changed.findings, 3);
}

#[test]
fn removed_sources_leave_current_scope_but_preserve_historical_runs() {
    let (_directory, root, case) = fixture();
    let first = capture(&root, &case, false, 1, 500_000);
    std::fs::remove_file(root.join("b.txt")).expect("remove source");
    let second = capture(&root, &case, true, 1, 500_000);
    assert_eq!(
        (second.discovered, second.reused, second.findings),
        (1, 1, 2)
    );
    assert_eq!(
        CaseStore::open(&case, true)
            .expect("case")
            .summary(Some(first.run_id))
            .expect("history")
            .findings,
        3
    );
}

#[test]
fn decisions_persist_for_reused_bytes_and_do_not_silently_transfer_to_changed_sources() {
    let (_directory, root, case) = fixture();
    capture(&root, &case, false, 1, 500_000);
    let mut store = CaseStore::open(&case, false).expect("case");
    let row = store
        .findings(None, 0, 1, None, None)
        .expect("page")
        .findings
        .remove(0);
    store
        .review(
            row.id,
            ReviewStatus::Confirmed,
            "synthetic evidence confirmed",
            "reviewer",
        )
        .expect("review");
    drop(store);
    capture(&root, &case, true, 1, 500_000);
    let store = CaseStore::open(&case, true).expect("case");
    assert_eq!(
        store
            .findings(None, 0, 10, Some(ReviewStatus::Confirmed), None)
            .expect("confirmed")
            .findings
            .len(),
        1
    );
    let resource = row.finding.origin.resource_id;
    let text = std::fs::read_to_string(root.join(&resource)).expect("source");
    std::fs::write(root.join(resource), format!("changed context {text}")).expect("edit");
    drop(store);
    capture(&root, &case, true, 1, 500_000);
    let store = CaseStore::open(&case, true).expect("case");
    assert!(
        store
            .findings(None, 0, 10, Some(ReviewStatus::Confirmed), None)
            .expect("confirmed")
            .findings
            .is_empty()
    );
    store.integrity().expect("audit and finding integrity");
}

#[test]
fn pagination_and_jsonl_roundtrip_preserve_every_occurrence_and_source() {
    let (directory, root, case) = fixture();
    capture(&root, &case, false, 1, 500_000);
    let store = CaseStore::open(&case, true).expect("case");
    let mut after = 0;
    let mut ids = Vec::new();
    loop {
        let page = store.findings(None, after, 1, None, None).expect("page");
        ids.extend(page.findings.iter().map(|row| row.id));
        if let Some(next) = page.next_after {
            after = next;
        } else {
            break;
        }
    }
    assert_eq!(ids.len(), 3);
    ids.sort_unstable();
    ids.dedup();
    assert_eq!(ids.len(), 3);
    let export = directory.path().join("export.jsonl");
    store
        .export_jsonl(
            None,
            &mut pii_explorer_core::storage::create_private_file(&export).expect("export"),
        )
        .expect("JSONL");
    let scan = pii_explorer_core::storage::load_scan(&export).expect("load export");
    assert_eq!(
        (
            scan.findings.len(),
            scan.sources.len(),
            scan.summary.findings
        ),
        (3, 2, 3)
    );
    assert!(!scan.summary.cancelled);
    assert!(
        pii_explorer_core::verify::verify_sources(&scan, &root, &AtomicBool::new(false))
            .expect("verify")
            .all_match()
    );
}

#[test]
fn cancelled_captures_remain_explicit_and_resume_without_duplicate_occurrences() {
    let (_directory, root, case) = fixture();
    let interrupted = capture(&root, &case, false, 1, 1);
    assert_eq!(interrupted.status, "cancelled");
    let completed = capture(&root, &case, true, 1, 500_000);
    assert_eq!(
        (
            completed.status.as_str(),
            completed.completed,
            completed.findings
        ),
        ("complete", 2, 3)
    );
}

#[test]
fn capture_refuses_a_case_inside_the_evidence_tree() {
    let (_directory, root, _case) = fixture();
    let case = root.join("bad.piicase");
    let scanner = Scanner::new(ScanOptions {
        detect_names: false,
        ocr: false,
        ..ScanOptions::default()
    })
    .expect("scanner");
    assert!(
        scan_case(
            scanner,
            &root,
            &case,
            CaseScanOptions {
                resume: false,
                refresh: false,
                engine: json!({})
            },
            Arc::new(AtomicBool::new(false))
        )
        .is_err()
    );
    assert!(!case.exists());
}

#[test]
fn changed_evidence_root_cannot_repurpose_an_existing_case() {
    let (directory, root, case) = fixture();
    capture(&root, &case, false, 1, 500_000);
    let other = directory.path().join("other");
    std::fs::create_dir(&other).expect("other root");
    let scanner = Scanner::new(ScanOptions {
        detect_names: false,
        ocr: false,
        ..ScanOptions::default()
    })
    .expect("scanner");
    assert!(
        scan_case(
            scanner,
            &other,
            &case,
            CaseScanOptions {
                resume: true,
                refresh: false,
                engine: json!({})
            },
            Arc::new(AtomicBool::new(false))
        )
        .is_err()
    );
    assert_eq!(
        CaseStore::open(&case, true)
            .expect("case")
            .runs()
            .expect("runs")
            .len(),
        1
    );
}

#[test]
fn captured_payload_and_audit_tampering_are_detected() {
    let (_directory, root, case) = fixture();
    capture(&root, &case, false, 1, 500_000);
    let connection = rusqlite::Connection::open(&case).expect("test mutation");
    connection
        .execute(
            "UPDATE findings SET payload='{}' WHERE id=(SELECT min(id) FROM findings)",
            [],
        )
        .expect("tamper payload");
    assert!(
        CaseStore::open(&case, true)
            .expect("case")
            .integrity()
            .is_err()
    );
    connection
        .execute("UPDATE audit SET sha256='tampered' WHERE id=1", [])
        .expect("tamper audit");
    assert!(
        CaseStore::open(&case, true)
            .expect("case")
            .integrity()
            .is_err()
    );
}

#[test]
fn missing_review_decisions_and_excluded_content_are_visible() {
    let (_directory, root, case) = fixture();
    std::fs::create_dir(root.join("node_modules")).expect("excluded directory");
    std::fs::write(root.join("node_modules/secret.txt"), "excluded@example.org")
        .expect("excluded source");
    let summary = capture(&root, &case, false, 1, 500_000);
    assert_eq!(
        (summary.discovered, summary.findings, summary.attention),
        (2, 3, 1)
    );
    let mut store = CaseStore::open(&case, false).expect("case");
    let id = store
        .findings(None, 0, 1, None, None)
        .expect("page")
        .findings[0]
        .id;
    store
        .review(
            id,
            ReviewStatus::FalsePositive,
            "synthetic control",
            "reviewer",
        )
        .expect("review");
    store.integrity().expect("valid review");
    rusqlite::Connection::open(&case)
        .expect("mutation")
        .execute("DELETE FROM reviews", [])
        .expect("delete review");
    assert!(store.integrity().is_err());
}

#[test]
fn audit_indexes_cannot_hide_missing_decisions_from_integrity_checks() {
    let (_directory, root, case) = fixture();
    capture(&root, &case, false, 1, 500_000);
    let mut store = CaseStore::open(&case, false).expect("case");
    let id = store
        .findings(None, 0, 1, None, None)
        .expect("page")
        .findings[0]
        .id;
    store
        .review(id, ReviewStatus::Confirmed, "", "reviewer")
        .expect("review");
    store.integrity().expect("original case");
    let connection = rusqlite::Connection::open(&case).expect("mutation");
    connection
        .execute(
            "UPDATE audit SET kind='ignored',finding_id=NULL WHERE kind='review'",
            [],
        )
        .expect("hide index");
    connection
        .execute("DELETE FROM reviews", [])
        .expect("delete review");
    assert!(store.integrity().is_err());
}

#[test]
fn resources_with_incomplete_extraction_are_retried_instead_of_cached() {
    let (_directory, root, case) = fixture();
    std::fs::write(root.join("unsupported.unknown-format"), [0_u8, 255, 1, 2])
        .expect("partial evidence");
    let first = capture(&root, &case, false, 1, 500_000);
    assert!(first.attention > 0);
    let second = capture(&root, &case, true, 1, 500_000);
    assert_eq!(second.reused, 2);
    assert_eq!(second.attention, first.attention);
}
