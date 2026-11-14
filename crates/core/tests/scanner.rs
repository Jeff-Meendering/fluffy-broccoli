#![allow(clippy::expect_used, clippy::unwrap_used)]
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use pii_explorer_core::custom::CustomRule;
use pii_explorer_core::{EntityType, ScanEvent, ScanOptions, Scanner};
use tempfile::TempDir;

fn options() -> ScanOptions {
    ScanOptions {
        detect_names: false,
        ocr: false,
        workers: 2,
        ..ScanOptions::default()
    }
}

fn scanner(options: ScanOptions) -> Scanner {
    Scanner::new(options).expect("valid scanner")
}

#[test]
fn repeated_unicode_occurrences_keep_absolute_utf16_offsets() {
    let directory = TempDir::new().expect("temporary directory");
    let text = "😀 alice@example.com\n".repeat(3_000);
    std::fs::write(directory.path().join("records.txt"), &text).expect("write fixture");
    let result = scanner(options())
        .scan(directory.path(), Arc::new(AtomicBool::new(false)))
        .expect("scan");
    let emails = result
        .findings
        .iter()
        .filter(|finding| finding.entity_type == EntityType::Email)
        .collect::<Vec<_>>();
    assert_eq!(emails.len(), 3_000);
    let first_units = "😀 ".encode_utf16().count() as u64;
    let record_units = "😀 alice@example.com\n".encode_utf16().count() as u64;
    for (index, finding) in emails.iter().enumerate() {
        assert_eq!(finding.start, index as u64 * record_units + first_units);
        assert_eq!(finding.length, 17);
        assert_eq!(finding.value, "alice@example.com");
    }
}

#[test]
fn artificial_chunk_edges_do_not_invent_identifier_prefixes_or_suffixes() {
    let directory = TempDir::new().expect("directory");
    let record = "contactabcdef@example.org\n";
    let text = format!("😀\n{}", record.repeat(2_000));
    let scanner = scanner(options());
    let source = directory.path().join("records.txt");
    std::fs::write(&source, &text).expect("source");
    for result in [
        scanner.detect_text(&text, Arc::new(AtomicBool::new(false))),
        scanner
            .scan(&source, Arc::new(AtomicBool::new(false)))
            .expect("scan"),
    ] {
        let emails = result
            .findings
            .iter()
            .filter(|finding| finding.entity_type == EntityType::Email)
            .collect::<Vec<_>>();
        assert_eq!(emails.len(), 2_000);
        for (index, finding) in emails.into_iter().enumerate() {
            assert_eq!(finding.value, "contactabcdef@example.org");
            assert_eq!(finding.start, 3 + index as u64 * record.len() as u64);
        }
    }
    // Strings extraction has its own overlapping buffers and byte/UTF-16LE strides.
    let printable = record.replace('\n', " ").repeat(2_000);
    for (name, data) in [
        ("narrow.bin", printable.as_bytes().to_vec()),
        (
            "wide.bin",
            printable
                .encode_utf16()
                .flat_map(u16::to_le_bytes)
                .collect(),
        ),
    ] {
        let mut bytes = vec![0xff, 0];
        bytes.extend(data);
        let source = directory.path().join(name);
        std::fs::write(&source, bytes).expect("binary source");
        let result = scanner
            .scan(&source, Arc::new(AtomicBool::new(false)))
            .expect("binary scan");
        let emails = result
            .findings
            .iter()
            .filter(|finding| finding.entity_type == EntityType::Email)
            .collect::<Vec<_>>();
        assert_eq!(emails.len(), 2_000, "{name}");
        assert!(
            emails
                .iter()
                .all(|finding| finding.value == "contactabcdef@example.org")
        );
    }
}

#[test]
fn worker_counts_produce_identical_evidence() {
    let directory = TempDir::new().expect("temporary directory");
    for index in 0..30 {
        std::fs::write(
            directory.path().join(format!("record-{index}.txt")),
            format!("😀 Contact person{index}@example.com or 4111 1111 1111 1111\n"),
        )
        .expect("write fixture");
    }
    let mut one = options();
    one.workers = 1;
    let mut two = options();
    two.workers = 2;
    let first = scanner(one)
        .scan(directory.path(), Arc::new(AtomicBool::new(false)))
        .expect("single-worker scan");
    let second = scanner(two)
        .scan(directory.path(), Arc::new(AtomicBool::new(false)))
        .expect("parallel scan");
    assert_eq!(first.findings, second.findings);
    assert_eq!(first.attention, second.attention);
    assert_eq!(first.sources, second.sources);
}

#[test]
fn finding_cap_is_exact_and_streamed_once() {
    let directory = TempDir::new().expect("temporary directory");
    for index in 0..20 {
        std::fs::write(
            directory.path().join(format!("{index}.txt")),
            "alice@example.com bob@example.net",
        )
        .expect("write fixture");
    }
    let mut options = options();
    options.max_findings = 7;
    let emitted = Arc::new(AtomicUsize::new(0));
    let callback_emitted = emitted.clone();
    let result = scanner(options)
        .scan_with_events(
            directory.path(),
            Arc::new(AtomicBool::new(false)),
            move |event| {
                if let ScanEvent::Findings(findings) = event {
                    callback_emitted.fetch_add(findings.len(), Ordering::Relaxed);
                }
            },
        )
        .expect("scan");
    assert_eq!(result.findings.len(), 7);
    assert_eq!(emitted.load(Ordering::Relaxed), 7);
    assert!(result.summary.cancelled);
    assert_eq!(
        result.summary.limit_reached.as_deref(),
        Some("finding limit")
    );
}

#[test]
fn attention_cap_stops_scan_transparently() {
    let directory = TempDir::new().expect("temporary directory");
    for index in 0..10 {
        std::fs::write(
            directory.path().join(format!("{index}.txt")),
            "more than one byte",
        )
        .expect("write fixture");
    }
    let mut options = options();
    options.max_file_bytes = 1;
    options.max_attention = 2;
    let result = scanner(options)
        .scan(directory.path(), Arc::new(AtomicBool::new(false)))
        .expect("scan");
    assert_eq!(result.attention.len(), 2);
    assert!(result.summary.cancelled);
    assert_eq!(
        result.summary.limit_reached.as_deref(),
        Some("attention limit")
    );
}

#[test]
fn stdin_detection_uses_utf16_and_hashes_actual_input() {
    let result = scanner(options()).detect_text(
        "😀 alice@example.com alice@example.com",
        Arc::new(AtomicBool::new(false)),
    );
    assert_eq!(result.findings.len(), 2);
    assert_eq!(result.findings[0].start, 3);
    assert_eq!(result.findings[1].start, 21);
    let expected_hash =
        pii_explorer_core::hash::sha256_hex("😀 alice@example.com alice@example.com".as_bytes());
    assert_eq!(
        result.sources[0].sha256.as_deref(),
        Some(expected_hash.as_str())
    );
}

#[test]
fn oversized_file_still_checks_its_name() {
    let directory = TempDir::new().expect("temporary directory");
    std::fs::write(
        directory.path().join("alice@example.com.bin"),
        b"content exceeds one byte",
    )
    .expect("write fixture");
    let mut options = options();
    options.max_file_bytes = 1;
    let result = scanner(options)
        .scan(directory.path(), Arc::new(AtomicBool::new(false)))
        .expect("scan");
    assert!(result.findings.iter().any(|finding| {
        finding.entity_type == EntityType::Email && finding.origin.resource_id.ends_with(".bin")
    }));
    assert!(
        result
            .attention
            .iter()
            .any(|item| item.message.contains("only its name"))
    );
    assert_eq!(result.sources[0].sha256, None);
}

#[test]
fn dependency_directories_and_symlinks_are_not_followed() {
    let directory = TempDir::new().expect("temporary directory");
    std::fs::create_dir(directory.path().join("node_modules")).expect("create excluded directory");
    std::fs::write(
        directory.path().join("node_modules/hidden.txt"),
        "hidden@example.com",
    )
    .expect("write excluded fixture");
    std::fs::write(directory.path().join("visible.txt"), "visible@example.com")
        .expect("write visible fixture");
    #[cfg(unix)]
    std::os::unix::fs::symlink(
        directory.path().join("node_modules/hidden.txt"),
        directory.path().join("linked.txt"),
    )
    .expect("create symlink");
    let result = scanner(options())
        .scan(directory.path(), Arc::new(AtomicBool::new(false)))
        .expect("scan");
    assert!(
        result
            .findings
            .iter()
            .any(|finding| finding.value == "visible@example.com")
    );
    assert!(
        !result
            .findings
            .iter()
            .any(|finding| finding.value == "hidden@example.com")
    );
    assert!(
        result
            .attention
            .iter()
            .any(|item| item.resource_id == "node_modules")
    );
    #[cfg(unix)]
    assert!(
        result
            .attention
            .iter()
            .any(|item| item.resource_id == "linked.txt")
    );
}

#[test]
fn custom_rules_flow_through_the_scanner() {
    let directory = TempDir::new().expect("temporary directory");
    std::fs::write(directory.path().join("case.txt"), "Reference ENG-123456")
        .expect("write fixture");
    let mut options = options();
    options.custom_rules.push(CustomRule {
        name: "engagement".into(),
        pattern: "ENG-[0-9]{6}".into(),
        entity_type: EntityType::LabelledIdentifier,
        confidence: 0.8,
        case_insensitive: false,
        whole_word: true,
        capture_group: 0,
    });
    let result = scanner(options)
        .scan(directory.path(), Arc::new(AtomicBool::new(false)))
        .expect("scan");
    assert!(
        result.findings.iter().any(|finding| {
            finding.value == "ENG-123456" && finding.method == "custom:engagement"
        })
    );
    assert_eq!(result.settings.custom_rules.len(), 1);
}

#[test]
fn streamed_records_have_exact_totals_without_retained_copies() {
    let directory = TempDir::new().expect("directory");
    for i in 0..30 {
        std::fs::write(
            directory.path().join(format!("{i}.txt")),
            "a@example.com a@example.com",
        )
        .expect("fixture");
    }
    let findings = AtomicUsize::new(0);
    let sources = AtomicUsize::new(0);
    let result = scanner(options())
        .with_result_retention(false)
        .scan_with_events(
            directory.path(),
            Arc::new(AtomicBool::new(false)),
            |event| match event {
                ScanEvent::Findings(batch) => {
                    findings.fetch_add(batch.len(), Ordering::Relaxed);
                }
                ScanEvent::Sources(batch) => {
                    sources.fetch_add(batch.len(), Ordering::Relaxed);
                }
                _ => {}
            },
        )
        .expect("streaming scan");
    assert_eq!(result.summary.findings, 60);
    assert_eq!(findings.load(Ordering::Relaxed), 60);
    assert_eq!(sources.load(Ordering::Relaxed), 30);
    assert!(result.findings.is_empty() && result.attention.is_empty() && result.sources.is_empty());
}

#[test]
fn single_resource_scanning_preserves_parent_filename_and_root_identity() {
    let directory = TempDir::new().expect("directory");
    let path = directory.path().join("notes.txt");
    std::fs::write(&path, "b@example.org").expect("fixture");
    let result = scanner(options())
        .scan_resource_with_events(
            &path,
            "a@example.com/notes.txt",
            Arc::new(AtomicBool::new(false)),
            |_| {},
        )
        .expect("resource scan");
    assert!(
        result
            .findings
            .iter()
            .any(|finding| finding.value == "a@example.com")
    );
    assert!(
        result
            .findings
            .iter()
            .any(|finding| finding.value == "b@example.org")
    );
    assert!(
        result
            .findings
            .iter()
            .all(|finding| finding.origin.resource_id == "a@example.com/notes.txt")
    );
    assert_eq!(result.sources[0].resource_id, "a@example.com/notes.txt");
}
