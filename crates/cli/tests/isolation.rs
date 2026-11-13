#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::{Duration, Instant};

use pii_explorer_core::extract::{ExtractionContext, Extractor, extract_bytes};
use pii_explorer_core::{ScanOptions, Scanner};
use pii_explorer_isolation::WorkerPool;
use tempfile::TempDir;

fn worker() -> &'static str {
    env!("CARGO_BIN_EXE_pii-explorer-worker")
}

fn options() -> ScanOptions {
    ScanOptions {
        detect_names: false,
        ocr: false,
        ..ScanOptions::default()
    }
}

#[test]
fn worker_protocol_preserves_large_unicode_parts_and_exact_evidence() {
    let data = format!(
        "{} alice@example.com {} bob@example.com",
        "😀 Unicode café\n".repeat(6_000),
        "é".repeat(40_000)
    );
    let context =
        ExtractionContext::for_root(Arc::new(options()), Arc::new(AtomicBool::new(false)));
    let native = extract_bytes("root:1/mail.txt", data.as_bytes(), &context);
    let isolated =
        WorkerPool::new(worker())
            .unwrap()
            .extract("root:1/mail.txt", data.as_bytes(), &context);
    assert_eq!(native.parts, isolated.parts);
    assert_eq!(native.attention, isolated.attention);
    assert_eq!(native.partial, isolated.partial);
    let directory = TempDir::new().unwrap();
    let source = directory.path().join("test.txt");
    std::fs::write(&source, data).unwrap();
    let native = Scanner::new(options())
        .unwrap()
        .scan(&source, Arc::new(AtomicBool::new(false)))
        .unwrap();
    let isolated = Scanner::new(options())
        .unwrap()
        .with_extractor(Arc::new(WorkerPool::new(worker()).unwrap()))
        .scan(&source, Arc::new(AtomicBool::new(false)))
        .unwrap();
    assert_eq!(native.findings, isolated.findings);
    assert_eq!(native.attention, isolated.attention);
    assert_eq!(native.sources, isolated.sources);
}

#[test]
fn persistent_workers_retire_and_replace_without_cross_resource_evidence() {
    let pool = WorkerPool::new(worker()).unwrap();
    for index in 0..135 {
        let context =
            ExtractionContext::for_root(Arc::new(options()), Arc::new(AtomicBool::new(false)));
        let name = format!("root:{index}.txt");
        let extraction = pool.extract(&name, b"alice@example.com", &context);
        assert!(
            extraction.attention.is_empty(),
            "{:?}",
            extraction.attention
        );
        assert!(!extraction.parts.is_empty());
        assert!(
            extraction
                .parts
                .iter()
                .all(|part| part.origin.resource_id == name)
        );
    }
}

#[test]
fn mixed_document_and_nested_archive_evidence_matches_the_native_engine() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/corpus");
    let native = Scanner::new(options())
        .unwrap()
        .scan(&root, Arc::new(AtomicBool::new(false)))
        .unwrap();
    let isolated = Scanner::new(options())
        .unwrap()
        .with_extractor(Arc::new(WorkerPool::new(worker()).unwrap()))
        .scan(&root, Arc::new(AtomicBool::new(false)))
        .unwrap();
    assert_eq!(native.summary.completed, 50);
    assert_eq!(native.findings, isolated.findings);
    assert_eq!(native.attention, isolated.attention);
    assert_eq!(native.sources, isolated.sources);
}

#[cfg(unix)]
mod unix {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};

    fn quote(path: &Path) -> String {
        format!("'{}'", path.to_str().unwrap().replace('\'', "'\\''"))
    }

    fn fake(directory: &Path, code: &str) -> PathBuf {
        let path = directory.join("worker.sh");
        std::fs::write(&path, format!("#!/bin/sh\n{code}\n")).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        path
    }

    #[test]
    fn deadline_interrupts_input_when_the_peer_never_reads() {
        let directory = TempDir::new().unwrap();
        let pool = WorkerPool::new(fake(directory.path(), "/bin/sleep 10")).unwrap();
        let context = ExtractionContext::for_root(
            Arc::new(ScanOptions {
                file_timeout: Duration::from_millis(150),
                ..options()
            }),
            Arc::new(AtomicBool::new(false)),
        );
        let start = Instant::now();
        let extraction = pool.extract("root.txt", &vec![b'x'; 8 * 1024 * 1024], &context);
        assert!(start.elapsed() < Duration::from_secs(3));
        assert!(extraction.partial);
        assert!(extraction.attention[0].message.contains("deadline"));
    }

    #[test]
    fn termination_kills_ocr_descendants_then_next_resource_works() {
        let directory = TempDir::new().unwrap();
        let flag = directory.path().join("first");
        let marker = directory.path().join("escaped-marker");
        let ready = directory.path().join("ready");
        std::fs::write(&flag, "1").unwrap();
        let executable = fake(
            directory.path(),
            &format!(
                "if [ -s {flag} ]; then\n : > {flag}\n ( /bin/sleep 1.5; /usr/bin/touch {marker} ) &\n : > {ready}\n /bin/sleep 10\nelse\n exec {real}\nfi",
                flag = quote(&flag),
                marker = quote(&marker),
                ready = quote(&ready),
                real = quote(Path::new(worker()))
            ),
        );
        let pool = WorkerPool::new(executable).unwrap();
        let cancelled = Arc::new(AtomicBool::new(false));
        let context = ExtractionContext::for_root(Arc::new(options()), cancelled.clone());
        let start = Instant::now();
        let extraction = std::thread::scope(|scope| {
            scope.spawn(|| {
                while !ready.exists() && start.elapsed() < Duration::from_secs(5) {
                    std::thread::sleep(Duration::from_millis(10));
                }
                std::thread::sleep(Duration::from_millis(100));
                cancelled.store(true, Ordering::Relaxed);
            });
            pool.extract("root:1.txt", &vec![b'x'; 8 * 1024 * 1024], &context)
        });
        assert!(start.elapsed() < Duration::from_secs(7));
        assert!(extraction.partial);
        assert!(extraction.attention[0].message.contains("deadline"));
        assert!(ready.exists(), "worker never reached its startup marker");
        let context =
            ExtractionContext::for_root(Arc::new(options()), Arc::new(AtomicBool::new(false)));
        let next = pool.extract("root:2.txt", b"alice@example.com", &context);
        assert!(next.attention.is_empty(), "{:?}", next.attention);
        assert!(!next.parts.is_empty());
        std::thread::sleep(Duration::from_millis(1600));
        assert!(!marker.exists(), "descendant survived resource termination");
    }

    #[test]
    fn cancellation_interrupts_a_stuck_worker_promptly() {
        let directory = TempDir::new().unwrap();
        let executable = fake(directory.path(), "/bin/sleep 10");
        let cancelled = Arc::new(AtomicBool::new(false));
        let context = ExtractionContext::for_root(Arc::new(options()), cancelled.clone());
        let pool = WorkerPool::new(executable).unwrap();
        let start = Instant::now();
        std::thread::scope(|scope| {
            scope.spawn(|| {
                std::thread::sleep(Duration::from_millis(100));
                cancelled.store(true, Ordering::Relaxed);
            });
            let extraction = pool.extract("root.txt", b"untrusted input", &context);
            assert!(extraction.partial);
            assert_eq!(extraction.attention.len(), 1);
        });
        assert!(start.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn crashes_malformed_and_oversize_responses_are_explicit_and_bounded() {
        for code in [
            "exit 7",
            "printf 'not-json\\n'",
            "printf '%s\\n' '{\"record\":\"text\",\"text\":\"no origin\"}'",
            "printf '%s\\n' '{\"record\":\"part\",\"origin\":{\"resource_id\":\"outside\",\"stream_id\":\"body\",\"kind\":\"Body\",\"representation\":\"text\",\"chunk_start\":0,\"coordinate_unit\":\"utf16\",\"stride\":1},\"location\":null}'",
            "/usr/bin/awk 'BEGIN {for(i=0;i<1100000;i++) printf \"x\"}'",
        ] {
            let directory = TempDir::new().unwrap();
            let pool = WorkerPool::new(fake(directory.path(), code)).unwrap();
            let context =
                ExtractionContext::for_root(Arc::new(options()), Arc::new(AtomicBool::new(false)));
            let start = Instant::now();
            let extraction = pool.extract("root.txt", b"test", &context);
            assert!(start.elapsed() < Duration::from_secs(3));
            assert!(extraction.partial);
            assert_eq!(extraction.attention.len(), 1);
            assert!(extraction.parts.is_empty());
        }
    }

    #[test]
    fn worker_crash_does_not_stop_the_scanning_coordinator() {
        let directory = TempDir::new().unwrap();
        let evidence = directory.path().join("evidence");
        std::fs::create_dir(&evidence).unwrap();
        std::fs::write(evidence.join("first.txt"), "alice@example.com").unwrap();
        std::fs::write(evidence.join("second.txt"), "bob@example.com").unwrap();
        let flag = directory.path().join("first");
        std::fs::write(&flag, "1").unwrap();
        let executable = fake(
            directory.path(),
            &format!(
                "if [ -f {flag} ]; then /bin/rm {flag}; exit 7; fi\nexec {real}",
                flag = quote(&flag),
                real = quote(Path::new(worker()))
            ),
        );
        let result = Scanner::new(ScanOptions {
            workers: 1,
            ..options()
        })
        .unwrap()
        .with_extractor(Arc::new(WorkerPool::new(executable).unwrap()))
        .scan(&evidence, Arc::new(AtomicBool::new(false)))
        .unwrap();
        assert_eq!(result.summary.completed, 2);
        assert_eq!(result.findings.len(), 1);
        assert_eq!(result.attention.len(), 1);
        assert!(result.attention[0].message.contains("Isolated extraction"));
    }
}
