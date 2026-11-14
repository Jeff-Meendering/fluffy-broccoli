#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::collections::BTreeSet;
use std::sync::{Arc, atomic::AtomicBool};

use pii_explorer_core::evaluation::EvaluationCase;
use pii_explorer_core::{ScanOptions, Scanner};

#[test]
fn frozen_smoke_labels_match_exact_utf16_occurrences_without_model_assets() {
    let scanner = Scanner::new(ScanOptions {
        detect_names: false,
        ocr: false,
        ..ScanOptions::default()
    })
    .expect("scanner");
    let corpus = include_str!("../../../tests/fixtures/accuracy-smoke.jsonl");
    for (line, record) in corpus.lines().enumerate() {
        let case: EvaluationCase = serde_json::from_str(record).expect("frozen annotation");
        let expected: BTreeSet<_> = case
            .entities
            .iter()
            .map(|entity| {
                (
                    entity.entity_type,
                    entity.start as u64,
                    entity.length as u64,
                )
            })
            .collect();
        let result = scanner.detect_text(&case.text, Arc::new(AtomicBool::new(false)));
        let actual: BTreeSet<_> = result
            .findings
            .iter()
            .map(|finding| (finding.entity_type, finding.start, finding.length))
            .collect();
        assert_eq!(actual, expected, "smoke case {}", line + 1);
    }
}

#[cfg(feature = "ner")]
#[test]
fn installed_name_model_does_not_add_false_positives_to_frozen_smoke_labels() {
    let assets = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../assets/models");
    if !assets.join("model_quantized.onnx").is_file() {
        return;
    }
    let scanner = Scanner::new(ScanOptions {
        ocr: false,
        model_path: Some(assets.join("model_quantized.onnx")),
        vocab_path: Some(assets.join("vocab.txt")),
        ..ScanOptions::default()
    })
    .expect("scanner");
    assert!(scanner.name_model_available(), "installed model must load");
    for (line, record) in include_str!("../../../tests/fixtures/accuracy-smoke.jsonl")
        .lines()
        .enumerate()
    {
        let case: EvaluationCase = serde_json::from_str(record).expect("annotation");
        let expected: BTreeSet<_> = case
            .entities
            .iter()
            .map(|entity| {
                (
                    entity.entity_type,
                    entity.start as u64,
                    entity.length as u64,
                )
            })
            .collect();
        let result = scanner.detect_text(&case.text, Arc::new(AtomicBool::new(false)));
        let actual: BTreeSet<_> = result
            .findings
            .iter()
            .map(|finding| (finding.entity_type, finding.start, finding.length))
            .collect();
        assert_eq!(actual, expected, "model smoke case {}", line + 1);
    }
}
