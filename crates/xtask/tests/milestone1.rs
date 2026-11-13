//! The Milestone 1 gate: on spreadsheet-only evidence, every seeded person is on the
//! notification list with the right elements, and no file goes unaccounted for.

// Test helpers fail the test by panicking, like the tests themselves.
#![allow(clippy::unwrap_used)]

use std::collections::BTreeSet;
use std::process::Command;

use rollcall_case::{Case, IngestOptions, Values, export_csv, ingest};
use rollcall_model::GapKind;
use xtask::score::score;
use xtask::synth::{Expect, generate};

fn export(case: &Case) -> String {
    let mut output = Vec::new();
    export_csv(case, &mut output, Values::Full).unwrap();
    String::from_utf8(output).unwrap()
}

#[test]
fn every_seeded_person_is_listed_and_every_file_is_accounted_for() {
    for seed in [1, 2, 3] {
        let out = tempfile::tempdir().unwrap();
        let truth = generate(seed, 300, out.path()).unwrap();
        let mut case = Case::create_or_open(&out.path().join("case.rollcall")).unwrap();
        let evidence = out.path().join("evidence");
        let summary = ingest(&mut case, &evidence, &IngestOptions::default()).unwrap();

        let list = export(&case);
        let result = score(&truth, &list).unwrap();
        assert!(result.is_perfect(), "seed {seed}\n{}", result.report());
        assert_eq!(result.people, 360, "300 main subjects and 60 spouses");

        // Every generated file was read, and each one that should raise a gap did.
        assert_eq!(summary.discovered, truth.files.len() as u64);
        assert_eq!((summary.read, summary.not_read), (summary.discovered, 0));
        let documents: BTreeSet<String> = case
            .documents()
            .unwrap()
            .into_iter()
            .map(|document| document.path)
            .collect();
        let gaps = case.gaps().unwrap();
        let with_gap: BTreeSet<&str> = gaps.iter().map(|gap| gap.path.as_str()).collect();
        for file in &truth.files {
            assert!(
                documents.contains(&file.path),
                "{} was not recorded",
                file.path
            );
            let expects_gap = matches!(file.expect, Expect::Gap | Expect::RecordsAndGap);
            assert_eq!(
                with_gap.contains(file.path.as_str()),
                expects_gap,
                "{}",
                file.path
            );
        }
        let kinds: Vec<(&str, GapKind)> = gaps
            .iter()
            .map(|gap| (gap.path.as_str(), gap.kind))
            .collect();
        assert_eq!(
            kinds,
            vec![
                ("benefits/enrollment.xlsx", GapKind::Unrecognised),
                ("misc/corrupt.xlsx", GapKind::Unreadable),
                ("misc/handbook.docx", GapKind::Unsupported),
                ("misc/inventory.csv", GapKind::Unrecognised),
            ]
        );

        // A second ingest of the unchanged folder extracts nothing and changes nothing.
        let again = ingest(&mut case, &evidence, &IngestOptions::default()).unwrap();
        assert_eq!(
            (again.read, again.reused, again.new_records),
            (0, again.discovered, 0)
        );
        assert_eq!(export(&case), list);
    }
}

#[test]
fn the_tree_holds_no_scripts_in_other_languages() {
    let root = concat!(env!("CARGO_MANIFEST_DIR"), "/../..");
    let listing = Command::new("git")
        .args(["ls-files", "--cached", "--others", "--exclude-standard"])
        .current_dir(root)
        .output();
    let Ok(listing) = listing else {
        eprintln!("git is not available; skipping");
        return;
    };
    if !listing.status.success() {
        eprintln!("not a git checkout; skipping");
        return;
    }
    let files = String::from_utf8_lossy(&listing.stdout);
    let foreign: Vec<&str> = files
        .lines()
        .filter(|path| std::path::Path::new(root).join(path).exists())
        .filter(|path| {
            let extension = path.rsplit_once('.').map_or("", |(_, extension)| extension);
            matches!(
                extension,
                "py" | "java" | "ps1" | "sh" | "cs" | "js" | "ts" | "rb" | "pl" | "bat"
            )
        })
        .collect();
    assert!(foreign.is_empty(), "non-Rust source files: {foreign:?}");
}
