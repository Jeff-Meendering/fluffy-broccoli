//! File names and cell values chosen by an adversary must not forge output, run as
//! formulas, or make one file hide another.

// Test helpers fail the test by panicking, like the tests themselves.
#![allow(clippy::unwrap_used)]
#![cfg(unix)]

use std::ffi::OsStr;
use std::fs;
use std::os::unix::ffi::OsStrExt;

use rollcall_case::{Case, IngestOptions, Values, export_people_csv, export_records_csv, ingest};
use rollcall_extract::delimited;

fn exported(case: &Case) -> Vec<Vec<String>> {
    let mut rows = Vec::new();
    for people in [true, false] {
        let mut output = Vec::new();
        if people {
            export_people_csv(case, &mut output, Values::Full).unwrap();
        } else {
            export_records_csv(case, &mut output, Values::Full).unwrap();
        }
        let text = String::from_utf8(output).unwrap();
        rows.extend(delimited::parse(&text, ',', usize::MAX, usize::MAX).rows);
    }
    rows
}

#[test]
fn hostile_names_and_values_stay_inert_and_no_file_hides_another() {
    let evidence = tempfile::tempdir().unwrap();
    let write = |name: &[u8], content: &str| {
        fs::write(evidence.path().join(OsStr::from_bytes(name)), content)
    };
    // Names with terminal escapes, line breaks and a leading dash.
    write(b"a\x1b[2J.csv", "Name,SSN\nAnn Lee,219-09-9991\n").unwrap();
    write(b"new\nline.csv", "Name,SSN\nBen Lee,219-09-9992\n").unwrap();
    write(b"-rf.csv", "Name,SSN\nCal Lee,219-09-9993\n").unwrap();
    // Two names that are not valid text and are shown the same way. Some filesystems
    // (macOS) refuse such names; where they do, there is nothing to tell apart.
    let odd_names = write(b"\xff.csv", "Name,SSN\nDee Lee,219-09-9994\n").is_ok()
        && write(b"\xfe.csv", "Name,SSN\nEli Lee,219-09-9995\n").is_ok();
    let files = if odd_names { 6 } else { 4 };
    // Values that a spreadsheet would run, and one that would repaint a terminal.
    write(
        b"values.csv",
        "Name,Email,Address\n\"=HYPERLINK(\"\"http://x\"\",\"\"y\"\")\",fay@example.com,\"@SUM(1+1) Main St 5\"\n\
         \"Gus\x1b[2J Lee\",gus@example.com,\"-2+3 Oak Ave\"\n",
    )
    .unwrap();

    let home = tempfile::tempdir().unwrap();
    let mut case = Case::create_or_open(&home.path().join("case.rollcall")).unwrap();
    let summary = ingest(&mut case, evidence.path(), &IngestOptions::default()).unwrap();
    assert_eq!((summary.discovered, summary.read), (files, files));

    let paths: Vec<String> = case
        .documents()
        .unwrap()
        .into_iter()
        .map(|document| document.path)
        .collect();
    assert_eq!(
        paths.len() as u64,
        files,
        "each file keeps its own entry: {paths:?}"
    );
    assert!(
        paths.iter().all(|path| !path.chars().any(char::is_control)),
        "{paths:?}"
    );
    assert!(
        paths.contains(&"a\\u{1b}[2J.csv".to_owned())
            && paths.contains(&"new\\u{a}line.csv".to_owned())
    );
    assert_eq!(
        paths
            .iter()
            .any(|path| path.ends_with("(name collision 2)")),
        odd_names,
        "{paths:?}"
    );

    let rows = exported(&case);
    let cells: Vec<&String> = rows.iter().flatten().collect();
    let expected: &[&str] = if odd_names {
        &["Ann Lee", "Ben Lee", "Cal Lee", "Dee Lee", "Eli Lee"]
    } else {
        &["Ann Lee", "Ben Lee", "Cal Lee"]
    };
    for name in expected {
        assert!(
            cells.iter().any(|cell| *cell == name),
            "{name} is missing from the lists"
        );
    }
    for cell in &cells {
        assert!(
            !cell.starts_with(['=', '+', '-', '@', '\t', '\r']),
            "a spreadsheet would run {cell:?}"
        );
        assert!(
            !cell.contains('\u{1b}'),
            "{cell:?} carries an escape sequence"
        );
    }
    // The name with an escape sequence in it is kept as evidence but not as a valid name.
    assert!(cells.iter().any(|cell| *cell == "gus@example.com"));
    assert!(!cells.iter().any(|cell| cell.contains("Gus")));
}
