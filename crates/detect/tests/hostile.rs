//! Cell values and headers come from the adversary too. Whatever the text, recognising
//! it must not crash, and nothing with a control character may pass as a valid value.

// Test helpers fail the test by panicking, like the tests themselves.
#![allow(clippy::unwrap_used)]

use rollcall_detect::{
    classify_header, infer_schema, is_placeholder, looks_like, normalize, normalize_header,
};
use rollcall_model::{ElementKind, Table};

struct Random(u64);

impl Random {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut mixed = self.0;
        mixed = (mixed ^ (mixed >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        mixed = (mixed ^ (mixed >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        mixed ^ (mixed >> 31)
    }

    fn below(&mut self, limit: usize) -> usize {
        usize::try_from(self.next() % limit.max(1) as u64).unwrap()
    }
}

/// Pieces that real values are made of, mixed with characters of every width and the
/// control characters an adversary would try.
const PIECES: [&str; 44] = [
    "0",
    "1",
    "2",
    "9",
    "00",
    "219",
    "09",
    "9999",
    "1980",
    "02",
    "31",
    "-",
    "/",
    ".",
    ",",
    " ",
    "  ",
    "(",
    ")",
    "+",
    "@",
    "x",
    "ext",
    "#",
    "mailto:",
    "example.com",
    "Jane",
    "Doe",
    "O'Brien",
    "é",
    "ñ",
    "ß",
    "日本",
    "😀",
    "\u{301}",
    "\u{1b}[2J",
    "\n",
    "\r",
    "\t",
    "\u{0}",
    "\u{feff}",
    "=",
    "Feb",
    "SSN",
];

fn hostile_text(random: &mut Random) -> String {
    (0..random.below(9))
        .map(|_| PIECES[random.below(PIECES.len())])
        .collect()
}

#[test]
fn any_text_can_be_normalised_and_valid_values_are_clean() {
    let mut random = Random(11);
    for _ in 0..40_000 {
        let text = hostile_text(&mut random);
        let _ = is_placeholder(&text);
        for kind in ElementKind::ALL {
            let normalized = normalize(kind, &text);
            let _ = looks_like(kind, &text);
            if normalized.valid {
                assert!(
                    !normalized.value.chars().any(char::is_control),
                    "{kind}: {text:?} gave {:?}",
                    normalized.value
                );
                assert!(
                    !normalized.value.is_empty(),
                    "{kind}: {text:?} gave an empty value"
                );
                // A canonical form is stable: normalising it again changes nothing.
                let again = normalize(kind, &normalized.value);
                assert!(
                    again.valid,
                    "{kind}: {:?} is not valid on a second pass",
                    normalized.value
                );
                assert_eq!(again.value, normalized.value, "{kind}: from {text:?}");
            }
        }
    }
}

#[test]
fn any_text_can_be_read_as_a_header() {
    let mut random = Random(12);
    for _ in 0..40_000 {
        let text = hostile_text(&mut random);
        let header = normalize_header(&text);
        assert!(
            !header.chars().any(char::is_control),
            "{text:?} gave {header:?}"
        );
        let _ = classify_header(&text);
    }
}

#[test]
fn any_table_gets_a_schema_within_its_own_bounds() {
    let mut random = Random(13);
    for _ in 0..2_000 {
        let rows: Vec<Vec<String>> = (0..random.below(12))
            .map(|_| {
                (0..random.below(7))
                    .map(|_| hostile_text(&mut random))
                    .collect()
            })
            .collect();
        let width = rows.iter().map(Vec::len).max().unwrap_or(0);
        let table = Table {
            scope: None,
            first_row: 0,
            first_column: 0,
            rows,
        };
        let schema = infer_schema(&table);
        assert!(schema.header_row.is_none_or(|row| row < table.rows.len()));
        assert!(schema.columns.iter().all(|column| column.index < width));
    }
}

#[test]
fn any_line_of_text_can_be_scanned_and_what_is_found_is_clean() {
    let mut random = Random(14);
    for _ in 0..40_000 {
        let line = hostile_text(&mut random);
        for found in rollcall_detect::scan_line(&line) {
            assert!(!found.normalized.is_empty(), "{line:?}");
            assert!(
                !found.normalized.chars().any(char::is_control),
                "{line:?} gave {:?}",
                found.normalized
            );
            assert!(
                found.start <= line.chars().count(),
                "{line:?}: offset {}",
                found.start
            );
            assert!(
                normalize(found.kind, &found.normalized).valid || found.kind == ElementKind::Name,
                "{line:?}"
            );
        }
    }
}
