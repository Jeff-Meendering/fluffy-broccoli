use encoding_rs::{UTF_8, UTF_16BE, UTF_16LE, WINDOWS_1252};

use super::Emitter;

pub(super) enum Decoded {
    Text(String),
    Binary(&'static str),
    Invalid(String),
}

/// Decode known textual resources without silently replacing malformed input. BOMs select their
/// encoding; otherwise strict UTF-8 is preferred and legacy Windows text falls back to cp1252.
pub(super) fn decode(data: &[u8]) -> Decoded {
    let (encoding, bytes, description) = if data.starts_with(&[0xef, 0xbb, 0xbf]) {
        (UTF_8, &data[3..], "UTF-8 BOM")
    } else if data.starts_with(&[0xff, 0xfe]) {
        (UTF_16LE, &data[2..], "UTF-16LE BOM")
    } else if data.starts_with(&[0xfe, 0xff]) {
        (UTF_16BE, &data[2..], "UTF-16BE BOM")
    } else {
        match std::str::from_utf8(data) {
            Ok(text) => {
                return if has_binary_controls(text) {
                    Decoded::Binary("NUL or binary control characters")
                } else {
                    Decoded::Text(text.to_owned())
                };
            }
            Err(_) => (WINDOWS_1252, data, "Windows-1252 fallback"),
        }
    };

    let Some(decoded) = encoding.decode_without_bom_handling_and_without_replacement(bytes) else {
        return Decoded::Invalid(format!("Invalid or truncated {description} text"));
    };
    if has_binary_controls(&decoded) {
        return Decoded::Binary("NUL or binary control characters after decoding");
    }
    Decoded::Text(decoded.into_owned())
}

fn has_binary_controls(text: &str) -> bool {
    text.chars().any(|character| {
        character == '\0'
            || (character.is_control()
                && !matches!(character, '\t' | '\n' | '\r' | '\u{0c}' | '\u{0b}'))
    })
}

pub(super) fn looks_like_text(data: &[u8]) -> bool {
    if data.starts_with(&[0xef, 0xbb, 0xbf])
        || data.starts_with(&[0xff, 0xfe])
        || data.starts_with(&[0xfe, 0xff])
    {
        return true;
    }
    let Ok(text) = std::str::from_utf8(data) else {
        return false;
    };
    if text.is_empty() {
        return true;
    }
    let mut suspicious = 0usize;
    let mut count = 0usize;
    for character in text.chars().take(16_384) {
        count += 1;
        if character == '\0'
            || (character.is_control()
                && !matches!(character, '\t' | '\n' | '\r' | '\u{0c}' | '\u{0b}'))
        {
            suspicious += 1;
        }
    }
    suspicious == 0 && count > 0
}

pub(super) fn plain(out: &mut Emitter<'_>, data: &[u8]) {
    match decode(data) {
        Decoded::Text(text) => {
            out.body(&text, "text", "decoded-text", "decoded-text");
        }
        Decoded::Binary(reason) => out.issue(format!(
            "Text decoding stopped because the resource contains {reason}; readable binary strings were not substituted for decoded text."
        )),
        Decoded::Invalid(error) => out.issue(format!(
            "Text decoding failed: {error}; malformed bytes were not replaced."
        )),
    }
}

pub(super) fn delimited(out: &mut Emitter<'_>, data: &[u8], tsv: bool) {
    let kind = if tsv { "TSV" } else { "CSV" };
    let text = match decode(data) {
        Decoded::Text(text) => text,
        Decoded::Binary(reason) => {
            out.issue(format!(
                "{kind} was not parsed because it contains {reason}."
            ));
            return;
        }
        Decoded::Invalid(error) => {
            out.issue(format!("{kind} decoding failed: {error}."));
            return;
        }
    };
    if text.is_empty() {
        return;
    }

    let mut reader = csv::ReaderBuilder::new()
        .has_headers(false)
        .flexible(true)
        .delimiter(if tsv { b'\t' } else { b',' })
        .from_reader(text.as_bytes());
    let mut synthesized = String::new();
    let mut headers = Vec::new();
    let mut named = false;
    let mut row = 0usize;
    let mut failure = None;
    for record in reader.records() {
        if !out.running() {
            break;
        }
        match record {
            Ok(record) => {
                let cells: Vec<String> = record.iter().map(str::to_owned).collect();
                if row == 0 {
                    headers = cells
                        .iter()
                        .map(|cell| column_label(cell).to_owned())
                        .collect();
                    named = headers.iter().any(|header| header == "Full name: ");
                    synthesized.push_str(&cells.join(" | "));
                    synthesized.push('\n');
                } else {
                    push_row(&mut synthesized, &cells, &headers, named, false);
                }
                row += 1;
            }
            Err(error) => {
                failure = Some(format!(
                    "Malformed {kind} record near line {}; remaining records were not checked: {error}",
                    error.position().map_or(0, csv::Position::line)
                ));
                break;
            }
        }
    }
    out.body(
        &synthesized,
        format!("{kind} rows 1-{row}"),
        "table",
        "synthesized-text",
    );
    if let Some(error) = failure {
        out.issue(error);
    }
}

/// The single source of table header semantics for delimited files, HTML and spreadsheets.
/// Generic identifiers are deliberately not promoted to sensitive column types.
pub(super) fn column_label(header: &str) -> &'static str {
    let normalized = header.trim().to_lowercase().replace(['_', '-'], " ");
    match normalized.as_str() {
        "name" | "full name" | "fullname" => "Full name: ",
        "dob" | "date of birth" | "birthdate" | "birth date" | "dateofbirth" => "DOB: ",
        "ssn" | "social security" | "social security number" | "socialsecuritynumber" => "SSN: ",
        "passport" | "passport number" | "passport no" => "Passport number: ",
        "driver license"
        | "driver's license"
        | "drivers license"
        | "driving licence"
        | "driver license number"
        | "drivers license number"
        | "driving licence number" => "Driver's license: ",
        "account number" | "account no" | "bank account" | "bank account number" => {
            "Account number: "
        }
        "tax id" | "tax identification number" | "tin" => "Tax ID: ",
        _ => "",
    }
}

pub(super) fn push_row(
    output: &mut String,
    cells: &[String],
    headers: &[String],
    named: bool,
    header_row: bool,
) {
    if named && !header_row {
        output.push_str("[Table] ");
    }
    for (index, cell) in cells.iter().enumerate() {
        if !header_row && let Some(label) = headers.get(index) {
            output.push_str(label);
        }
        output.push_str(&cell.replace(['\n', '\r'], " "));
        output.push_str(" | ");
    }
    output.push('\n');
}

/// A stateful table renderer used by HTML and workbooks, where a later explicit header row can
/// establish semantics even when introductory rows precede it.
pub(super) struct TableState {
    pub headers: Vec<String>,
    pub named: bool,
}

impl TableState {
    pub fn new() -> Self {
        Self {
            headers: Vec::new(),
            named: false,
        }
    }

    pub fn reset(&mut self) {
        self.headers.clear();
        self.named = false;
    }

    pub fn push(&mut self, output: &mut String, cells: &[String]) {
        let labels: Vec<String> = cells
            .iter()
            .map(|cell| column_label(cell).to_owned())
            .collect();
        let header_row = labels.iter().any(|label| !label.is_empty());
        if header_row {
            self.headers = labels;
            self.named = self.headers.iter().any(|label| label == "Full name: ");
        }
        push_row(output, cells, &self.headers, self.named, header_row);
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, atomic::AtomicBool};

    use crate::ScanOptions;

    use crate::extract::ExtractionContext;

    fn extract(name: &str, bytes: &[u8]) -> crate::Extraction {
        let context = ExtractionContext::for_root(
            Arc::new(ScanOptions::default()),
            Arc::new(AtomicBool::new(false)),
        );
        crate::extract::extract_bytes(name, bytes, &context)
    }

    #[test]
    fn strict_boms_and_legacy_encoding() {
        let utf16: Vec<u8> = "🙂 utf16@example.com"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        let result = extract("notes.txt", &[&[0xff, 0xfe], utf16.as_slice()].concat());
        assert!(result.parts[0].text.contains("🙂 utf16@example.com"));
        assert!(result.attention.is_empty());

        let result = extract("legacy.txt", b"Ren\xe9e \x93memo\x94 legacy@example.com");
        assert!(result.parts[0].text.contains("Renée “memo”"));
        assert!(result.attention.is_empty());
    }

    #[test]
    fn malformed_unicode_is_not_lossy() {
        let result = extract("broken.txt", &[0xff, 0xfe, 0x00]);
        assert!(result.parts.is_empty());
        assert!(result.attention[0].message.contains("Invalid or truncated"));
    }

    #[test]
    fn quoted_table_rows_keep_central_header_semantics() {
        let result = extract(
            "people.tsv",
            b"full_name\tdob\tnotes\nPriya Raghunathan\t1991-07-24\t\"Called\tMonday\"\n",
        );
        assert!(result.attention.is_empty(), "{:?}", result.attention);
        let text = result
            .parts
            .iter()
            .map(|part| part.text.as_str())
            .collect::<String>();
        assert!(
            text.contains(
                "[Table] Full name: Priya Raghunathan | DOB: 1991-07-24 | Called\tMonday |"
            )
        );
        assert!(
            result
                .parts
                .iter()
                .all(|part| part.origin.stream_id == "table")
        );
        assert!(
            result
                .parts
                .iter()
                .all(|part| part.origin.representation == "synthesized-text")
        );
    }

    #[test]
    fn repeated_rows_have_continuous_offsets_across_chunks() {
        let csv = format!(
            "dob,email\n{}",
            "1991-07-24,repeat@example.net\n".repeat(800)
        );
        let result = extract("rows.csv", csv.as_bytes());
        let mut actual = std::collections::BTreeSet::new();
        for part in &result.parts {
            for (byte, _) in part.text.match_indices("repeat@example.net") {
                let local = part.text[..byte].encode_utf16().count() as u64;
                actual.insert(part.origin.chunk_start + local);
            }
        }
        let expected = format!(
            "dob | email\n{}",
            "DOB: 1991-07-24 | repeat@example.net | \n".repeat(800)
        );
        let expected: std::collections::BTreeSet<u64> = expected
            .match_indices("repeat@example.net")
            .map(|(byte, _)| expected[..byte].encode_utf16().count() as u64)
            .collect();
        assert_eq!(actual, expected);
    }

    #[test]
    fn real_text_fixtures_decode() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/corpus/01_plain");
        for name in ["utf16-notes.txt", "cp1252-memo.txt", "contacts.txt"] {
            let data = std::fs::read(root.join(name)).expect("fixture");
            let result = extract(name, &data);
            assert!(!result.parts.is_empty(), "{name}: {:?}", result.attention);
            assert!(
                result.attention.is_empty(),
                "{name}: {:?}",
                result.attention
            );
        }
    }
}
