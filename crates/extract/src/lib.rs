//! Turns evidence files into structured tables.
//!
//! Tables stay as rows and cells with their source coordinates. Flattening a
//! spreadsheet to text would throw away the one thing that says which values belong to
//! the same person: the row.

pub mod delimited;
mod docx;
mod text;
mod xlsx;
mod xml;

use rollcall_model::{CoverageGap, GapKind, Table, Text};

/// Bounds on how much of one file is held in memory.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    pub max_rows: usize,
    pub max_cells: usize,
    /// Largest decompressed size accepted for one part of a workbook container.
    pub max_part_bytes: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_rows: 2_000_000,
            max_cells: 5_000_000,
            max_part_bytes: 256 * 1024 * 1024,
        }
    }
}

/// What one file holds: tables, running text, and whatever could not be read.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Extraction {
    pub tables: Vec<Table>,
    pub texts: Vec<Text>,
    pub gaps: Vec<CoverageGap>,
}

impl Extraction {
    fn gap(kind: GapKind, detail: impl Into<String>) -> Self {
        Self {
            gaps: vec![CoverageGap::new(None, kind, detail)],
            ..Self::default()
        }
    }
}

/// Reads one file's bytes. Never fails: whatever cannot be read is reported as a gap.
#[must_use]
pub fn extract(name: &str, bytes: &[u8], limits: &Limits) -> Extraction {
    let extension = name
        .rsplit_once('.')
        .filter(|(stem, _)| !stem.is_empty() && !stem.ends_with(['/', '\\']))
        .map(|(_, extension)| extension.to_ascii_lowercase());
    match extension.as_deref() {
        Some("csv" | "psv") => read_delimited(bytes, None, limits),
        Some("tsv" | "tab") => read_delimited(bytes, Some('\t'), limits),
        Some("xlsx" | "xlsm") => xlsx::read(bytes, limits),
        Some("docx" | "docm") => docx::read(bytes, limits),
        Some("html" | "htm") => text::read_html(bytes, limits),
        Some(
            "txt" | "text" | "log" | "md" | "json" | "yaml" | "yml" | "ini" | "conf" | "cfg"
            | "sql" | "xml",
        ) => text::read_plain(bytes, limits),
        Some(legacy @ ("xls" | "xlsb" | "ods")) => Extraction::gap(
            GapKind::Unsupported,
            format!("Spreadsheet format .{legacy} is not read yet."),
        ),
        Some(other) => Extraction::gap(
            GapKind::Unsupported,
            format!("File type .{other} is not read yet."),
        ),
        None => Extraction::gap(
            GapKind::Unsupported,
            "File has no extension; its type was not recognised.",
        ),
    }
}

fn read_delimited(bytes: &[u8], delimiter: Option<char>, limits: &Limits) -> Extraction {
    let (text, lossy) = delimited::decode(bytes);
    let delimiter = delimiter.unwrap_or_else(|| delimited::sniff_delimiter(&text));
    let parsed = delimited::parse(&text, delimiter, limits.max_rows, limits.max_cells);
    let mut gaps = Vec::new();
    if lossy {
        gaps.push(CoverageGap::new(
            None,
            GapKind::Unreadable,
            "Some bytes were not valid text in the file's encoding and were replaced; \
             affected values may be wrong.",
        ));
    }
    if parsed.truncated {
        gaps.push(CoverageGap::new(
            None,
            GapKind::Truncated,
            format!(
                "Reading stopped after {} rows at the size limit.",
                parsed.rows.len()
            ),
        ));
    }
    if parsed.unterminated_quote {
        gaps.push(CoverageGap::new(
            None,
            GapKind::Truncated,
            "The file ends inside a quoted field; the last row may be incomplete.",
        ));
    }
    let tables = if parsed.rows.is_empty() {
        Vec::new()
    } else {
        vec![Table {
            scope: None,
            first_row: 0,
            first_column: 0,
            rows: parsed.rows,
        }]
    };
    Extraction {
        tables,
        gaps,
        ..Extraction::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_delimited_files_by_extension() {
        let csv = extract(
            "people.CSV",
            b"name;email\nAda;ada@example.com\n",
            &Limits::default(),
        );
        assert!(csv.gaps.is_empty());
        assert_eq!(csv.tables[0].rows[1], vec!["Ada", "ada@example.com"]);

        let tsv = extract("a/b.tsv", b"x,y\tz\n", &Limits::default());
        assert_eq!(tsv.tables[0].rows[0], vec!["x,y", "z"]);
    }

    #[test]
    fn reports_unsupported_and_extensionless_files() {
        for name in ["notes.pdf", "old.xls", "README", ".hidden", "dir.d/file"] {
            let extraction = extract(name, b"data", &Limits::default());
            assert!(extraction.tables.is_empty(), "{name}");
            assert_eq!(extraction.gaps[0].kind, GapKind::Unsupported, "{name}");
        }
    }

    #[test]
    fn reports_replaced_bytes_and_row_limits() {
        let lossy = extract("a.csv", b"name\ncaf\xE9\n", &Limits::default());
        assert_eq!(lossy.gaps[0].kind, GapKind::Unreadable);
        assert_eq!(lossy.tables[0].rows.len(), 2);

        let limits = Limits {
            max_rows: 1,
            ..Limits::default()
        };
        let limited = extract("a.csv", b"1\n2\n", &limits);
        assert_eq!(limited.gaps[0].kind, GapKind::Truncated);
    }

    #[test]
    fn an_empty_file_yields_no_table_and_no_gap() {
        assert_eq!(
            extract("a.csv", b"", &Limits::default()),
            Extraction::default()
        );
    }
}
