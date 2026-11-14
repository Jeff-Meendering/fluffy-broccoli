//! Reading plain text and HTML.

use rollcall_model::{CoverageGap, GapKind, Table, Text};

use crate::xml::unescape;
use crate::{Extraction, Limits, delimited};

/// Reads a file with a text extension. A file that is really a delimited table
/// (`export.txt` with tab-separated columns) is read as a table.
pub(crate) fn read_plain(bytes: &[u8], limits: &Limits) -> Extraction {
    let (text, lossy) = delimited::decode(bytes);
    if looks_binary(&text) {
        return Extraction::gap(
            GapKind::Unreadable,
            "File has a text extension but holds binary data; it was not read.",
        );
    }
    let mut extraction = Extraction::default();
    if lossy {
        extraction.gaps.push(CoverageGap::new(
            None,
            GapKind::Unreadable,
            "Some bytes were not valid text in the file's encoding and were replaced; \
             affected values may be wrong.",
        ));
    }
    if let Some(delimiter) = table_delimiter(&text) {
        let parsed = delimited::parse(&text, delimiter, limits.max_rows, limits.max_cells);
        if parsed.truncated {
            extraction.gaps.push(truncated(parsed.rows.len(), "rows"));
        }
        extraction.tables.push(Table {
            scope: None,
            first_row: 0,
            first_column: 0,
            rows: parsed.rows,
        });
        return extraction;
    }
    push_lines(
        &mut extraction,
        None,
        text.lines().map(str::to_owned),
        limits,
    );
    extraction
}

/// Reads an HTML page as the text a reader would see.
pub(crate) fn read_html(bytes: &[u8], limits: &Limits) -> Extraction {
    let (source, lossy) = delimited::decode(bytes);
    let mut extraction = Extraction::default();
    if lossy {
        extraction.gaps.push(CoverageGap::new(
            None,
            GapKind::Unreadable,
            "Some bytes were not valid text in the file's encoding and were replaced; \
             affected values may be wrong.",
        ));
    }
    let visible = strip_markup(&source);
    push_lines(
        &mut extraction,
        None,
        visible.lines().map(|line| line.trim().to_owned()),
        limits,
    );
    extraction
}

fn truncated(count: usize, unit: &str) -> CoverageGap {
    CoverageGap::new(
        None,
        GapKind::Truncated,
        format!("Reading stopped after {count} {unit} at the size limit."),
    )
}

/// Adds running text to an extraction, bounded by the row limit.
pub(crate) fn push_lines(
    extraction: &mut Extraction,
    scope: Option<String>,
    lines: impl Iterator<Item = String>,
    limits: &Limits,
) {
    let mut kept: Vec<String> = Vec::new();
    let mut cut = false;
    for line in lines {
        if kept.len() >= limits.max_rows {
            cut = true;
            break;
        }
        kept.push(line);
    }
    if cut {
        let mut gap = truncated(kept.len(), "lines");
        gap.scope.clone_from(&scope);
        extraction.gaps.push(gap);
    }
    if kept.iter().any(|line| !line.trim().is_empty()) {
        extraction.texts.push(Text {
            scope,
            first_line: 0,
            lines: kept,
        });
    }
}

/// True when text is mostly not text: more than one character in fifty is a control
/// character other than a tab or line break.
fn looks_binary(text: &str) -> bool {
    let sample = text.chars().take(8_192);
    let (mut total, mut odd) = (0_usize, 0_usize);
    for character in sample {
        total += 1;
        odd += usize::from(
            character.is_control() && !matches!(character, '\t' | '\n' | '\r' | '\u{c}'),
        );
    }
    odd * 50 > total
}

/// The delimiter of a table stored under a text extension, if the file is one: its
/// leading lines must all split into the same number of columns.
fn table_delimiter(text: &str) -> Option<char> {
    let lines: Vec<&str> = text
        .lines()
        .filter(|line| !line.trim().is_empty())
        .take(20)
        .collect();
    if lines.len() < 3 {
        return None;
    }
    // Commas are common in prose, so a comma-separated table needs more columns.
    [('\t', 1), ('|', 1), (';', 1), (',', 2)]
        .into_iter()
        .find_map(|(delimiter, fewest)| {
            let count = |line: &str| line.matches(delimiter).count();
            let first = count(lines[0]);
            (first >= fewest && lines.iter().all(|line| count(line) == first)).then_some(delimiter)
        })
}

/// Tags after which a browser starts a new line.
const BLOCK_TAGS: [&str; 20] = [
    "p", "div", "br", "tr", "li", "ul", "ol", "table", "h1", "h2", "h3", "h4", "h5", "h6",
    "section", "article", "header", "footer", "pre", "hr",
];

/// Removes markup from HTML, leaving the text with line breaks where blocks end.
fn strip_markup(source: &str) -> String {
    let mut text = String::with_capacity(source.len() / 2);
    let mut rest = source;
    while let Some(open) = rest.find('<') {
        text.push_str(&unescape(&rest[..open]).replace('\u{a0}', " "));
        rest = &rest[open..];
        if rest.starts_with("<!--") {
            rest = rest.find("-->").map_or("", |end| &rest[end + 3..]);
            continue;
        }
        let Some(close) = rest.find('>') else {
            // An unclosed tag: what follows is not text a reader would see.
            rest = "";
            break;
        };
        let closing = rest[1..close].starts_with('/');
        let tag = rest[1..close].trim_start_matches('/').trim();
        let name = tag
            .split(|character: char| !character.is_ascii_alphanumeric())
            .next()
            .unwrap_or_default()
            .to_ascii_lowercase();
        rest = &rest[close + 1..];
        if !closing && (name == "script" || name == "style") {
            // Skip to the matching end tag; its content is code, not text.
            let lower = rest.to_ascii_lowercase();
            rest = lower
                .find(&format!("</{name}"))
                .map_or("", |end| &rest[end..]);
        } else if BLOCK_TAGS.contains(&name.as_str()) {
            text.push('\n');
        } else if closing && (name == "td" || name == "th") {
            text.push('\t');
        }
    }
    text.push_str(&unescape(rest).replace('\u{a0}', " "));
    text.replace("&nbsp;", " ")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lines(extraction: &Extraction) -> Vec<&str> {
        extraction
            .texts
            .iter()
            .flat_map(|text| &text.lines)
            .map(String::as_str)
            .collect()
    }

    #[test]
    fn plain_text_keeps_its_lines_and_blank_separators() {
        let extraction = read_plain(
            b"Name: Jane Doe\r\nSSN: 219-09-9999\n\nnext block\n",
            &Limits::default(),
        );
        assert!(extraction.gaps.is_empty() && extraction.tables.is_empty());
        assert_eq!(
            lines(&extraction),
            ["Name: Jane Doe", "SSN: 219-09-9999", "", "next block"]
        );
    }

    #[test]
    fn a_table_under_a_text_extension_is_read_as_a_table() {
        let tabbed = read_plain(
            b"name\tssn\nJane Doe\t219-09-9999\nJohn Roe\t219-09-9998\n",
            &Limits::default(),
        );
        assert!(tabbed.texts.is_empty());
        assert_eq!(tabbed.tables[0].rows[1], ["Jane Doe", "219-09-9999"]);

        let prose = read_plain(
            b"Dear all,\nPlease see below, thanks.\nRegards, Jane\n",
            &Limits::default(),
        );
        assert!(
            prose.tables.is_empty(),
            "sentences with a comma each are not a table"
        );
    }

    #[test]
    fn binary_data_and_overlong_files_are_reported() {
        let binary = read_plain(&[0, 1, 2, 3, 4, 5, 6, 7, 8, 14, 15, 16], &Limits::default());
        assert_eq!(binary.gaps[0].kind, GapKind::Unreadable);
        assert!(binary.texts.is_empty());

        let limits = Limits {
            max_rows: 2,
            ..Limits::default()
        };
        let long = read_plain(b"one\ntwo\nthree\nfour\n", &limits);
        assert_eq!(long.texts[0].lines.len(), 2);
        assert_eq!(long.gaps[0].kind, GapKind::Truncated);
        assert!(read_plain(b"\n \n", &Limits::default()).texts.is_empty());
    }

    #[test]
    fn html_is_reduced_to_what_a_reader_sees() {
        let page = b"<html><head><style>p { color: red }</style><script>var a = '<p>x</p>';</script></head>\
            <body><h1>Staff</h1><p>Jane&nbsp;Doe &amp; co<br>jane@example.com</p><!-- hidden@example.com -->\
            <table><tr><td>SSN</td><td>219-09-9999</td></tr></table></body></html>";
        let extraction = read_html(page, &Limits::default());
        let shown: Vec<&str> = lines(&extraction)
            .into_iter()
            .filter(|line| !line.is_empty())
            .collect();
        assert_eq!(
            shown,
            [
                "Staff",
                "Jane Doe & co",
                "jane@example.com",
                "SSN\t219-09-9999"
            ]
        );
    }

    #[test]
    fn broken_markup_does_not_leak_or_loop() {
        for page in [
            "<p>ok</p><script>never closed",
            "text <unclosed",
            "<<<>>>",
            "<!-- open",
            "",
        ] {
            let _ = read_html(page.as_bytes(), &Limits::default());
        }
        assert_eq!(
            lines(&read_html(b"shown <b", &Limits::default())),
            ["shown"]
        );
    }
}
