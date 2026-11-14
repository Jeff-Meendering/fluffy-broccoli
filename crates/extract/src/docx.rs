//! Reading Word documents (`.docx`, `.docm`).
//!
//! The body's paragraphs become running text and its tables become tables, so a staff
//! list pasted into a letter is read as the table it is. Headers, footers, footnotes,
//! endnotes and comments are read as text of their own.

use std::io::{Cursor, Read};

use rollcall_model::{CoverageGap, GapKind, Table, visible};
use zip::ZipArchive;

use crate::text::push_lines;
use crate::xml::{Event, Reader, local_name};
use crate::{Extraction, Limits};

pub(crate) fn read(bytes: &[u8], limits: &Limits) -> Extraction {
    if bytes.starts_with(&[0xD0, 0xCF, 0x11, 0xE0]) {
        return Extraction::gap(
            GapKind::Unreadable,
            "Document is password-protected or stored in a legacy container; its contents were not read.",
        );
    }
    let Ok(mut archive) = ZipArchive::new(Cursor::new(bytes)) else {
        return Extraction::gap(
            GapKind::Unreadable,
            "File is not a readable document container.",
        );
    };
    let mut parts: Vec<String> = archive
        .file_names()
        .filter_map(Result::ok)
        .map(std::borrow::Cow::into_owned)
        .filter(|name| is_text_part(name))
        .collect();
    // The body first, then the other parts in a stable order.
    parts.sort_by_key(|name| (name != "word/document.xml", name.clone()));
    if parts.first().map(String::as_str) != Some("word/document.xml") {
        return Extraction::gap(
            GapKind::Unreadable,
            "Container has no document body; it may not be a Word document.",
        );
    }

    let mut extraction = Extraction::default();
    for part in parts {
        let scope = (part != "word/document.xml").then(|| {
            let name = part.trim_start_matches("word/").trim_end_matches(".xml");
            visible(name)
        });
        let parsed =
            read_part(&mut archive, &part, limits).and_then(|text| parse_part(&text, limits));
        match parsed {
            Ok(content) => {
                for (index, rows) in content.tables.into_iter().enumerate() {
                    let table = match &scope {
                        Some(scope) => format!("{scope} table {}", index + 1),
                        None => format!("table {}", index + 1),
                    };
                    extraction.tables.push(Table {
                        scope: Some(table),
                        first_row: 0,
                        first_column: 0,
                        rows,
                    });
                }
                if content.truncated {
                    extraction.gaps.push(CoverageGap::new(
                        scope.clone(),
                        GapKind::Truncated,
                        "Reading stopped at the size limit.",
                    ));
                }
                push_lines(
                    &mut extraction,
                    scope,
                    content.paragraphs.into_iter(),
                    limits,
                );
            }
            Err(detail) => {
                extraction
                    .gaps
                    .push(CoverageGap::new(scope, GapKind::Unreadable, detail))
            }
        }
    }
    extraction
}

fn is_text_part(name: &str) -> bool {
    let Some(part) = name
        .strip_prefix("word/")
        .and_then(|part| part.strip_suffix(".xml"))
    else {
        return false;
    };
    let numbered = |prefix: &str| {
        part.strip_prefix(prefix)
            .is_some_and(|number| number.bytes().all(|byte| byte.is_ascii_digit()))
    };
    matches!(part, "document" | "footnotes" | "endnotes" | "comments")
        || numbered("header")
        || numbered("footer")
}

fn read_part(
    archive: &mut ZipArchive<Cursor<&[u8]>>,
    path: &str,
    limits: &Limits,
) -> Result<String, String> {
    let entry = archive
        .by_name(path)
        .map_err(|_| "Document part could not be opened.".to_owned())?;
    let mut data = Vec::new();
    entry
        .take(limits.max_part_bytes.saturating_add(1))
        .read_to_end(&mut data)
        .map_err(|_| "Document part could not be decompressed.".to_owned())?;
    if u64::try_from(data.len()).unwrap_or(u64::MAX) > limits.max_part_bytes {
        return Err("Document part is larger than the size limit.".to_owned());
    }
    String::from_utf8(data).map_err(|_| "Document part is not UTF-8 text.".to_owned())
}

#[derive(Default)]
struct Content {
    paragraphs: Vec<String>,
    tables: Vec<Vec<Vec<String>>>,
    truncated: bool,
}

fn parse_part(text: &str, limits: &Limits) -> Result<Content, String> {
    let mut content = Content::default();
    // Tables can nest; only the outermost is laid out, with inner ones folded into
    // the cell that holds them.
    let mut depth = 0_usize;
    let (mut table, mut row, mut cell): (Vec<Vec<String>>, Vec<String>, String) =
        Default::default();
    let mut paragraph = String::new();
    let mut capturing = false;
    let mut cells = 0_usize;

    for event in Reader::new(text) {
        let event = event.map_err(|error| error.to_string())?;
        match event {
            Event::Start { name, empty, .. } => match local_name(name) {
                "tbl" if !empty => depth += 1,
                "t" => capturing = !empty,
                "tab" => paragraph.push('\t'),
                "br" | "cr" => paragraph.push(' '),
                // An empty paragraph is a blank line: it separates blocks of text.
                "p" if empty && depth == 0 => content.paragraphs.push(String::new()),
                _ => {}
            },
            Event::End { name } => match local_name(name) {
                "t" => capturing = false,
                "p" => {
                    let finished = std::mem::take(&mut paragraph);
                    if depth == 0 {
                        content.paragraphs.push(finished);
                    } else {
                        if !cell.is_empty() && !finished.is_empty() {
                            cell.push(' ');
                        }
                        cell.push_str(&finished);
                    }
                }
                "tc" if depth == 1 => {
                    row.push(std::mem::take(&mut cell).trim().to_owned());
                    cells += 1;
                }
                "tr" if depth == 1 => table.push(std::mem::take(&mut row)),
                "tbl" => {
                    depth = depth.saturating_sub(1);
                    if depth == 0 {
                        content.tables.push(std::mem::take(&mut table));
                    }
                }
                _ => {}
            },
            Event::Text { .. } if capturing => paragraph.push_str(&event.text()),
            Event::Text { .. } => {}
        }
        if cells >= limits.max_cells
            || table.len() >= limits.max_rows
            || content.paragraphs.len() > limits.max_rows
        {
            content.truncated = true;
            break;
        }
    }
    if !table.is_empty() {
        content.tables.push(table);
    }
    content.tables.retain(|rows| {
        rows.iter()
            .any(|row| row.iter().any(|cell| !cell.is_empty()))
    });
    Ok(content)
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use zip::ZipWriter;
    use zip::write::SimpleFileOptions;

    use super::*;

    const BODY: &str = r#"<w:document xmlns:w="w"><w:body>
        <w:p><w:r><w:t>Offer letter for </w:t></w:r><w:r><w:t xml:space="preserve">Jane Doe</w:t></w:r></w:p>
        <w:p/>
        <w:tbl>
          <w:tr><w:tc><w:p><w:r><w:t>Name</w:t></w:r></w:p></w:tc><w:tc><w:p><w:r><w:t>SSN</w:t></w:r></w:p></w:tc></w:tr>
          <w:tr><w:tc><w:p><w:r><w:t>Jane</w:t></w:r></w:p><w:p><w:r><w:t>Doe</w:t></w:r></w:p></w:tc>
                <w:tc><w:tbl><w:tr><w:tc><w:p><w:r><w:t>219-09-9999</w:t></w:r></w:p></w:tc></w:tr></w:tbl></w:tc></w:tr>
        </w:tbl>
        <w:p><w:r><w:t>Phone:</w:t><w:tab/><w:t>415-555-0134</w:t><w:br/><w:t>after break</w:t></w:r></w:p>
    </w:body></w:document>"#;
    const FOOTER: &str =
        r#"<w:ftr xmlns:w="w"><w:p><w:r><w:t>hr@example.com</w:t></w:r></w:p></w:ftr>"#;

    fn document(parts: &[(&str, &str)]) -> Vec<u8> {
        let mut writer = ZipWriter::new(Cursor::new(Vec::new()));
        for (path, text) in parts {
            writer
                .start_file(*path, SimpleFileOptions::default())
                .unwrap();
            writer.write_all(text.as_bytes()).unwrap();
        }
        writer.finish().unwrap().into_inner()
    }

    #[test]
    fn paragraphs_become_text_and_tables_stay_tables() {
        let bytes = document(&[
            ("word/footer1.xml", FOOTER),
            ("word/document.xml", BODY),
            ("word/styles.xml", "<x/>"),
        ]);
        let extraction = read(&bytes, &Limits::default());
        assert!(extraction.gaps.is_empty(), "{:?}", extraction.gaps);

        assert_eq!(extraction.tables.len(), 1);
        assert_eq!(extraction.tables[0].scope.as_deref(), Some("table 1"));
        assert_eq!(
            extraction.tables[0].rows,
            [["Name", "SSN"], ["Jane Doe", "219-09-9999"]]
        );

        assert_eq!(extraction.texts.len(), 2);
        assert_eq!(extraction.texts[0].scope, None);
        assert_eq!(
            extraction.texts[0].lines,
            [
                "Offer letter for Jane Doe",
                "",
                "Phone:\t415-555-0134 after break"
            ]
        );
        assert_eq!(extraction.texts[1].scope.as_deref(), Some("footer1"));
        assert_eq!(extraction.texts[1].lines, ["hr@example.com"]);
    }

    #[test]
    fn containers_that_are_not_documents_are_reported() {
        for bytes in [
            b"plain bytes".to_vec(),
            vec![0xD0, 0xCF, 0x11, 0xE0, 0, 0],
            document(&[("xl/workbook.xml", "<workbook/>")]),
        ] {
            let extraction = read(&bytes, &Limits::default());
            assert!(extraction.tables.is_empty() && extraction.texts.is_empty());
            assert_eq!(extraction.gaps[0].kind, GapKind::Unreadable);
        }
    }

    #[test]
    fn a_damaged_part_is_reported_and_the_rest_is_still_read() {
        let bytes = document(&[
            ("word/document.xml", BODY),
            ("word/header1.xml", "<w:hdr><w:p><w:r"),
        ]);
        let extraction = read(&bytes, &Limits::default());
        assert_eq!(extraction.tables.len(), 1);
        assert_eq!(extraction.gaps.len(), 1);
        assert_eq!(extraction.gaps[0].scope.as_deref(), Some("header1"));
    }
}
