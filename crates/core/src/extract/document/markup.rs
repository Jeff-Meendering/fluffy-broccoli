use quick_xml::Reader;
use quick_xml::events::Event;

use super::Emitter;
use super::text::{Decoded, TableState, decode};

#[derive(Default)]
struct HtmlOutput {
    body: String,
    tables: String,
    attributes: Vec<(String, String)>,
}

pub(super) fn html(out: &mut Emitter<'_>, data: &[u8]) {
    let source = match decode(data) {
        Decoded::Text(text) => text,
        Decoded::Binary(reason) => {
            out.issue(format!("HTML was not parsed because it contains {reason}."));
            return;
        }
        Decoded::Invalid(error) => {
            out.issue(format!("HTML decoding failed: {error}."));
            return;
        }
    };

    let mut parsed = HtmlOutput::default();
    parsed
        .attributes
        .push(("resourceName".to_owned(), out.name.to_owned()));
    let mut table = TableState::new();
    let mut error = None;
    parse_html(&source, &mut parsed, &mut table, out, &mut error);

    let representation = if parsed.tables.is_empty() {
        "parsed-text"
    } else {
        "synthesized-text"
    };
    out.body(&parsed.body, "HTML document text", "body", representation);
    out.body(&parsed.tables, "HTML tables", "table", "synthesized-text");
    for (ordinal, (key, value)) in parsed.attributes.iter().enumerate() {
        if !out.metadata(key, value, ordinal) {
            break;
        }
    }
    // This independent decoded coordinate space intentionally retains comments, source,
    // attribute spellings and link targets even if the readable parser above encountered an error.
    out.body(&source, "HTML raw markup", "decoded-text", "decoded-text");
    if let Some(error) = error {
        out.issue(format!(
            "HTML parsing stopped at a malformed element; parsed text is partial, raw markup was checked: {error}"
        ));
    }
}

fn parse_html(
    source: &str,
    output: &mut HtmlOutput,
    table: &mut TableState,
    out: &mut Emitter<'_>,
    failure: &mut Option<String>,
) {
    let mut reader = Reader::from_str(source);
    reader.config_mut().check_end_names = false;
    reader.config_mut().allow_unmatched_ends = true;
    reader.config_mut().trim_text(false);

    let mut suppressed = 0usize;
    let mut table_depth = 0usize;
    let mut row: Option<Vec<String>> = None;
    let mut cell: Option<String> = None;
    let mut saw_table = false;

    loop {
        if !out.running() {
            break;
        }
        let event = match reader.read_event() {
            Ok(Event::Eof) => break,
            Ok(event) => event,
            Err(error) => {
                *failure = Some(format!("at byte {}: {error}", reader.error_position()));
                break;
            }
        };
        let is_empty = matches!(event, Event::Empty(_));
        match event {
            Event::Start(start) | Event::Empty(start) => {
                let tag = local_name(start.name().as_ref());
                collect_attributes(&start, &tag, &mut output.attributes);
                match tag.as_str() {
                    "script" | "style" | "noscript" | "template" => {
                        if !is_empty {
                            suppressed += 1;
                        }
                    }
                    "table" => {
                        if table_depth == 0 {
                            table.reset();
                            saw_table = true;
                        }
                        table_depth += 1;
                    }
                    "tr" if table_depth > 0 => row = Some(Vec::new()),
                    "td" | "th" if table_depth > 0 => cell = Some(String::new()),
                    "br" | "hr" => append_break(cell.as_mut().unwrap_or(&mut output.body)),
                    "p" | "div" | "section" | "article" | "header" | "footer" | "li" | "h1"
                    | "h2" | "h3" | "h4" | "h5" | "h6"
                        if cell.is_none() && suppressed == 0 =>
                    {
                        append_break(&mut output.body);
                    }
                    _ => {}
                }
            }
            Event::End(end) => {
                let tag = local_name(end.name().as_ref());
                match tag.as_str() {
                    "script" | "style" | "noscript" | "template" => {
                        suppressed = suppressed.saturating_sub(1);
                    }
                    "td" | "th" if table_depth > 0 => finish_cell(&mut cell, &mut row),
                    "tr" if table_depth > 0 => {
                        finish_cell(&mut cell, &mut row);
                        if let Some(cells) = row.take() {
                            table.push(&mut output.tables, &cells);
                        }
                    }
                    "table" if table_depth > 0 => {
                        finish_cell(&mut cell, &mut row);
                        if let Some(cells) = row.take() {
                            table.push(&mut output.tables, &cells);
                        }
                        table_depth -= 1;
                        if table_depth == 0 {
                            table.reset();
                        }
                        append_break(&mut output.body);
                    }
                    "p" | "div" | "section" | "article" | "header" | "footer" | "li" | "h1"
                    | "h2" | "h3" | "h4" | "h5" | "h6"
                        if cell.is_none() && suppressed == 0 =>
                    {
                        append_break(&mut output.body);
                    }
                    _ => {}
                }
            }
            Event::Text(text) => {
                if suppressed > 0 {
                    continue;
                }
                let decoded = text.html_content();
                let decoded =
                    quick_xml::escape::unescape(&decoded).unwrap_or_else(|_| decoded.clone());
                if let Some(cell) = cell.as_mut() {
                    cell.push_str(&decoded);
                } else {
                    output.body.push_str(&decoded);
                }
            }
            Event::CData(text) => {
                if suppressed == 0 {
                    let decoded = text.html_content();
                    if let Some(cell) = cell.as_mut() {
                        cell.push_str(&decoded);
                    } else {
                        output.body.push_str(&decoded);
                    }
                }
            }
            // Never resolve a custom or external entity. Raw markup remains available above.
            Event::DocType(_) | Event::GeneralRef(_) => {}
            Event::Decl(_) | Event::PI(_) | Event::Comment(_) | Event::Eof => {}
        }
    }
    finish_cell(&mut cell, &mut row);
    if let Some(cells) = row.take() {
        table.push(&mut output.tables, &cells);
    }
    if saw_table && output.tables.is_empty() && table_depth > 0 {
        *failure = Some("unterminated table".to_owned());
    }
}

fn collect_attributes(
    start: &quick_xml::events::BytesStart<'_>,
    tag: &str,
    attributes: &mut Vec<(String, String)>,
) {
    for attribute in start.attributes().with_checks(false) {
        let Ok(attribute) = attribute else {
            continue;
        };
        let key = attribute.key.as_ref().to_owned();
        let Ok(value) = attribute.normalized_value(quick_xml::XmlVersion::Implicit1_0) else {
            // Unknown entities are left unresolved; do not provide a custom resolver.
            continue;
        };
        attributes.push((format!("{tag}@{key}"), value.into_owned()));
    }
}

fn finish_cell(cell: &mut Option<String>, row: &mut Option<Vec<String>>) {
    if let Some(text) = cell.take() {
        row.get_or_insert_with(Vec::new)
            .push(text.trim().to_owned());
    }
}

fn append_break(text: &mut String) {
    if !text.is_empty() && !text.ends_with(['\n', '\r']) {
        text.push('\n');
    }
}

pub(super) fn local_name(name: &str) -> String {
    name.rsplit(':').next().unwrap_or(name).to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, atomic::AtomicBool};

    use crate::ScanOptions;
    use crate::extract::ExtractionContext;

    fn extract(bytes: &[u8]) -> crate::Extraction {
        let context = ExtractionContext::for_root(
            Arc::new(ScanOptions::default()),
            Arc::new(AtomicBool::new(false)),
        );
        crate::extract::extract_bytes("page.html", bytes, &context)
    }

    #[test]
    fn html_has_readable_raw_attribute_and_table_views() {
        let result = extract(br#"<!doctype html><html><head><meta name="author" content="meta@example.net"></head><body><a href="mailto:link@example.net">Link</a><table><tr><th>dob</th><th>email</th></tr><tr><td>1991-07-24</td><td>body@example.net</td></tr></table><input type="hidden" value="hidden@example.net"><script>script@example.net</script></body></html>"#);
        assert!(result.attention.is_empty(), "{:?}", result.attention);
        let body: String = result
            .parts
            .iter()
            .filter(|part| part.origin.stream_id == "body")
            .map(|part| part.text.as_str())
            .collect();
        assert!(body.contains("Link"));
        assert!(!body.contains("script@example.net"));
        let raw: String = result
            .parts
            .iter()
            .filter(|part| part.origin.stream_id == "decoded-text")
            .map(|part| part.text.as_str())
            .collect();
        assert!(raw.contains("script@example.net"));
        let table: String = result
            .parts
            .iter()
            .filter(|part| part.origin.stream_id == "table")
            .map(|part| part.text.as_str())
            .collect();
        assert!(table.contains("DOB: 1991-07-24"));
        for expected in [
            "meta@example.net",
            "mailto:link@example.net",
            "hidden@example.net",
        ] {
            assert!(
                result
                    .parts
                    .iter()
                    .any(|part| part.origin.kind == crate::EvidenceKind::Metadata
                        && part.text == expected),
                "missing {expected}"
            );
        }
    }

    #[test]
    fn external_entities_are_never_resolved() {
        let result = extract(b"<!DOCTYPE data [<!ENTITY secret SYSTEM 'file:///etc/passwd'>]><html><body>visible@example.net &secret;</body></html>");
        let all: String = result.parts.iter().map(|part| part.text.as_str()).collect();
        assert!(all.contains("visible@example.net"));
        assert!(!all.contains("root:"));
    }

    #[test]
    fn real_html_fixture_has_link_target_and_raw_markup() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/corpus/01_plain/intranet.html");
        let result = extract(&std::fs::read(path).expect("fixture"));
        assert!(result.attention.is_empty());
        assert!(
            result
                .parts
                .iter()
                .any(|part| part.text.contains("mailto:tomas.andersson@example.co.uk"))
        );
    }
}
