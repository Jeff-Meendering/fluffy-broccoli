use std::io::{Cursor, Read};

use quick_xml::Reader;
use quick_xml::events::Event;
use zip::ZipArchive;

use super::Emitter;
use super::image;
use super::markup::local_name;
use super::text::{Decoded, TableState, decode};

const MAX_XML_PART_BYTES: u64 = 64 * 1024 * 1024;
const MAX_CONTAINER_PARTS: usize = 8_192;

pub(super) fn document(out: &mut Emitter<'_>, data: &[u8], extension: &str) {
    let cursor = Cursor::new(data);
    let mut archive = match ZipArchive::new(cursor) {
        Ok(archive) => archive,
        Err(error) => {
            out.issue(format!("Could not open OOXML document: {error}"));
            return;
        }
    };
    if archive.len() > MAX_CONTAINER_PARTS {
        out.issue(
            "Document container part limit reached; only the first recognized parts were checked.",
        );
    }
    let mut names = Vec::new();
    for index in 0..archive.len().min(MAX_CONTAINER_PARTS) {
        match archive.name_for_index(index) {
            Some(Ok(name)) => names.push(name.into_owned()),
            Some(Err(error)) => out.issue(format!("Invalid document part name: {error}")),
            None => {}
        }
    }
    names.sort_by_key(|name| part_order(name, extension));

    out.metadata("resourceName", out.name, 0);
    // Core properties and relationships precede body parts so metadata survives later failures.
    for name in names.iter().filter(|name| is_metadata_part(name)) {
        if !out.running() {
            return;
        }
        match read_entry(&mut archive, name, MAX_XML_PART_BYTES) {
            Ok(bytes) => match decode(&bytes) {
                Decoded::Text(xml) => metadata_xml(out, name, &xml),
                Decoded::Binary(reason) => {
                    out.issue(format!("Metadata part {name} contains {reason}."))
                }
                Decoded::Invalid(error) => out.issue(format!("Metadata part {name}: {error}.")),
            },
            Err(error) => out.issue(format!("Could not read document part {name}: {error}")),
        }
    }

    for name in names.iter().filter(|name| is_body_part(name, extension)) {
        if !out.running() {
            return;
        }
        match read_entry(&mut archive, name, MAX_XML_PART_BYTES) {
            Ok(bytes) => match decode(&bytes) {
                Decoded::Text(xml) => body_xml(out, name, &xml),
                Decoded::Binary(reason) => {
                    out.issue(format!("Document part {name} contains {reason}."))
                }
                Decoded::Invalid(error) => out.issue(format!("Document part {name}: {error}.")),
            },
            Err(error) => out.issue(format!("Could not read document part {name}: {error}")),
        }
    }

    // Images are kept under logical embedded IDs. No staging filename enters evidence.
    let media_limit = out.context.options.max_file_bytes.min(MAX_XML_PART_BYTES);
    let mut media_ordinal = 0usize;
    for name in names.iter().filter(|name| is_image_part(name)) {
        if !out.running() {
            return;
        }
        media_ordinal += 1;
        match read_entry(&mut archive, name, media_limit) {
            Ok(bytes) => {
                let resource = format!("{}/embedded:{media_ordinal}", out.name);
                let mut embedded = Emitter::new_at(&resource, out.archive_depth, out.context);
                embedded.metadata("partName", name, 0);
                image::extract(&mut embedded, &bytes);
                out.merge(embedded.finish());
            }
            Err(error) => out.issue(format!("Embedded image {name} was not checked: {error}")),
        }
    }
}

fn part_order(name: &str, extension: &str) -> (u8, u64, String) {
    let category = if name == "word/document.xml"
        || name == "content.xml"
        || name.starts_with("ppt/slides/")
    {
        0
    } else if name.starts_with("word/header")
        || name.starts_with("word/footer")
        || name.starts_with("ppt/notesSlides/")
    {
        1
    } else if name.contains("footnote") || name.contains("endnote") || name.contains("comment") {
        2
    } else if name.starts_with("ppt/slideMasters/") || name.starts_with("ppt/slideLayouts/") {
        3
    } else if extension == "epub" {
        4
    } else {
        5
    };
    (category, trailing_number(name), name.to_owned())
}

fn trailing_number(name: &str) -> u64 {
    let digits: String = name
        .trim_end_matches(".xml")
        .chars()
        .rev()
        .take_while(char::is_ascii_digit)
        .collect();
    digits
        .chars()
        .rev()
        .collect::<String>()
        .parse()
        .unwrap_or(0)
}

fn is_metadata_part(name: &str) -> bool {
    (name.starts_with("docProps/") && name.ends_with(".xml"))
        || name == "meta.xml"
        || (name.ends_with(".rels") && name.contains("/_rels/"))
}

fn is_body_part(name: &str, extension: &str) -> bool {
    match extension {
        "docx" | "docm" | "dotx" | "dotm" => {
            name == "word/document.xml"
                || ((name.starts_with("word/header") || name.starts_with("word/footer"))
                    && name.ends_with(".xml"))
                || matches!(
                    name,
                    "word/footnotes.xml"
                        | "word/endnotes.xml"
                        | "word/comments.xml"
                        | "word/glossary/document.xml"
                )
        }
        "pptx" | "pptm" | "potx" | "potm" | "ppsx" | "ppsm" => {
            (name.starts_with("ppt/slides/slide")
                || name.starts_with("ppt/notesSlides/notesSlide")
                || name.starts_with("ppt/slideMasters/slideMaster")
                || name.starts_with("ppt/slideLayouts/slideLayout"))
                && name.ends_with(".xml")
        }
        "odt" | "odp" => name == "content.xml",
        "epub" => {
            (name.ends_with(".xhtml") || name.ends_with(".html") || name.ends_with(".htm"))
                && !name.starts_with("META-INF/")
        }
        _ => false,
    }
}

fn is_image_part(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    (lower.starts_with("word/media/")
        || lower.starts_with("ppt/media/")
        || lower.starts_with("media/"))
        && [
            ".png", ".jpg", ".jpeg", ".webp", ".bmp", ".gif", ".tif", ".tiff",
        ]
        .iter()
        .any(|extension| lower.ends_with(extension))
}

fn read_entry(
    archive: &mut ZipArchive<Cursor<&[u8]>>,
    name: &str,
    limit: u64,
) -> Result<Vec<u8>, String> {
    let entry = archive.by_name(name).map_err(|error| error.to_string())?;
    if entry.size() > limit {
        return Err(format!("expanded part exceeds the {limit}-byte limit"));
    }
    let mut bytes = Vec::with_capacity(entry.size().min(1024 * 1024) as usize);
    entry
        .take(limit.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    if bytes.len() as u64 > limit {
        return Err("expanded part size exceeds its declared size and limit".to_owned());
    }
    Ok(bytes)
}

fn metadata_xml(out: &mut Emitter<'_>, part: &str, xml: &str) {
    let mut reader = xml_reader(xml);
    let mut stack = Vec::new();
    let mut ordinal = 0usize;
    loop {
        if !out.running() {
            break;
        }
        match reader.read_event() {
            Ok(Event::Start(start)) => stack.push(local_name(start.name().as_ref())),
            Ok(Event::Empty(start)) => {
                if local_name(start.name().as_ref()) == "relationship" {
                    let mut id = String::new();
                    let mut target = None;
                    for attribute in start.attributes().with_checks(false).flatten() {
                        let key = local_name(attribute.key.as_ref());
                        if let Ok(value) =
                            attribute.normalized_value(quick_xml::XmlVersion::Implicit1_0)
                        {
                            if key == "id" {
                                id = value.into_owned();
                            } else if key == "target" {
                                target = Some(value.into_owned());
                            }
                        }
                    }
                    if let Some(target) = target {
                        let key = format!("{part}:relationship:{id}:Target");
                        out.metadata(&key, &target, ordinal);
                        ordinal += 1;
                    }
                }
            }
            Ok(Event::Text(text)) => {
                let decoded = text.xml10_content();
                let value =
                    quick_xml::escape::unescape(&decoded).unwrap_or_else(|_| decoded.clone());
                if let Some(key) = stack.last() {
                    let key = format!("{part}:{key}");
                    out.metadata(&key, value.trim(), ordinal);
                    ordinal += 1;
                }
            }
            Ok(Event::End(_)) => {
                stack.pop();
            }
            Ok(Event::CData(text)) => {
                if let Some(key) = stack.last() {
                    let key = format!("{part}:{key}");
                    out.metadata(&key, text.html_content().trim(), ordinal);
                    ordinal += 1;
                }
            }
            Ok(Event::Eof) => break,
            Ok(_) => {}
            Err(error) => {
                out.issue(format!("Malformed metadata XML in {part}: {error}"));
                break;
            }
        }
    }
}

fn body_xml(out: &mut Emitter<'_>, part: &str, xml: &str) {
    let mut reader = xml_reader(xml);
    let mut body = String::new();
    let mut tables = String::new();
    let mut table = TableState::new();
    let mut row = None;
    let mut cell: Option<String> = None;
    let mut table_depth = 0usize;
    let mut attributes = Vec::new();

    loop {
        if !out.running() {
            break;
        }
        match reader.read_event() {
            Ok(Event::Start(start)) | Ok(Event::Empty(start)) => {
                let tag = local_name(start.name().as_ref());
                for attribute in start.attributes().with_checks(false).flatten() {
                    let key = local_name(attribute.key.as_ref());
                    if matches!(
                        key.as_str(),
                        "descr" | "title" | "name" | "alt" | "href" | "target"
                    ) && let Ok(value) =
                        attribute.normalized_value(quick_xml::XmlVersion::Implicit1_0)
                    {
                        attributes.push((format!("{part}:{tag}@{key}"), value.into_owned()));
                    }
                }
                match tag.as_str() {
                    "tbl" | "table" => table_depth += 1,
                    "tr" | "table-row" if table_depth > 0 => row = Some(Vec::new()),
                    "tc" | "table-cell" if table_depth > 0 => cell = Some(String::new()),
                    "tab" => {
                        if let Some(cell) = cell.as_mut() {
                            cell.push('\t');
                        } else {
                            body.push('\t');
                        }
                    }
                    "br" | "cr" | "line-break" => {
                        append_break(cell.as_mut().unwrap_or(&mut body));
                    }
                    _ => {}
                }
            }
            Ok(Event::Text(text)) => {
                let decoded = text.xml10_content();
                let decoded =
                    quick_xml::escape::unescape(&decoded).unwrap_or_else(|_| decoded.clone());
                if let Some(cell) = cell.as_mut() {
                    cell.push_str(&decoded);
                } else {
                    body.push_str(&decoded);
                }
            }
            Ok(Event::CData(text)) => {
                if let Some(cell) = cell.as_mut() {
                    cell.push_str(&text.html_content());
                } else {
                    body.push_str(&text.html_content());
                }
            }
            Ok(Event::End(end)) => {
                let tag = local_name(end.name().as_ref());
                match tag.as_str() {
                    "tc" | "table-cell" if table_depth > 0 => finish_cell(&mut cell, &mut row),
                    "tr" | "table-row" if table_depth > 0 => {
                        finish_cell(&mut cell, &mut row);
                        if let Some(cells) = row.take() {
                            table.push(&mut tables, &cells);
                        }
                    }
                    "tbl" | "table" => {
                        table_depth = table_depth.saturating_sub(1);
                        if table_depth == 0 {
                            table.reset();
                        }
                    }
                    "p" | "h" => append_break(cell.as_mut().unwrap_or(&mut body)),
                    _ => {}
                }
            }
            Ok(Event::Eof) => break,
            Ok(_) => {}
            Err(error) => {
                out.issue(format!(
                    "Malformed document XML in {part}; earlier content was retained: {error}"
                ));
                break;
            }
        }
    }
    let stream = format!("body:{part}");
    out.body(
        &body,
        format!("Document part {part}"),
        &stream,
        "synthesized-text",
    );
    out.body(
        &tables,
        format!("Tables in {part}"),
        &format!("table:{part}"),
        "synthesized-text",
    );
    for (ordinal, (key, value)) in attributes.iter().enumerate() {
        out.metadata(key, value, ordinal);
    }
}

fn xml_reader(xml: &str) -> Reader<&[u8]> {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().check_end_names = true;
    reader.config_mut().trim_text(false);
    reader
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

#[cfg(test)]
mod tests {
    use std::sync::{Arc, atomic::AtomicBool};

    use crate::ScanOptions;
    use crate::extract::ExtractionContext;

    fn extract(name: &str, data: &[u8]) -> crate::Extraction {
        let context = ExtractionContext::for_root(
            Arc::new(ScanOptions {
                ocr: false,
                ..ScanOptions::default()
            }),
            Arc::new(AtomicBool::new(false)),
        );
        crate::extract::extract_bytes(name, data, &context)
    }

    #[test]
    fn office_fixtures_include_body_textboxes_and_notes() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/corpus/02_office");
        for (name, expected) in [
            ("staff-handbook.docx", "maria.hernandez@example.com"),
            ("textbox-only.docx", "@"),
            ("account-review.pptx", "@"),
        ] {
            let result = extract(name, &std::fs::read(root.join(name)).expect("fixture"));
            let text: String = result.parts.iter().map(|part| part.text.as_str()).collect();
            assert!(
                text.contains(expected),
                "{name}: {text:?}; {:?}",
                result.attention
            );
            assert!(
                result
                    .attention
                    .iter()
                    .all(|item| item.message.contains("OCR is off")),
                "{name}: {:?}",
                result.attention
            );
        }
    }
}
