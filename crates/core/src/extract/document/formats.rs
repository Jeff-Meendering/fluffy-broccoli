use std::collections::{BTreeSet, HashSet};
use std::io::Cursor;
use std::panic::{AssertUnwindSafe, catch_unwind};

use calamine::{Reader, Sheets, open_workbook_auto_from_rs};
use mail_parser::{HeaderValue, MessageParser, PartKind};
use one_note_converter::{doc, markdown};
use pdf_extract::{Document, Object, ObjectId, PlainTextOutput};

use super::Emitter;
use super::markup;
use super::text::{TableState, push_row};

pub(super) fn workbook(out: &mut Emitter<'_>, data: &[u8]) {
    let opened = catch_unwind(AssertUnwindSafe(|| {
        open_workbook_auto_from_rs(Cursor::new(data))
    }));
    let mut workbook: Sheets<Cursor<&[u8]>> = match opened {
        Ok(Ok(workbook)) => workbook,
        Ok(Err(error)) => {
            out.issue(format!("Could not open spreadsheet: {error}"));
            return;
        }
        Err(_) => {
            out.issue(
                "Spreadsheet parser failed on malformed input; content was not fully checked.",
            );
            return;
        }
    };

    match catch_unwind(AssertUnwindSafe(|| workbook.workbook_properties())) {
        Ok(Ok(properties)) => {
            let fields = [
                ("creator", properties.creator),
                ("lastModifiedBy", properties.last_modified_by),
                ("created", properties.created),
                ("modified", properties.modified),
                ("title", properties.title),
                ("subject", properties.subject),
                ("description", properties.description),
                ("keywords", properties.keywords),
                ("category", properties.category),
                ("contentStatus", properties.content_status),
                ("revision", properties.revision),
                ("version", properties.version),
                ("application", properties.application),
                ("appVersion", properties.app_version),
                ("company", properties.company),
                ("template", properties.template),
                ("manager", properties.manager),
            ];
            let mut ordinal = 0usize;
            for (key, value) in fields {
                if let Some(value) = value {
                    out.metadata(key, &value, ordinal);
                    ordinal += 1;
                }
            }
            let mut custom: Vec<_> = properties.custom_properties.into_iter().collect();
            custom.sort_by(|left, right| left.0.cmp(&right.0));
            for (key, value) in custom {
                out.metadata(&format!("custom:{key}"), &value, ordinal);
                ordinal += 1;
            }
        }
        Ok(Err(error)) => out.issue(format!(
            "Spreadsheet properties were not fully read: {error}"
        )),
        Err(_) => {
            out.issue("Spreadsheet property parser failed; worksheets will still be checked.")
        }
    }

    let sheets = workbook.sheet_names();
    for (ordinal, sheet) in sheets.iter().enumerate() {
        if !out.running() {
            return;
        }
        out.metadata("sheet", sheet, ordinal);
        match catch_unwind(AssertUnwindSafe(|| workbook.worksheet_range(sheet))) {
            Ok(Ok(range)) => {
                let mut text = String::new();
                let mut table = TableState::new();
                for row in range.rows() {
                    if !out.running() {
                        break;
                    }
                    let cells: Vec<String> = row.iter().map(ToString::to_string).collect();
                    if cells.iter().all(|cell| cell.is_empty()) {
                        continue;
                    }
                    // The first explicit sensitive header establishes labels. Before one is
                    // found, retain the row verbatim without inventing semantics.
                    if table.headers.is_empty()
                        && !cells
                            .iter()
                            .any(|cell| !super::text::column_label(cell).is_empty())
                    {
                        push_row(&mut text, &cells, &[], false, true);
                    } else {
                        table.push(&mut text, &cells);
                    }
                }
                out.body(
                    &text,
                    format!("Worksheet {sheet}"),
                    &format!("table:sheet:{ordinal}"),
                    "synthesized-text",
                );
            }
            Ok(Err(error)) => {
                out.issue(format!("Worksheet {sheet} was not fully checked: {error}"));
                continue;
            }
            Err(_) => {
                out.issue(format!(
                    "Worksheet {sheet} parser failed; later sheets will still be checked."
                ));
                continue;
            }
        }
        match catch_unwind(AssertUnwindSafe(|| workbook.worksheet_formula(sheet))) {
            Ok(Ok(formulas)) => {
                let text = formulas
                    .rows()
                    .flat_map(|row| row.iter())
                    .filter(|formula| !formula.is_empty())
                    .cloned()
                    .collect::<Vec<_>>()
                    .join("\n");
                out.body(
                    &text,
                    format!("Formulas in {sheet}"),
                    &format!("formula:sheet:{ordinal}"),
                    "synthesized-text",
                );
            }
            Ok(Err(error)) => out.issue(format!("Formulas in {sheet} were not checked: {error}")),
            Err(_) => out.issue(format!("Formula parser failed for worksheet {sheet}")),
        }
    }
}

pub(super) fn email(out: &mut Emitter<'_>, data: &[u8]) {
    let Some(message) = MessageParser::new().parse(data) else {
        out.issue(
            "Email parser did not recognize a MIME message; raw decoded text was checked instead.",
        );
        super::text::plain(out, data);
        return;
    };
    out.metadata("resourceName", out.name, 0);

    for part in message.parts() {
        if !out.running() {
            return;
        }
        let id = part.id();
        if part.has_problems() {
            let problems = part.flags().names().collect::<Vec<_>>().join(", ");
            out.issue(format!(
                "Email MIME part {id} was incomplete or malformed: {problems}."
            ));
        }
        for (ordinal, header) in part.headers().iter().enumerate() {
            let key = format!("part:{id}:{}", header.raw_name());
            if let Ok(raw) = std::str::from_utf8(header.raw_value()) {
                out.metadata(&key, raw.trim(), ordinal * 2);
            }
            let decoded = match header.value() {
                HeaderValue::Text(text) => Some(text.to_owned()),
                HeaderValue::TextList(list) => Some(list.iter().collect::<Vec<_>>().join(", ")),
                HeaderValue::Address(list) => Some(
                    list.mailboxes()
                        .map(|mailbox| match (mailbox.name(), mailbox.address()) {
                            (Some(name), Some(address)) => format!("{name} <{address}>"),
                            (Some(name), None) => name.to_owned(),
                            (None, Some(address)) => address.to_owned(),
                            (None, None) => String::new(),
                        })
                        .filter(|value| !value.is_empty())
                        .collect::<Vec<_>>()
                        .join(", "),
                ),
                HeaderValue::DateTime(date) => Some(date.to_rfc3339()),
                HeaderValue::ContentType(content) => Some(format!(
                    "{}/{}",
                    content.ctype(),
                    content.subtype().unwrap_or_default()
                )),
                HeaderValue::Empty | HeaderValue::Received(_) => None,
            };
            if let Some(decoded) = decoded {
                out.metadata(&format!("{key}:decoded"), &decoded, ordinal * 2 + 1);
            }
        }
        if let Some(name) = part.attachment_name() {
            out.metadata(&format!("part:{id}:attachmentName"), name, 0);
        }

        match part.kind() {
            PartKind::Text | PartKind::Html => {
                let Some((text, problems)) = part.text_checked() else {
                    continue;
                };
                if !problems.is_empty() {
                    out.issue(format!(
                        "Email part {id} had decoding problems: {}; replacement or retained malformed input may remain.",
                        problems.names().collect::<Vec<_>>().join(", ")
                    ));
                }
                if matches!(part.kind(), PartKind::Html) {
                    let resource = format!("{}/html-part:{id}", out.name);
                    let mut html = Emitter::new_at(&resource, out.archive_depth, out.context);
                    markup::html(&mut html, text.as_bytes());
                    out.merge(html.finish());
                } else {
                    out.body(
                        &text,
                        format!("Email MIME part {id}"),
                        &format!("mail:part:{id}:text"),
                        "decoded-text",
                    );
                }
            }
            PartKind::Binary | PartKind::InlineBinary => {
                if out.archive_depth >= out.context.options.max_archive_depth {
                    out.issue(format!(
                        "Embedded attachment nesting limit reached at email part {id}; content was not checked."
                    ));
                    continue;
                }
                if part.decoded_len() as u64 > out.context.options.max_file_bytes {
                    out.issue(format!(
                        "Email attachment in part {id} exceeds the file size limit."
                    ));
                    continue;
                }
                let (bytes, problems) = part.decoded_checked();
                if !problems.is_empty() {
                    out.issue(format!(
                        "Email attachment part {id} had transfer-decoding problems: {}.",
                        problems.names().collect::<Vec<_>>().join(", ")
                    ));
                }
                let fallback = part
                    .content_type()
                    .and_then(|content| content.subtype().map(str::to_owned))
                    .filter(|subtype| subtype.chars().all(|c| c.is_ascii_alphanumeric()))
                    .map_or_else(
                        || format!("part-{id}.bin"),
                        |subtype| format!("part-{id}.{subtype}"),
                    );
                let filename = part.attachment_name().unwrap_or(&fallback);
                let resource = format!("{}/attachment:{id}/{filename}", out.name);
                let child = crate::extract::extract_bytes_at(
                    &resource,
                    &bytes,
                    out.archive_depth.saturating_add(1),
                    out.context,
                );
                out.merge(child);
            }
            // Nested messages and their children already appear in Message::parts().
            PartKind::Message(_) | PartKind::Multipart => {}
        }
    }
}

pub(super) fn onenote(out: &mut Emitter<'_>, data: &[u8]) {
    let loaded = catch_unwind(AssertUnwindSafe(|| one_note_converter::load(data)));
    let (_, store) = match loaded {
        Ok(Ok(loaded)) => loaded,
        Ok(Err(error)) => {
            out.issue(format!(
                "OneNote section was not recognized or was malformed: {error}"
            ));
            return;
        }
        Err(_) => {
            out.issue("OneNote parser failed on malformed input; section content was not checked.");
            return;
        }
    };
    let pages = catch_unwind(AssertUnwindSafe(|| doc::extract(&store)));
    let pages = match pages {
        Ok(pages) => pages,
        Err(_) => {
            out.issue(
                "OneNote page graph was malformed; remaining section content was not checked.",
            );
            return;
        }
    };
    if pages.is_empty() {
        out.issue("No readable OneNote pages were extracted; review this .one file manually.");
        return;
    }
    let mut any_text = false;
    let mut metadata_ordinal = 0usize;
    for (index, page) in pages.iter().enumerate() {
        if !out.running() {
            return;
        }
        out.metadata("OneNote page title", &page.title, metadata_ordinal);
        metadata_ordinal += 1;
        for author in &page.authors {
            out.metadata("OneNote author", author, metadata_ordinal);
            metadata_ordinal += 1;
        }
        if let Some(created) = page.created {
            out.metadata(
                "OneNote created",
                &markdown::iso8601(created),
                metadata_ordinal,
            );
            metadata_ordinal += 1;
        }
        if let Some(modified) = page.modified {
            out.metadata(
                "OneNote modified",
                &markdown::iso8601(modified),
                metadata_ordinal,
            );
            metadata_ordinal += 1;
        }
        if !out.running() {
            return;
        }
        let rendered = catch_unwind(AssertUnwindSafe(|| {
            markdown::render(std::slice::from_ref(page), &mut |asset| {
                if asset.filename.is_empty() {
                    asset.alt.clone()
                } else {
                    asset.filename.clone()
                }
            })
        }));
        match rendered {
            Ok(text) => {
                any_text |= !page.blocks.is_empty()
                    || (!page.title.trim().is_empty() && page.title != "Untitled page");
                out.body(
                    &text,
                    format!("OneNote page {}", index + 1),
                    &format!("onenote:page:{index}"),
                    "synthesized-text",
                );
            }
            Err(_) => out.issue(format!("OneNote page {} could not be rendered.", index + 1)),
        }
    }
    if !any_text {
        out.issue("No readable text extracted from OneNote; review this .one file manually.");
    }
}

pub(super) fn pdf(out: &mut Emitter<'_>, data: &[u8]) {
    let loaded = catch_unwind(AssertUnwindSafe(|| Document::load_mem(data)));
    let mut document = match loaded {
        Ok(Ok(document)) => document,
        Ok(Err(error)) => {
            out.issue(format!("Could not parse PDF: {error}"));
            return;
        }
        Err(_) => {
            out.issue("PDF parser failed on malformed input; content was not checked.");
            return;
        }
    };
    if document.is_encrypted() {
        let decrypted = catch_unwind(AssertUnwindSafe(|| document.decrypt("")));
        match decrypted {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                out.issue(format!(
                    "Password-protected PDF could not be decrypted with an empty password: {error}"
                ));
                return;
            }
            Err(_) => {
                out.issue("PDF decryption failed on malformed encryption data.");
                return;
            }
        }
    }

    if catch_unwind(AssertUnwindSafe(|| pdf_metadata(out, &document))).is_err() {
        out.issue("PDF metadata parser failed; body extraction will continue.");
    }
    if catch_unwind(AssertUnwindSafe(|| pdf_forms(out, &document))).is_err() {
        out.issue("PDF form or annotation parser failed; body extraction will continue.");
    }
    let pages = catch_unwind(AssertUnwindSafe(|| document.get_pages()));
    let pages = match pages {
        Ok(pages) => pages,
        Err(_) => {
            out.issue(
                "PDF page tree was malformed; metadata was checked but page content was not.",
            );
            return;
        }
    };
    if pages.is_empty() {
        out.issue("PDF contains no readable pages; page content was not checked.");
        return;
    }
    let mut empty_pages = BTreeSet::new();
    let mut image_pages = BTreeSet::new();
    let page_numbers = pages.keys().copied().collect();
    for (page_number, page_id) in pages {
        if !out.running() {
            return;
        }
        if catch_unwind(AssertUnwindSafe(|| pdf_page_has_image(&document, page_id)))
            .unwrap_or(false)
        {
            image_pages.insert(page_number);
        }
        let extracted = catch_unwind(AssertUnwindSafe(|| {
            let mut text = String::new();
            let mut output = PlainTextOutput::new(&mut text);
            pdf_extract::output_doc_page(&document, &mut output, page_number)?;
            Ok::<String, pdf_extract::OutputError>(text)
        }));
        match extracted {
            Ok(Ok(text)) => {
                if text.trim().is_empty() {
                    empty_pages.insert(page_number);
                }
                out.body(
                    &text,
                    format!("PDF page {page_number}"),
                    &format!("pdf:page:{page_number}"),
                    "extracted-text",
                );
            }
            Ok(Err(error)) => out.issue(format!(
                "PDF page {page_number} was not fully checked; earlier pages were retained: {error}"
            )),
            Err(_) => out.issue(format!(
                "PDF page {page_number} caused a parser failure; earlier pages were retained."
            )),
        }
    }
    if out.context.options.ocr {
        // Render every page: inline images and images inside Form XObjects can coexist with
        // extractable text and are not reliably identified by a shallow resource inventory.
        super::image::pdf_pages(out, data, &page_numbers);
        return;
    }
    if !empty_pages.is_empty() {
        let count = empty_pages.len();
        out.issue(format!(
            "{count} PDF page(s) had no extractable text and image content was not OCR checked (OCR is off)."
        ));
    }
    if !image_pages.is_empty() {
        let count = image_pages.len();
        out.issue(format!(
            "Embedded images on {count} PDF page(s) were not OCR checked (OCR is off)."
        ));
    }
}

fn pdf_page_has_image(document: &Document, page_id: ObjectId) -> bool {
    let mut current = Some(page_id);
    let mut visited = HashSet::new();
    for _ in 0..64 {
        let Some(id) = current else {
            return false;
        };
        if !visited.insert(id) {
            return false;
        }
        let Ok(page) = document.get_dictionary(id) else {
            return false;
        };
        if let Ok(resources) = page.get(b"Resources") {
            let Some(resources) =
                resolve(document, resources).and_then(|object| object.as_dict().ok())
            else {
                return false;
            };
            if let Ok(objects) = resources.get(b"XObject") {
                let Some(objects) =
                    resolve(document, objects).and_then(|object| object.as_dict().ok())
                else {
                    return false;
                };
                for object in objects.iter().map(|(_, object)| object) {
                    if let Some(Object::Stream(stream)) = resolve(document, object)
                        && stream
                            .dict
                            .get(b"Subtype")
                            .and_then(Object::as_name)
                            .is_ok_and(|name| name == b"Image")
                    {
                        return true;
                    }
                }
            }
        }
        current = page.get(b"Parent").and_then(Object::as_reference).ok();
    }
    false
}

fn pdf_metadata(out: &mut Emitter<'_>, document: &Document) {
    let Some(info) = document
        .trailer
        .get(b"Info")
        .ok()
        .and_then(|object| resolve(document, object))
        .and_then(|object| object.as_dict().ok())
    else {
        return;
    };
    let mut entries: Vec<_> = info.iter().collect();
    entries.sort_by(|left, right| left.0.cmp(right.0));
    for (ordinal, (key, value)) in entries.into_iter().enumerate() {
        if let Some(value) = pdf_object_text(document, value) {
            out.metadata(
                &format!("PDF:{}", String::from_utf8_lossy(key)),
                &value,
                ordinal,
            );
        }
    }
}

fn pdf_forms(out: &mut Emitter<'_>, document: &Document) {
    let Some(root) = document
        .trailer
        .get(b"Root")
        .ok()
        .and_then(|object| resolve(document, object))
        .and_then(|object| object.as_dict().ok())
    else {
        return;
    };
    if let Some(fields) = root
        .get(b"AcroForm")
        .ok()
        .and_then(|object| resolve(document, object))
        .and_then(|object| object.as_dict().ok())
        .and_then(|form| form.get(b"Fields").ok())
    {
        let mut visited = HashSet::new();
        let mut ordinal = 0usize;
        pdf_field(out, document, fields, 0, &mut visited, &mut ordinal);
    }

    let mut ordinal = 0usize;
    for (page, id) in document.get_pages() {
        let Ok(page_dict) = document.get_dictionary(id) else {
            continue;
        };
        let Some(annotations) = page_dict
            .get(b"Annots")
            .ok()
            .and_then(|object| resolve(document, object))
            .and_then(|object| object.as_array().ok())
        else {
            continue;
        };
        for annotation in annotations {
            let Some(dictionary) =
                resolve(document, annotation).and_then(|object| object.as_dict().ok())
            else {
                continue;
            };
            for key in [b"Contents".as_slice(), b"T", b"Subj", b"RC", b"TU"] {
                if let Some(value) = dictionary
                    .get(key)
                    .ok()
                    .and_then(|object| pdf_object_text(document, object))
                {
                    out.metadata(
                        &format!(
                            "PDF:page:{page}:annotation:{}",
                            String::from_utf8_lossy(key)
                        ),
                        &value,
                        ordinal,
                    );
                    ordinal += 1;
                }
            }
        }
    }
}

fn pdf_field(
    out: &mut Emitter<'_>,
    document: &Document,
    object: &Object,
    depth: usize,
    visited: &mut HashSet<ObjectId>,
    ordinal: &mut usize,
) {
    if depth > 64 || *ordinal >= 10_000 || !out.running() {
        if *ordinal >= 10_000 {
            out.issue("PDF form field limit reached; remaining fields were not checked.");
        }
        return;
    }
    if let Object::Reference(id) = object
        && !visited.insert(*id)
    {
        return;
    }
    let Some(object) = resolve(document, object) else {
        return;
    };
    if let Ok(fields) = object.as_array() {
        for field in fields {
            pdf_field(out, document, field, depth + 1, visited, ordinal);
        }
        return;
    }
    let Ok(dictionary) = object.as_dict() else {
        return;
    };
    *ordinal += 1;
    for key in [b"T".as_slice(), b"TU", b"TM", b"V", b"DV", b"FT"] {
        if let Some(value) = dictionary
            .get(key)
            .ok()
            .and_then(|object| pdf_object_text(document, object))
        {
            out.metadata(
                &format!("PDF:form:{}:{}", *ordinal, String::from_utf8_lossy(key)),
                &value,
                *ordinal,
            );
        }
    }
    if let Ok(children) = dictionary.get(b"Kids") {
        pdf_field(out, document, children, depth + 1, visited, ordinal);
    }
}

fn resolve<'a>(document: &'a Document, mut object: &'a Object) -> Option<&'a Object> {
    let mut visited = HashSet::new();
    for _ in 0..64 {
        let Object::Reference(id) = object else {
            return Some(object);
        };
        if !visited.insert(*id) {
            return None;
        }
        object = document.get_object(*id).ok()?;
    }
    None
}

fn pdf_object_text(document: &Document, object: &Object) -> Option<String> {
    let object = resolve(document, object)?;
    match object {
        Object::String(_, _) => pdf_extract::decode_text_string(object).ok(),
        Object::Name(name) => Some(String::from_utf8_lossy(name).into_owned()),
        Object::Integer(value) => Some(value.to_string()),
        Object::Real(value) => Some(value.to_string()),
        Object::Boolean(value) => Some(value.to_string()),
        Object::Array(values) => Some(
            values
                .iter()
                .filter_map(|value| pdf_object_text(document, value))
                .collect::<Vec<_>>()
                .join(" | "),
        ),
        Object::Null | Object::Dictionary(_) | Object::Stream(_) | Object::Reference(_) => None,
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
    fn real_office_mail_and_pdf_fixtures_extract_identifiers() {
        let root =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/corpus");
        for (relative, expected) in [
            ("02_office/payroll.xlsx", "maria.hernandez@example.com"),
            ("02_office/lease-thread.eml", "maria.hernandez@example.com"),
            ("03_pdf/invoice.pdf", "priya.r@example.net"),
        ] {
            let name = relative.rsplit('/').next().expect("name");
            let result = extract(name, &std::fs::read(root.join(relative)).expect("fixture"));
            let text: String = result.parts.iter().map(|part| part.text.as_str()).collect();
            assert!(
                text.contains(expected),
                "{relative}: {text:?}; {:?}",
                result.attention
            );
            assert!(
                result.attention.is_empty(),
                "{relative}: {:?}",
                result.attention
            );
        }
    }

    #[test]
    fn real_onenote_fixture_extracts_page_text() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/testOneNote2016.one");
        let data = std::fs::read(path).expect("fixture");
        for name in ["testOneNote2016.one", "renamed.bin"] {
            let result = extract(name, &data);
            let text: String = result.parts.iter().map(|part| part.text.as_str()).collect();
            assert!(
                text.contains("This is one note 2016"),
                "{name}: {text:?}; {:?}",
                result.attention
            );
            assert!(result.attention.is_empty(), "{:?}", result.attention);
        }
    }

    #[test]
    fn email_attachment_uses_logical_identity_and_native_recursion() {
        let message = b"From: sender@example.net\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=\"x\"\r\n\r\n--x\r\nContent-Type: text/plain\r\n\r\nbody@example.net\r\n--x\r\nContent-Type: application/octet-stream; name=\"note.txt\"\r\nContent-Disposition: attachment; filename=\"note.txt\"\r\nContent-Transfer-Encoding: base64\r\n\r\nYXR0YWNobWVudEBleGFtcGxlLm5ldA==\r\n--x--\r\n";
        let result = extract("message.eml", message);
        assert!(result.attention.is_empty(), "{:?}", result.attention);
        assert!(
            result.parts.iter().any(|part| {
                part.origin.resource_id == "message.eml/attachment:2/note.txt"
                    && part.text.contains("attachment@example.net")
            }),
            "{:?}",
            result.parts
        );
    }

    #[test]
    fn broken_pdf_is_an_explicit_partial_result() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/corpus/08_broken/truncated.pdf");
        let result = extract("truncated.pdf", &std::fs::read(path).expect("fixture"));
        assert!(result.partial);
        assert!(!result.attention.is_empty());
    }
}
