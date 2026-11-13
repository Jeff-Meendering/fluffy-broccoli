//! Native, in-memory extraction for text, documents, mail, PDF, and images.
//!
//! Every representation has its own stream and coordinate space. In particular, generated
//! table labels are never presented as decoded source text, and raw HTML is retained alongside
//! its readable-text view so attributes and link targets remain searchable.

use super::ExtractionContext;
use crate::{
    AttentionItem, CoordinateUnit, DEFAULT_CHUNK_OVERLAP_UTF16, DEFAULT_CHUNK_UTF16, EvidenceKind,
    EvidenceOrigin, ExtractedPart, Extraction,
};

mod image;
mod markup;
mod text;

#[cfg(feature = "formats")]
mod formats;
#[cfg(all(feature = "formats", feature = "archives"))]
mod ooxml;

const MAX_ATTENTION_MESSAGE_CHARS: usize = 2_000;

/// Route one logical resource. `name` is evidence identity, not a host filesystem path.
pub fn extract_at(
    name: &str,
    data: &[u8],
    archive_depth: usize,
    context: &ExtractionContext,
) -> Extraction {
    #[allow(unused_mut)]
    let mut extension = extension(name).to_ascii_lowercase();
    #[cfg(feature = "archives")]
    if is_zip(data)
        && !is_zip_document(&extension)
        && let Some(detected) = zip_document_extension(data, context)
    {
        extension = detected.into();
    }
    let zip_document = is_zip_document(&extension);

    if is_archive(&extension, data) && !(zip_document && is_zip(data)) {
        return super::archive::extract(name, data, archive_depth, context);
    }

    let mut out = Emitter::new_at(name, archive_depth, context);
    if extension == "pdf" || data.starts_with(b"%PDF-") {
        #[cfg(feature = "formats")]
        formats::pdf(&mut out, data);
        #[cfg(not(feature = "formats"))]
        out.issue("PDF support was not compiled in; enable the formats feature");
        return out.finish();
    }
    if extension == "one" || data.starts_with(&[0xe4, 0x52, 0x5c, 0x7b, 0x8c, 0xd8, 0xa7, 0x4d]) {
        #[cfg(feature = "formats")]
        formats::onenote(&mut out, data);
        #[cfg(not(feature = "formats"))]
        out.issue("OneNote support was not compiled in; enable the formats feature");
        return out.finish();
    }
    if image::is_image(data)
        || matches!(
            extension.as_str(),
            "png"
                | "jpg"
                | "jpeg"
                | "webp"
                | "bmp"
                | "gif"
                | "tif"
                | "tiff"
                | "pnm"
                | "pbm"
                | "pgm"
                | "ppm"
        )
    {
        image::extract(&mut out, data);
        return out.finish();
    }

    match extension.as_str() {
        "csv" | "tsv" => text::delimited(&mut out, data, extension == "tsv"),
        "html" | "htm" | "xhtml" => markup::html(&mut out, data),
        "docx" | "docm" | "dotx" | "dotm" | "pptx" | "pptm" | "potx" | "potm"
        | "ppsx" | "ppsm" | "odt" | "odp" | "epub" => {
            #[cfg(all(feature = "formats", feature = "archives"))]
            if std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                ooxml::document(&mut out, data, &extension);
            }))
            .is_err()
            {
                out.issue("OOXML parser failed on malformed input; earlier parts were retained.");
            }
            #[cfg(not(all(feature = "formats", feature = "archives")))]
            out.issue(
                "This document requires both the formats and archives features; content was not checked",
            );
        }
        "xlsx" | "xlsm" | "xlsb" | "xltx" | "xltm" | "xls" | "xla" | "xlam" | "ods" => {
            #[cfg(feature = "formats")]
            formats::workbook(&mut out, data);
            #[cfg(not(feature = "formats"))]
            out.issue("Spreadsheet support was not compiled in; enable the formats feature");
        }
        "eml" => {
            #[cfg(feature = "formats")]
            formats::email(&mut out, data);
            #[cfg(not(feature = "formats"))]
            out.issue("Email support was not compiled in; enable the formats feature");
        }
        "onetoc2" => out.issue(
            "OneNote notebook index contains no section content; scan the local .one section files. Linked or cloud notebooks were not fetched.",
        ),
        _ if is_text_extension(&extension) => text::plain(&mut out, data),
        _ if extension.is_empty() && text::looks_like_text(data) => text::plain(&mut out, data),
        _ => return super::binary::extract(name, data, context),
    }
    out.finish()
}

fn extension(name: &str) -> &str {
    let leaf = name.rsplit(['/', '\\']).next().unwrap_or(name);
    let Some((_, extension)) = leaf.rsplit_once('.') else {
        return "";
    };
    extension
}

fn eq_extension(actual: &str, expected: &'static str) -> bool {
    actual.eq_ignore_ascii_case(expected)
}

fn is_text_extension(extension: &str) -> bool {
    const EXTENSIONS: &[&str] = &[
        "txt",
        "text",
        "md",
        "markdown",
        "mdown",
        "mkd",
        "log",
        "yaml",
        "yml",
        "ini",
        "cfg",
        "conf",
        "config",
        "sql",
        "cs",
        "py",
        "pyw",
        "js",
        "mjs",
        "cjs",
        "ts",
        "env",
        "json",
        "jsonl",
        "ndjson",
        "xml",
        "xsl",
        "xslt",
        "svg",
        "toml",
        "properties",
        "sh",
        "bash",
        "zsh",
        "fish",
        "ps1",
        "psm1",
        "psd1",
        "bat",
        "cmd",
        "java",
        "go",
        "rb",
        "php",
        "c",
        "h",
        "cpp",
        "cxx",
        "cc",
        "hpp",
        "hh",
        "rs",
        "kt",
        "kts",
        "swift",
        "scala",
        "pl",
        "pm",
        "lua",
        "r",
        "vbs",
        "jsx",
        "tsx",
        "vue",
        "svelte",
        "css",
        "scss",
        "sass",
        "less",
        "vcf",
        "ics",
        "reg",
        "inf",
        "diff",
        "patch",
        "tex",
        "rst",
        "adoc",
        "xaml",
        "plist",
        "csproj",
        "fsproj",
        "vbproj",
        "props",
        "targets",
        "gradle",
        "tf",
        "tfvars",
        "hcl",
        "srt",
        "vtt",
        "rtf",
        "mht",
        "mhtml",
        "csv",
        "tsv",
        "htm",
        "html",
        "xhtml",
    ];
    EXTENSIONS
        .iter()
        .any(|candidate| eq_extension(extension, candidate))
}

fn is_zip_document(extension: &str) -> bool {
    const EXTENSIONS: &[&str] = &[
        "docx", "docm", "dotx", "dotm", "xlsx", "xlsm", "xlsb", "xltx", "xltm", "pptx", "pptm",
        "potx", "potm", "ppsx", "ppsm", "odt", "ods", "odp", "epub",
    ];
    EXTENSIONS
        .iter()
        .any(|candidate| eq_extension(extension, candidate))
}

/// Identify renamed document containers before generic archive recursion. Probe only
/// central-directory names and a bounded MIME entry; source identity keeps its original name.
#[cfg(feature = "archives")]
fn zip_document_extension(data: &[u8], context: &ExtractionContext) -> Option<&'static str> {
    use std::io::{Cursor, Read};

    let mut archive = zip::ZipArchive::new(Cursor::new(data)).ok()?;
    let mut content_types = false;
    let mut document = None;
    for index in 0..archive.len().min(context.options.max_archive_members) {
        if context.is_cancelled() {
            return None;
        }
        let entry = archive.by_index_data(index).ok()?;
        match entry.name_raw() {
            b"[Content_Types].xml" => content_types = true,
            b"word/document.xml" => document = Some("docx"),
            b"xl/workbook.xml" => document = Some("xlsx"),
            b"xl/workbook.bin" => document = Some("xlsb"),
            b"ppt/presentation.xml" => document = Some("pptx"),
            b"mimetype" if !entry.is_dir() && !entry.is_symlink() && !entry.encrypted() => {
                let file = archive.by_index(index).ok()?;
                let mut mime = String::new();
                file.take(129).read_to_string(&mut mime).ok()?;
                match mime.trim() {
                    "application/epub+zip" => return Some("epub"),
                    "application/vnd.oasis.opendocument.text" => return Some("odt"),
                    "application/vnd.oasis.opendocument.spreadsheet" => return Some("ods"),
                    "application/vnd.oasis.opendocument.presentation" => return Some("odp"),
                    _ => {}
                }
            }
            _ => {}
        }
    }
    content_types.then_some(document).flatten()
}

fn is_zip(data: &[u8]) -> bool {
    data.len() >= 4
        && data[0] == b'P'
        && data[1] == b'K'
        && matches!((data[2], data[3]), (3, 4) | (5, 6) | (7, 8))
}

fn is_archive(extension: &str, data: &[u8]) -> bool {
    const EXTENSIONS: &[&str] = &["zip", "rar", "7z", "tar", "gz", "tgz", "bz2", "xz", "jar"];
    if EXTENSIONS
        .iter()
        .any(|candidate| eq_extension(extension, candidate))
    {
        return true;
    }
    (data.len() >= 6 && data[..6] == [0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c])
        || (data.len() >= 7 && data[..6] == *b"Rar!\x1a\x07" && data[6] <= 1)
        || data.starts_with(&[0x1f, 0x8b])
        || data.starts_with(b"BZh")
        || data.starts_with(&[0xfd, b'7', b'z', b'X', b'Z', 0])
        || (data.len() >= 262 && &data[257..262] == b"ustar")
        || (is_zip(data) && !is_zip_document(extension))
}

struct Emitter<'a> {
    name: &'a str,
    #[cfg_attr(not(feature = "formats"), allow(dead_code))]
    archive_depth: usize,
    context: &'a ExtractionContext,
    extraction: Extraction,
    cancellation_reported: bool,
    stopped: bool,
}

impl<'a> Emitter<'a> {
    fn new_at(name: &'a str, archive_depth: usize, context: &'a ExtractionContext) -> Self {
        Self {
            name,
            archive_depth,
            context,
            extraction: Extraction::default(),
            cancellation_reported: false,
            stopped: false,
        }
    }

    fn finish(self) -> Extraction {
        self.extraction
    }

    #[cfg(feature = "formats")]
    fn merge(&mut self, mut child: Extraction) {
        self.stopped |= child
            .attention
            .iter()
            .any(|item| item.message.contains("Total extracted text limit reached"));
        self.extraction.parts.append(&mut child.parts);
        self.extraction.partial |= child.partial;
        let available = self
            .context
            .options
            .max_attention
            .saturating_sub(self.extraction.attention.len());
        let keep = available.min(child.attention.len());
        self.extraction
            .attention
            .extend(child.attention.drain(..keep));
        if keep < child.attention.len() {
            self.extraction.partial = true;
        }
    }

    fn running(&mut self) -> bool {
        if self.stopped {
            return false;
        }
        if !self.context.is_cancelled() {
            return true;
        }
        if !self.cancellation_reported {
            self.cancellation_reported = true;
            self.issue(
                "Extraction cancelled or timed out; remaining content was not fully checked.",
            );
        }
        false
    }

    fn issue(&mut self, message: impl AsRef<str>) {
        self.extraction.partial = true;
        if self.extraction.attention.len() >= self.context.options.max_attention {
            return;
        }
        let message: String = message
            .as_ref()
            .chars()
            .take(MAX_ATTENTION_MESSAGE_CHARS)
            .collect();
        self.extraction.attention.push(AttentionItem {
            resource_id: self.name.to_owned(),
            message,
        });
    }

    fn origin(&self, stream: &str, kind: EvidenceKind, representation: &str) -> EvidenceOrigin {
        EvidenceOrigin {
            resource_id: self.name.to_owned(),
            stream_id: stream.to_owned(),
            kind,
            representation: representation.to_owned(),
            chunk_start: 0,
            coordinate_unit: CoordinateUnit::Utf16CodeUnits,
            stride: 1,
        }
    }

    fn body(
        &mut self,
        text: &str,
        location: impl Into<String>,
        stream: &str,
        representation: &str,
    ) -> bool {
        self.emit(text, location, stream, EvidenceKind::Body, representation)
    }

    fn metadata(&mut self, key: &str, value: &str, ordinal: usize) -> bool {
        if value.trim().is_empty() {
            return true;
        }
        let stream = format!("metadata:{}:{key}:{ordinal}", key.len());
        self.emit(
            value,
            format!("metadata: {key}"),
            &stream,
            EvidenceKind::Metadata,
            "extracted-text",
        )
    }

    fn ocr(&mut self, text: &str, location: impl Into<String>, stream: &str) -> bool {
        self.emit(text, location, stream, EvidenceKind::Ocr, "ocr-text")
    }

    /// Reserve before every emitted chunk. Overlap is explicit in the absolute chunk start, so
    /// downstream occurrence identity remains stable and repeated rows never collapse together.
    fn emit(
        &mut self,
        text: &str,
        location: impl Into<String>,
        stream: &str,
        kind: EvidenceKind,
        representation: &str,
    ) -> bool {
        if text.is_empty() {
            return true;
        }
        let location = location.into();
        let mut start_byte = 0usize;
        let mut start_units = 0u64;
        while start_byte < text.len() {
            if !self.running() {
                return false;
            }
            let end_byte = chunk_end(text, start_byte, DEFAULT_CHUNK_UTF16);
            let chunk = &text[start_byte..end_byte];
            let units = chunk.encode_utf16().count();
            if !self.context.reserve_extracted_utf16(units) {
                self.stopped = true;
                self.issue(
                    "Total extracted text limit reached; remaining content was not checked.",
                );
                return false;
            }
            let mut origin = self.origin(stream, kind, representation);
            origin.chunk_start = start_units;
            self.extraction.parts.push(
                ExtractedPart::new(chunk, origin)
                    .with_continuations(start_byte > 0, end_byte < text.len())
                    .at(format!("{location} · character {start_units}")),
            );
            if end_byte == text.len() {
                break;
            }
            let next_byte = overlap_start(text, start_byte, end_byte);
            start_units += text[start_byte..next_byte].encode_utf16().count() as u64;
            start_byte = next_byte;
        }
        true
    }
}

fn chunk_end(text: &str, start: usize, limit: usize) -> usize {
    let mut units = 0usize;
    let mut end = text.len();
    let mut last_whitespace = None;
    for (relative, character) in text[start..].char_indices() {
        let next_units = units + character.len_utf16();
        if next_units > limit {
            end = start + relative;
            break;
        }
        units = next_units;
        let next = start + relative + character.len_utf8();
        if character.is_whitespace() && units >= limit / 2 {
            last_whitespace = Some(next);
        }
        end = next;
        if units == limit {
            break;
        }
    }
    if end < text.len()
        && let Some(boundary) = last_whitespace.filter(|boundary| *boundary > start)
    {
        return boundary;
    }
    // Always make progress, including a single supplementary character at a tiny test limit.
    if end == start {
        start + text[start..].chars().next().map_or(0, char::len_utf8)
    } else {
        end
    }
}

fn overlap_start(text: &str, start: usize, end: usize) -> usize {
    let chunk = &text[start..end];
    let total = chunk.encode_utf16().count();
    let target = total.saturating_sub(DEFAULT_CHUNK_OVERLAP_UTF16.min(256));
    let mut units = 0usize;
    for (relative, character) in chunk.char_indices() {
        if units >= target {
            return start + relative;
        }
        units += character.len_utf16();
    }
    end
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, atomic::AtomicBool};

    use crate::ScanOptions;

    use super::*;

    fn context(options: ScanOptions) -> ExtractionContext {
        ExtractionContext::for_root(Arc::new(options), Arc::new(AtomicBool::new(false)))
    }

    fn all_text(extraction: &Extraction) -> String {
        extraction
            .parts
            .iter()
            .map(|part| part.text.as_str())
            .collect::<String>()
    }

    #[test]
    fn decoded_chunks_keep_absolute_unicode_offsets() {
        let text = format!("🙂 {}", "word ".repeat(6_000));
        let context = context(ScanOptions::default());
        let result = super::extract_at("unicode.txt", text.as_bytes(), 0, &context);
        assert!(result.attention.is_empty());
        assert!(result.parts.len() > 1);
        for part in result.parts {
            let start = part.origin.chunk_start as usize;
            let mut units = 0usize;
            let mut byte_start = 0usize;
            for (index, character) in text.char_indices() {
                if units == start {
                    byte_start = index;
                    break;
                }
                units += character.len_utf16();
            }
            assert_eq!(units, start);
            assert!(text[byte_start..].starts_with(&part.text));
            assert_eq!(part.origin.coordinate_unit, CoordinateUnit::Utf16CodeUnits);
            assert_eq!(part.origin.representation, "decoded-text");
        }
    }

    #[test]
    fn text_budget_preserves_earlier_parts() {
        let options = ScanOptions {
            max_extracted_utf16: 25_000,
            ..ScanOptions::default()
        };
        let context = context(options);
        let text = "line@example.com\n".repeat(4_000);
        let result = super::extract_at("budget.txt", text.as_bytes(), 0, &context);
        assert!(!result.parts.is_empty());
        assert!(result.partial);
        assert!(
            result
                .attention
                .iter()
                .any(|item| item.message.contains("text limit"))
        );
    }

    #[test]
    fn empty_text_is_successfully_empty() {
        let context = context(ScanOptions::default());
        let result = super::extract_at("empty.txt", b"", 0, &context);
        assert!(result.parts.is_empty());
        assert!(result.attention.is_empty());
    }

    #[test]
    fn uppercase_and_extensionless_text_route_natively() {
        let context = context(ScanOptions::default());
        for name in ["UPPER.TXT", "notes-no-extension"] {
            let result = super::extract_at(name, b"router@example.net", 0, &context);
            assert!(
                result.parts.iter().any(|part| {
                    part.origin.stream_id == "decoded-text" && part.text == "router@example.net"
                }),
                "{name}: {:?}",
                result.attention
            );
        }
    }

    #[test]
    fn logical_name_is_not_replaced_with_a_path() {
        let context = context(ScanOptions::default());
        let result = super::extract_at("nested/original.txt", b"person@example.com", 0, &context);
        assert_eq!(result.parts[0].origin.resource_id, "nested/original.txt");
        assert!(!all_text(&result).contains("/tmp/"));
    }
}
