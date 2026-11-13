#![cfg(feature = "report")]
//! Fresh, metadata-free PDF reports built only from scan results.
//!
//! No source PDF is opened or imported. Host paths are redacted from visible text, while detected
//! values use a narrower rule so URLs, connection strings, and slash-prefixed evidence survive.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as FmtWrite;
use std::fs::File;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use printpdf::font::PdfFont;
use printpdf::serialize::{PdfSaveOptions, to_lopdf_doc};
use printpdf::{
    Color, FontId, Mm, Op, PaintMode, ParsedFont, PdfDocument, PdfFontHandle, PdfPage, Pt, Rect,
    Rgb, TextItem,
};

use crate::{
    AttentionItem, CoordinateUnit, EntityType, EvidenceKind, Finding, ScanOptions, ScanResult,
};

const REPORT_FONT: &[u8] = include_bytes!("../assets/NotoSans-Regular.ttf");
const WIDTH: f32 = 595.0;
const HEIGHT: f32 = 842.0;
const MARGIN: f32 = 44.0;
const BOTTOM_FROM_TOP: f32 = 785.0;
const OMITTED: &str = "[absolute path omitted]";

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ReportOptions {
    /// Replace resource and stream names with stable aliases. Attention details are also omitted
    /// because parser errors commonly contain host filenames and paths.
    pub hide_file_names: bool,
    /// Include the exact context captured by the scanner. This does not re-read source files.
    pub include_context: bool,
}

impl ReportOptions {
    #[must_use]
    pub const fn new(hide_file_names: bool, include_context: bool) -> Self {
        Self {
            hide_file_names,
            include_context,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct ReportSnapshot<'a> {
    /// Scan root used only to recognize and remove absolute host prefixes. Resource IDs produced
    /// by the scanner are already root-relative.
    pub root: &'a Path,
    pub result: &'a ScanResult,
    pub scan_options: &'a ScanOptions,
    pub options: ReportOptions,
}

impl<'a> ReportSnapshot<'a> {
    /// Uses the settings recorded in the scan result, preventing configuration drift.
    #[must_use]
    pub const fn from_result(
        root: &'a Path,
        result: &'a ScanResult,
        options: ReportOptions,
    ) -> Self {
        Self {
            root,
            result,
            scan_options: &result.settings,
            options,
        }
    }

    /// Compatibility constructor for imported results that carry settings separately.
    #[must_use]
    pub const fn new(
        root: &'a Path,
        result: &'a ScanResult,
        scan_options: &'a ScanOptions,
        options: ReportOptions,
    ) -> Self {
        Self {
            root,
            result,
            scan_options,
            options,
        }
    }
}

pub struct PdfReport;

impl PdfReport {
    /// Returns labels keyed by `(resource_id, stream_id)`. Attention items use an empty stream ID.
    /// The mapping lets a caller retain the association when the PDF itself uses aliases.
    #[must_use]
    pub fn source_labels(report: &ReportSnapshot<'_>) -> BTreeMap<(String, String), String> {
        let privacy = ReportText::new(report);
        let mut keys = BTreeSet::new();
        for finding in &report.result.findings {
            keys.insert((
                finding.origin.resource_id.clone(),
                finding.origin.stream_id.clone(),
            ));
        }
        for item in &report.result.attention {
            keys.insert((item.resource_id.clone(), String::new()));
        }
        keys.into_iter()
            .map(|(resource, stream)| {
                let label = privacy.source(&resource, &stream);
                ((resource, stream), label)
            })
            .collect()
    }

    /// Writes a new PDF to an arbitrary stream. The caller controls stream persistence; use
    /// [`PdfReport::save`] for atomic, non-overwriting filesystem output.
    pub fn write<W: Write>(mut output: W, report: &ReportSnapshot<'_>) -> io::Result<()> {
        let mut font_warnings = Vec::new();
        let font = ParsedFont::from_bytes(REPORT_FONT, 0, &mut font_warnings).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "The embedded report font could not be parsed.",
            )
        })?;
        let font_id = FontId("PiiExplorerReportFont".to_owned());
        let mut document = PdfDocument::new("");
        document.metadata.info = Default::default();
        document.metadata.xmp = None;
        // A deterministic internal resource name is not a document identifier and avoids
        // printpdf's random FontId::new().
        document
            .resources
            .fonts
            .map
            .insert(font_id.clone(), PdfFont::new(font.clone()));

        let privacy = ReportText::new(report);
        let mut layout = ReportLayout::new(PdfFontHandle::External(font_id), &font);
        build_report(&mut layout, report, &privacy);
        document.pages = layout.finish();

        // printpdf 0.12 always creates an Info dictionary with epoch dates and a random trailer
        // ID. Remove both before serialization rather than merely blanking identifying values.
        // The public serializer API still produces a fresh PDF and a correct rebuilt xref table.
        let options = PdfSaveOptions {
            optimize: true,
            subset_fonts: true,
            secure: true,
            image_optimization: None,
        };
        let mut warnings = Vec::new();
        let mut pdf = to_lopdf_doc(&document, &options, &mut warnings);
        let info_id = pdf
            .trailer
            .get(b"Info")
            .ok()
            .and_then(|object| object.as_reference().ok());
        let root_id = pdf
            .trailer
            .get(b"Root")
            .ok()
            .and_then(|object| object.as_reference().ok());
        pdf.trailer.remove(b"Info");
        pdf.trailer.remove(b"ID");
        if let Some(info_id) = info_id {
            pdf.objects.remove(&info_id);
        }
        if let Some(root_id) = root_id
            && let Ok(catalog) = pdf.get_dictionary_mut(root_id)
        {
            catalog.remove(b"Metadata");
        }
        if options.optimize {
            pdf.compress();
        }
        pdf.save_to(&mut output).map_err(io::Error::other)?;
        output.flush()
    }

    /// Saves through a same-directory `create_new` staging file. The final hard link either
    /// creates the destination atomically or fails, including when the destination is a symlink.
    /// POSIX rename is never used as a fallback because it can replace an existing file.
    pub fn save(destination: impl AsRef<Path>, report: &ReportSnapshot<'_>) -> io::Result<()> {
        save_non_overwriting(destination.as_ref(), ".pii-export-", |file| {
            Self::write(file, report)
        })
    }
}

/// Convenience API for scanner and CLI callers that do not need a snapshot type of their own.
pub fn save_pdf_report(
    destination: impl AsRef<Path>,
    root: &Path,
    result: &ScanResult,
    scan_options: &ScanOptions,
    options: ReportOptions,
) -> io::Result<()> {
    PdfReport::save(
        destination,
        &ReportSnapshot::new(root, result, scan_options, options),
    )
}

pub fn write_pdf_report<W: Write>(
    output: W,
    root: &Path,
    result: &ScanResult,
    scan_options: &ScanOptions,
    options: ReportOptions,
) -> io::Result<()> {
    PdfReport::write(
        output,
        &ReportSnapshot::new(root, result, scan_options, options),
    )
}

pub fn source_labels(report: &ReportSnapshot<'_>) -> BTreeMap<(String, String), String> {
    PdfReport::source_labels(report)
}

fn build_report(layout: &mut ReportLayout<'_>, report: &ReportSnapshot<'_>, privacy: &ReportText) {
    let result = report.result;
    let partial = result.summary.cancelled
        || result.summary.limit_reached.is_some()
        || result.summary.completed < result.summary.discovered;
    layout.heading("PII findings", 25.0);
    let status = if result.summary.cancelled {
        "PARTIAL SCAN - stopped before all content was checked"
    } else if result.summary.limit_reached.is_some() {
        "PARTIAL SCAN - a configured scan limit stopped the scan"
    } else if result.summary.completed < result.summary.discovered {
        "PARTIAL SCAN - not every discovered file was processed"
    } else if !result.attention.is_empty() {
        "SCAN FINISHED - some content needs attention"
    } else {
        "SCAN FINISHED"
    };
    layout.paragraph(status, 11.0, true);
    layout.paragraph(
        &format!(
            "{} findings   |   {} / {} files processed   |   {} attention items",
            result.findings.len(),
            result.summary.completed,
            result.summary.discovered,
            result.attention.len()
        ),
        10.0,
        false,
    );
    layout.paragraph(
        &format!(
            "Recorded counts: {} findings, {} attention items. Elapsed: {} ms.",
            result.summary.findings, result.summary.attention, result.summary.elapsed_ms
        ),
        8.0,
        false,
    );
    if let Some(limit) = &result.summary.limit_reached {
        layout.paragraph(&format!("Scan limit: {}", privacy.clean(limit)), 9.0, true);
    }
    layout.paragraph(
        &format!(
            "Image reading: {}. People’s names: {}. File limit: {} bytes ({} MiB). Timeout: {} seconds.",
            on_off(report.scan_options.ocr),
            on_off(report.scan_options.detect_names),
            report.scan_options.max_file_bytes,
            report.scan_options.max_file_bytes / 1024 / 1024,
            format_seconds(report.scan_options.file_timeout.as_secs_f64())
        ),
        9.0,
        false,
    );
    layout.paragraph(
        &format!(
            "Workers: {}. Max findings: {}. Max attention items: {}. Phone regions: {}. OCR timeout: {} seconds.",
            report.scan_options.workers,
            report.scan_options.max_findings,
            report.scan_options.max_attention,
            if report.scan_options.phone_regions.is_empty() {
                "none".to_owned()
            } else {
                report
                    .scan_options
                    .phone_regions
                    .iter()
                    .map(String::as_str)
                    .collect::<Vec<_>>()
                    .join(",")
            },
            format_seconds(report.scan_options.ocr_timeout.as_secs_f64())
        ),
        8.0,
        false,
    );
    layout.paragraph(
        &format!(
            "Archive limit: {} bytes; archive members: {}; archive depth: {}; extracted text limit: {} UTF-16 code units.",
            report.scan_options.max_archive_bytes,
            report.scan_options.max_archive_members,
            report.scan_options.max_archive_depth,
            report.scan_options.max_extracted_utf16
        ),
        8.0,
        false,
    );
    layout.paragraph(
        "Potential PII requires review. No findings does not prove that a file contains no PII. Files processed includes files that could not be fully read; see Needs attention.",
        9.0,
        false,
    );
    layout.paragraph(
        if report.options.hide_file_names {
            "Source labels use file and part IDs; their mapping stays in the app. Detected values can still reveal names."
        } else {
            "Sources are relative to the scanned folder. The folder’s absolute path is omitted."
        },
        9.0,
        false,
    );
    layout.paragraph(
        "The PDF contains no author, computer name, dates, source attachments or document IDs in its metadata. Visible findings still contain sensitive information. Unsupported font characters are written as [U+XXXX].",
        9.0,
        false,
    );
    layout.paragraph(
        if report.options.include_context {
            if report.scan_options.include_context {
                "Surrounding context is included."
            } else {
                "Context was requested for this report, but the scan did not collect surrounding context."
            }
        } else {
            "Surrounding context is omitted."
        },
        9.0,
        false,
    );

    if !result.findings.is_empty() {
        layout.heading("Finding types", 14.0);
        let mut totals: BTreeMap<EntityType, usize> = BTreeMap::new();
        for finding in &result.findings {
            *totals.entry(finding.entity_type).or_default() += 1;
        }
        for (kind, count) in totals {
            layout.paragraph(&format!("{}: {count}", kind.as_str()), 10.0, false);
        }
    }

    layout.heading("Findings", 17.0);
    if result.findings.is_empty() {
        layout.paragraph("No PII detected in the checked content.", 10.0, false);
    }
    for (index, finding) in result.findings.iter().enumerate() {
        layout.ensure(100.0);
        layout.heading(&format!("{}. {}", index + 1, finding.entity_type), 12.0);
        layout.paragraph(
            &format!(
                "Source: {}",
                privacy.source(&finding.origin.resource_id, &finding.origin.stream_id)
            ),
            9.0,
            false,
        );
        layout.paragraph(
            &format!("Location: {}", privacy.location(finding)),
            9.0,
            false,
        );
        layout.paragraph(
            &format!("Value: {}", privacy.value(&finding.value)),
            11.0,
            false,
        );
        let confidence = if finding.confidence.is_finite() {
            format!("{:.0}%", f64::from(finding.confidence) * 100.0)
        } else {
            "not available".to_owned()
        };
        layout.paragraph(
            &format!(
                "Detection: {} (confidence {confidence}; not a calibrated probability)",
                privacy.clean(&finding.method)
            ),
            8.0,
            false,
        );
        if report.options.include_context {
            let context = if finding
                .origin
                .representation
                .to_ascii_lowercase()
                .contains("synthesized")
            {
                format!(
                    "[Synthesized context; may include generated labels, separators or name substitutions]\n{}",
                    finding.context
                )
            } else {
                finding.context.clone()
            };
            layout.paragraph(
                &format!(
                    "Context: {}",
                    privacy.clean_preserving(&context, &finding.value)
                ),
                9.0,
                false,
            );
        }
        layout.rule();
    }

    layout.ensure(130.0);
    layout.heading("Needs attention", 17.0);
    if result.attention.is_empty() {
        layout.paragraph(
            if partial {
                "Some content may not have been checked. The scan was incomplete; no individual file issues were recorded."
            } else {
                "No extraction issues were reported. Detection is still not exhaustive."
            },
            10.0,
            false,
        );
    }
    for item in &result.attention {
        layout.ensure(65.0);
        layout.paragraph(
            &format!("Source: {}", privacy.source(&item.resource_id, "")),
            10.0,
            true,
        );
        layout.paragraph(
            &attention_text(item, report.options.hide_file_names, privacy),
            9.0,
            false,
        );
        layout.rule();
    }
}

fn attention_text(item: &AttentionItem, aliases: bool, privacy: &ReportText) -> String {
    if aliases {
        "Content could not be fully checked. Review this source’s attention item in the app."
            .to_owned()
    } else {
        privacy.clean(&item.message)
    }
}

fn on_off(value: bool) -> &'static str {
    if value { "on" } else { "off" }
}

fn format_seconds(seconds: f64) -> String {
    if seconds.fract() == 0.0 {
        format!("{seconds:.0}")
    } else {
        format!("{seconds:.3}")
            .trim_end_matches('0')
            .trim_end_matches('.')
            .to_owned()
    }
}

struct ReportText {
    aliases: bool,
    files: BTreeMap<String, String>,
    parts: BTreeMap<(String, String), String>,
    root: String,
    private_prefixes: Vec<regex::Regex>,
}

impl ReportText {
    fn new(report: &ReportSnapshot<'_>) -> Self {
        let mut resources = BTreeSet::new();
        for source in &report.result.sources {
            resources.insert(source.resource_id.clone());
        }
        for finding in &report.result.findings {
            resources.insert(finding.origin.resource_id.clone());
        }
        for item in &report.result.attention {
            resources.insert(item.resource_id.clone());
        }
        let files = resources
            .into_iter()
            .enumerate()
            .map(|(index, resource)| (resource, format!("File {:05}", index + 1)))
            .collect();
        let part_keys: BTreeSet<(String, String)> = report
            .result
            .findings
            .iter()
            .filter(|finding| !finding.origin.stream_id.is_empty())
            .map(|finding| {
                (
                    finding.origin.resource_id.clone(),
                    finding.origin.stream_id.clone(),
                )
            })
            .collect();
        let parts = part_keys
            .into_iter()
            .enumerate()
            .map(|(index, key)| (key, format!("Part {:05}", index + 1)))
            .collect();

        let absolute_root =
            std::path::absolute(report.root).unwrap_or_else(|_| report.root.to_path_buf());
        let root = absolute_root.to_string_lossy().replace('\\', "/");
        let mut prefixes = BTreeSet::new();
        let mut add_prefix = |path: PathBuf| {
            let value = path.to_string_lossy().trim().to_owned();
            if value.len() > 3 {
                prefixes.insert(value.trim_end_matches(['/', '\\']).to_owned());
                prefixes.insert(value.replace('\\', "/"));
                prefixes.insert(value.replace('/', "\\"));
            }
        };
        add_prefix(absolute_root);
        add_prefix(std::env::temp_dir());
        if let Some(home) = std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE")) {
            add_prefix(PathBuf::from(home));
        }
        let mut prefixes: Vec<String> = prefixes
            .into_iter()
            .filter(|prefix| prefix.len() > 3)
            .collect();
        prefixes.sort_by_key(|prefix| std::cmp::Reverse(prefix.len()));
        let private_prefixes = prefixes
            .into_iter()
            .filter_map(|prefix| {
                regex::RegexBuilder::new(&regex::escape(&prefix))
                    .case_insensitive(true)
                    .build()
                    .ok()
            })
            .collect();
        Self {
            aliases: report.options.hide_file_names,
            files,
            parts,
            root,
            private_prefixes,
        }
    }

    fn file_alias(&self, resource: &str) -> String {
        self.files
            .get(resource)
            .cloned()
            .unwrap_or_else(|| "File unknown".to_owned())
    }

    fn resource(&self, resource: &str) -> String {
        if self.aliases {
            return self.file_alias(resource);
        }
        let normalized = resource.replace('\\', "/");
        let relative = strip_root(&normalized, &self.root).unwrap_or(&normalized);
        let cleaned = self.clean(relative);
        if cleaned.contains(OMITTED) || looks_like_absolute_path(relative) {
            self.file_alias(resource)
        } else {
            cleaned
        }
    }

    fn stream(&self, resource: &str, stream: &str) -> String {
        if self.aliases {
            self.parts
                .get(&(resource.to_owned(), stream.to_owned()))
                .cloned()
                .unwrap_or_else(|| "Part unknown".to_owned())
        } else {
            self.clean(stream)
        }
    }

    fn source(&self, resource: &str, stream: &str) -> String {
        let file = self.resource(resource);
        if stream.is_empty() {
            file
        } else {
            format!("{file} > {}", self.stream(resource, stream))
        }
    }

    fn location(&self, finding: &Finding) -> String {
        let origin = &finding.origin;
        let unit = match origin.coordinate_unit {
            CoordinateUnit::Utf16CodeUnits => "UTF-16",
            CoordinateUnit::Bytes => "byte",
        };
        format!(
            "{} · {} / {} · {} · {} offset {}, length {}; chunk offset {}; detector offset {}, length {}; context offset {}; stride {}",
            evidence_kind(origin.kind),
            self.resource(&origin.resource_id),
            self.stream(&origin.resource_id, &origin.stream_id),
            self.clean(&origin.representation),
            unit,
            finding.start,
            finding.length,
            origin.chunk_start,
            finding.detector_start,
            finding.detector_length,
            finding.context_start,
            origin.stride
        )
    }

    /// Detected values are evidence. Only unambiguous file URIs, drive paths, and UNC/network
    /// paths are removed; a leading slash alone never destroys a detected value.
    fn value(&self, value: &str) -> String {
        self.private(&redact_paths(value, false))
    }

    /// Free-form host text also hides bare Unix absolute paths. Exact detected values are preserved
    /// by `clean_preserving`, including URLs, connection strings, and slash-prefixed identifiers.
    fn clean(&self, text: &str) -> String {
        self.private(&redact_paths(text, true))
    }

    fn clean_preserving(&self, text: &str, preserve: &str) -> String {
        if preserve.is_empty() || self.value(preserve) != preserve {
            return self.clean(text);
        }
        let mut result = String::new();
        let mut at = 0;
        for (start, value) in text.match_indices(preserve) {
            result.push_str(&self.clean(&text[at..start]));
            result.push_str(value);
            at = start + value.len();
        }
        result.push_str(&self.clean(&text[at..]));
        result
    }

    fn private(&self, text: &str) -> String {
        let mut result = text.to_owned();
        for prefix in &self.private_prefixes {
            result = prefix.replace_all(&result, "[source root]").into_owned();
        }
        result
    }
}

fn evidence_kind(kind: EvidenceKind) -> &'static str {
    match kind {
        EvidenceKind::Body => "body",
        EvidenceKind::Filename => "filename",
        EvidenceKind::ArchiveMemberName => "archive member name",
        EvidenceKind::Metadata => "metadata",
        EvidenceKind::Ocr => "OCR",
        EvidenceKind::BinaryStrings => "binary strings",
    }
}

fn strip_root<'a>(resource: &'a str, root: &str) -> Option<&'a str> {
    if root.is_empty() {
        return None;
    }
    let root = root.trim_end_matches('/');
    if root.is_empty() {
        return resource.strip_prefix('/');
    }
    if resource.len() <= root.len()
        || !resource
            .get(..root.len())
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case(root))
    {
        return None;
    }
    resource
        .get(root.len()..)
        .and_then(|suffix| suffix.strip_prefix('/'))
        .filter(|rest| !rest.is_empty())
}

fn looks_like_absolute_path(value: &str) -> bool {
    value.starts_with('/')
        || value.starts_with("\\\\")
        || value.to_ascii_lowercase().starts_with("file:/")
        || value.as_bytes().get(1).is_some_and(|byte| *byte == b':')
            && value
                .as_bytes()
                .first()
                .is_some_and(u8::is_ascii_alphabetic)
}

fn path_start_regex() -> Option<&'static regex::Regex> {
    static REGEX: OnceLock<Option<regex::Regex>> = OnceLock::new();
    REGEX
        .get_or_init(|| regex::Regex::new(r"(?i)file:/+|[a-z]:[\\/]|\\\\|//|/").ok())
        .as_ref()
}

fn redact_paths(text: &str, bare_slash: bool) -> String {
    let Some(regex) = path_start_regex() else {
        return text.to_owned();
    };
    let mut result = String::new();
    let mut at = 0;
    let mut search = 0;
    while search < text.len() {
        let Some(candidate) = regex.find_at(text, search) else {
            break;
        };
        let token = candidate.as_str();
        let start = candidate.start();
        let previous = text[..start].chars().next_back();
        let lower = token.to_ascii_lowercase();
        let accepted = if lower.starts_with("file:") {
            previous.is_none_or(|character| !is_word(character))
        } else if token.len() == 3 && token.as_bytes()[1] == b':' {
            // A drive letter at the end of a URL scheme (the `s:/` in `https:/`) is not a drive.
            previous.is_none_or(|character| !is_word(character))
        } else if token == "//" {
            previous.is_none_or(|character| !is_word(character) && character != ':')
        } else if token == "/" {
            let next = text[candidate.end()..].chars().next();
            bare_slash
                && previous.is_none_or(|character| {
                    !is_word(character) && character != ':' && character != '/'
                })
                && next.is_some_and(|character| !character.is_whitespace() && character != '/')
        } else {
            // Two initial backslashes identify a UNC path.
            true
        };
        search = candidate.end();
        if !accepted {
            continue;
        }
        let end = consume_path(text, start);
        if end <= start {
            continue;
        }
        result.push_str(&text[at..start]);
        result.push_str(OMITTED);
        at = end;
        search = end;
    }
    if at == 0 {
        text.to_owned()
    } else {
        result.push_str(&text[at..]);
        result
    }
}

fn is_word(character: char) -> bool {
    character == '_' || character.is_alphanumeric()
}

fn consume_path(text: &str, start: usize) -> usize {
    let mut end = path_token_end(text, start);
    loop {
        let mut next = end;
        while let Some(character) = text[next..].chars().next() {
            if character != ' ' && character != '\t' {
                break;
            }
            next += character.len_utf8();
        }
        if next == end || next >= text.len() {
            break;
        }
        let next_end = path_token_end(text, next);
        let token = &text[next..next_end];
        if token.is_empty() || !(token.contains('/') || token.contains('\\')) {
            break;
        }
        end = next_end;
    }
    end
}

fn path_token_end(text: &str, start: usize) -> usize {
    for (relative, character) in text[start..].char_indices() {
        if character.is_whitespace() || matches!(character, '<' | '>' | '|' | '"') {
            return start + relative;
        }
    }
    text.len()
}

struct ReportLayout<'a> {
    font_handle: PdfFontHandle,
    font: &'a ParsedFont,
    pages: Vec<PdfPage>,
    ops: Vec<Op>,
    y: f32,
    page: usize,
}

impl<'a> ReportLayout<'a> {
    fn new(font_handle: PdfFontHandle, font: &'a ParsedFont) -> Self {
        let mut layout = Self {
            font_handle,
            font,
            pages: Vec::new(),
            ops: Vec::new(),
            y: 0.0,
            page: 0,
        };
        layout.new_page();
        layout
    }

    fn new_page(&mut self) {
        if self.page > 0 {
            self.push_page();
        }
        self.page += 1;
        self.rectangle(0.0, HEIGHT - 7.0, WIDTH, 7.0, rgb(18, 45, 56));
        self.draw(
            "PII EXPLORER / FINDINGS REPORT",
            MARGIN,
            HEIGHT - 29.0,
            8.0,
            false,
        );
        self.draw(
            "Sensitive findings - review before sharing",
            MARGIN,
            23.0,
            8.0,
            false,
        );
        self.draw(
            &format!("Page {}", self.page),
            WIDTH - 85.0,
            23.0,
            8.0,
            false,
        );
        self.y = 56.0;
    }

    fn push_page(&mut self) {
        let ops = std::mem::take(&mut self.ops);
        self.pages
            .push(PdfPage::new(Mm::from(Pt(WIDTH)), Mm::from(Pt(HEIGHT)), ops));
    }

    fn finish(mut self) -> Vec<PdfPage> {
        self.push_page();
        self.pages
    }

    fn ensure(&mut self, height: f32) {
        if self.y + height > BOTTOM_FROM_TOP {
            self.new_page();
        }
    }

    fn heading(&mut self, text: &str, size: f32) {
        self.ensure(size * 2.0 + 20.0);
        self.y += 8.0;
        self.paragraph(text, size, true);
    }

    fn paragraph(&mut self, text: &str, size: f32, accent: bool) {
        let normalized = self.normalize(text);
        let mut remaining = normalized.as_str();
        if remaining.is_empty() {
            self.y += size * 1.45 + 4.0;
            return;
        }
        while !remaining.is_empty() {
            let mut width = 0.0;
            let mut count = 0;
            for (index, character) in remaining.char_indices() {
                let next = width + self.char_width(character, size);
                if next > WIDTH - 2.0 * MARGIN && count > 0 {
                    break;
                }
                width = next;
                count = index + character.len_utf8();
                if width > WIDTH - 2.0 * MARGIN {
                    break;
                }
            }
            if count == 0 {
                count = remaining.chars().next().map_or(0, char::len_utf8);
            }
            if count < remaining.len() {
                let prefix = &remaining[..count];
                if let Some(space) = prefix.rfind(' ')
                    && space > count / 3
                {
                    count = space + 1;
                }
            }
            self.ensure(size * 1.55);
            self.draw(
                remaining[..count].trim_end(),
                MARGIN,
                HEIGHT - self.y - size,
                size,
                accent,
            );
            self.y += size * 1.45;
            remaining = &remaining[count..];
        }
        self.y += 4.0;
    }

    fn normalize(&self, text: &str) -> String {
        let mut result = String::with_capacity(text.len());
        for character in text.chars() {
            if matches!(character, '\r' | '\n' | '\t') {
                result.push(' ');
            } else if character.is_control()
                || is_format_control(character)
                || self.font.lookup_glyph_index(character as u32).is_none()
            {
                let _ = write!(result, "[U+{:04X}]", character as u32);
            } else {
                result.push(character);
            }
        }
        result
    }

    fn char_width(&self, character: char, size: f32) -> f32 {
        let units = self
            .font
            .lookup_glyph_index(character as u32)
            .and_then(|glyph| self.font.get_glyph_width(glyph))
            .unwrap_or(500);
        let em = self.font.units_per_em.max(1);
        f32::from(units) * size / f32::from(em)
    }

    #[allow(clippy::too_many_arguments)]
    fn draw(&mut self, text: &str, x: f32, y: f32, size: f32, accent: bool) {
        if text.is_empty() {
            return;
        }
        self.ops.extend([
            Op::StartTextSection,
            Op::SetTextCursor {
                pos: printpdf::Point { x: Pt(x), y: Pt(y) },
            },
            Op::SetFont {
                font: self.font_handle.clone(),
                size: Pt(size),
            },
            Op::SetFillColor {
                col: if accent {
                    rgb(17, 122, 115)
                } else {
                    rgb(40, 59, 69)
                },
            },
            Op::ShowText {
                items: vec![TextItem::Text(text.to_owned())],
            },
            Op::EndTextSection,
        ]);
    }

    fn rectangle(&mut self, x: f32, y: f32, width: f32, height: f32, color: Color) {
        self.ops.extend([
            Op::SetFillColor { col: color },
            Op::DrawRectangle {
                rectangle: Rect {
                    x: Pt(x),
                    y: Pt(y),
                    width: Pt(width),
                    height: Pt(height),
                    mode: Some(PaintMode::Fill),
                    winding_order: None,
                },
            },
        ]);
    }

    fn rule(&mut self) {
        self.ensure(12.0);
        self.rectangle(
            MARGIN,
            HEIGHT - self.y - 3.0,
            WIDTH - 2.0 * MARGIN,
            0.6,
            rgb(224, 231, 237),
        );
        self.y += 12.0;
    }
}

fn rgb(red: u8, green: u8, blue: u8) -> Color {
    Color::Rgb(Rgb {
        r: f32::from(red) / 255.0,
        g: f32::from(green) / 255.0,
        b: f32::from(blue) / 255.0,
        icc_profile: None,
    })
}

fn is_format_control(character: char) -> bool {
    matches!(
        character as u32,
        0x00ad | 0x061c | 0x06dd | 0x070f | 0x08e2 | 0x180e | 0xfeff | 0x110bd | 0x110cd | 0xe0001
    ) || matches!(character as u32,
        0x0600..=0x0605
            | 0x0890..=0x0891
            | 0x200b..=0x200f
            | 0x202a..=0x202e
            | 0x2060..=0x2064
            | 0x2066..=0x206f
            | 0xfff9..=0xfffb
            | 0x13430..=0x1343f
            | 0x1bca0..=0x1bca3
            | 0x1d173..=0x1d17a
            | 0xe0020..=0xe007f
    )
}

static STAGING_COUNTER: AtomicU64 = AtomicU64::new(0);

struct StagingPath(PathBuf);

impl Drop for StagingPath {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn save_non_overwriting<F>(destination: &Path, prefix: &str, write: F) -> io::Result<()>
where
    F: FnOnce(&mut File) -> io::Result<()>,
{
    let parent = destination
        .parent()
        .filter(|path| !path.as_os_str().is_empty());
    let parent = parent.unwrap_or_else(|| Path::new("."));
    let file_name = destination.file_name().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "A report filename is required.",
        )
    })?;
    let target = parent.join(file_name);
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos());
    let mut staged = None;
    for _ in 0..128 {
        let counter = STAGING_COUNTER.fetch_add(1, Ordering::Relaxed);
        let candidate = parent.join(format!(
            "{prefix}{}-{nonce:x}-{counter:x}.tmp",
            std::process::id()
        ));
        match crate::storage::create_private_file(&candidate) {
            Ok(file) => {
                staged = Some((StagingPath(candidate), file));
                break;
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error),
        }
    }
    let (staging, mut file) = staged.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::AlreadyExists,
            "Could not allocate a unique report staging file.",
        )
    })?;
    write(&mut file)?;
    file.sync_all()?;
    drop(file);

    match std::fs::hard_link(&staging.0, &target) {
        Ok(()) => {
            std::fs::remove_file(&staging.0)?;
            Ok(())
        }
        Err(error)
            if error.kind() == io::ErrorKind::AlreadyExists
                || std::fs::symlink_metadata(&target).is_ok() =>
        {
            Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "That filename already exists. Choose a new report filename; existing files are never overwritten.",
            ))
        }
        Err(error) => {
            #[cfg(windows)]
            {
                // Windows rename is non-overwriting; POSIX rename is not a safe fallback.
                match std::fs::rename(&staging.0, &target) {
                    Ok(()) => Ok(()),
                    Err(_) if std::fs::symlink_metadata(&target).is_ok() => Err(io::Error::new(
                        io::ErrorKind::AlreadyExists,
                        "That filename already exists; existing reports are never overwritten.",
                    )),
                    Err(_) => Err(error),
                }
            }
            #[cfg(not(windows))]
            {
                Err(error)
            }
        }
    }
}

#[cfg(all(test, feature = "formats"))]
mod tests {
    use super::*;
    use crate::{EvidenceOrigin, ScanOptions, ScanSummary};

    fn finding(resource: &str, stream: &str, kind: EntityType, value: &str) -> Finding {
        Finding {
            entity_type: kind,
            value: value.to_owned(),
            start: 0,
            length: value.encode_utf16().count() as u64,
            context: "Secret surrounding context".to_owned(),
            context_start: 0,
            detector_start: 0,
            detector_length: value.encode_utf16().count() as u64,
            confidence: 0.99,
            method: if kind == EntityType::Person {
                "Local model".to_owned()
            } else {
                "Pattern".to_owned()
            },
            origin: EvidenceOrigin::text(resource, stream, "parsed-text"),
        }
    }

    fn snapshot<'a>(
        root: &'a Path,
        result: &'a ScanResult,
        aliases: bool,
        context: bool,
    ) -> ReportSnapshot<'a> {
        ReportSnapshot::from_result(root, result, ReportOptions::new(aliases, context))
    }

    fn result() -> ScanResult {
        let mut archive = finding(
            "backup.rar",
            "staff/contacts.txt",
            EntityType::Email,
            "archive.check@example.com",
        );
        archive.origin.kind = EvidenceKind::ArchiveMemberName;
        ScanResult {
            settings: ScanOptions::default(),
            findings: vec![
                finding(
                    "HR/contacts.txt",
                    "body",
                    EntityType::Email,
                    "report.check@example.com",
                ),
                finding(
                    "Finance/contacts.txt",
                    "body",
                    EntityType::Person,
                    "José Muñoz",
                ),
                archive,
            ],
            attention: vec![AttentionItem {
                resource_id: "locked.zip".into(),
                message: "Cannot open C:\\Users\\ReportHostUser\\Documents\\locked.zip".into(),
            }],
            sources: Vec::new(),
            summary: ScanSummary {
                discovered: 4,
                completed: 4,
                findings: 3,
                attention: 1,
                cancelled: false,
                limit_reached: None,
                elapsed_ms: 10_000,
            },
        }
    }

    fn extract(path: &Path) -> String {
        pdf_extract::extract_text(path).expect("independently extract PDF text")
    }

    fn raw_contains(bytes: &[u8], needle: &[u8]) -> bool {
        bytes.windows(needle.len()).any(|window| window == needle)
    }

    #[test]
    fn metadata_is_absent_and_sources_unicode_and_values_survive() {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path().join("source");
        std::fs::create_dir(&root).expect("root");
        let mut result = result();
        // Older/imported results may contain absolute IDs; in-root paths still become relative.
        result.findings[0].origin.resource_id =
            root.join("HR/contacts.txt").to_string_lossy().into_owned();
        result.attention[0].resource_id = root.join("locked.zip").to_string_lossy().into_owned();
        let path = temp.path().join("report.pdf");
        PdfReport::save(&path, &snapshot(&root, &result, false, false)).expect("save PDF");
        let bytes = std::fs::read(&path).expect("read PDF");
        assert!(bytes.starts_with(b"%PDF-"));
        for key in [
            b"/Author".as_slice(),
            b"/Creator".as_slice(),
            b"/Producer".as_slice(),
            b"/CreationDate".as_slice(),
            b"/ModDate".as_slice(),
            b"/Metadata".as_slice(),
            b"/EmbeddedFiles".as_slice(),
            b"/JavaScript".as_slice(),
            b"/ID ".as_slice(),
        ] {
            assert!(!raw_contains(&bytes, key));
        }
        let text = extract(&path);
        for expected in [
            "report.check@example.com",
            "archive.check@example.com",
            "José Muñoz",
            "HR/contacts.txt",
            "Finance/contacts.txt",
            "staff/contacts.txt",
        ] {
            assert!(text.contains(expected), "missing {expected:?} in {text}");
        }
        assert!(!text.contains("ReportHostUser"));
        assert!(!text.contains(temp.path().to_str().expect("UTF-8 temp path")));
        assert!(!text.contains("Secret surrounding context"));
        assert!(text.contains("Cannot open [absolute path omitted]"));
        assert!(text.contains("Image reading: on"));
        assert!(text.contains("File limit: 104857600 bytes (100 MiB)"));
        assert!(text.contains("Timeout: 180 seconds"));
    }

    #[test]
    fn occurrence_provenance_and_synthesized_context_are_visible() {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path().join("source");
        let mut result = result();
        result.findings = vec![
            finding(
                "root/archive:2",
                "table",
                EntityType::Email,
                "a@example.com",
            ),
            finding(
                "root/archive:2",
                "table",
                EntityType::Email,
                "a@example.com",
            ),
        ];
        result.findings[0].start = 120;
        result.findings[1].start = 220;
        for finding in &mut result.findings {
            finding.origin.representation = "synthesized-text".into();
            finding.origin.chunk_start = 110;
        }
        let path = temp.path().join("occurrences.pdf");
        PdfReport::save(&path, &snapshot(&root, &result, false, true)).expect("save PDF");
        let text = extract(&path);
        assert!(text.contains("root/archive:2 / table"));
        assert!(text.contains("UTF-16 offset 120"));
        assert!(text.contains("UTF-16 offset 220"));
        assert!(text.contains("chunk offset 110"));
        assert!(text.contains("Synthesized context"));
    }

    #[test]
    fn aliases_hide_names_and_keep_distinct_traceable_ids() {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path().join("source");
        let result = result();
        let report = snapshot(&root, &result, true, true);
        let path = temp.path().join("aliases.pdf");
        PdfReport::save(&path, &report).expect("save PDF");
        let text = extract(&path);
        for secret in [
            "contacts.txt",
            "backup.rar",
            "locked.zip",
            "ReportHostUser",
            "staff",
        ] {
            assert!(!text.contains(secret));
        }
        let labels = PdfReport::source_labels(&report);
        assert_eq!(labels.values().collect::<BTreeSet<_>>().len(), 4);
        for label in labels.values() {
            assert!(text.contains(label), "missing alias {label}");
        }
        assert!(text.contains("Secret surrounding context"));
    }

    #[test]
    fn arbitrary_paths_are_redacted_without_destroying_evidence() {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path().join("source");
        let mut result = result();
        result.findings = vec![finding(
            "/srv/PrivateUser/secret.txt",
            "C:\\Users\\PrivateHost\\one.zip > /srv/PrivateUser/secret.txt",
            EntityType::Email,
            "report.check@example.com",
        )];
        result.attention = vec![AttentionItem {
            resource_id: "//PrivateServer/Share/secret.txt".into(),
            message: "Cannot read /opt/PrivateUser/hidden.txt; metadata: /root-secret".into(),
        }];
        let path = temp.path().join("paths.pdf");
        PdfReport::save(&path, &snapshot(&root, &result, false, false)).expect("save PDF");
        let text = extract(&path);
        for secret in [
            "PrivateHost",
            "PrivateUser",
            "PrivateServer",
            "root-secret",
            "hidden.txt",
        ] {
            assert!(!text.contains(secret), "leaked {secret}");
        }
        assert!(text.contains("report.check@example.com"));
        assert!(text.contains("Cannot read [absolute path omitted]"));
    }

    #[test]
    fn slash_values_urls_and_connection_strings_survive_path_redaction() {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path().join("source");
        let mut result = result();
        let slash = "/O=Acme/CN=jane.doe@example.com";
        result.findings = vec![
            finding("x", "body", EntityType::Email, slash),
            finding(
                "y",
                "body",
                EntityType::Credential,
                "postgres://reader:s3cr3t@db.example.com:5432/app",
            ),
            finding(
                "z",
                "body",
                EntityType::Credential,
                "https://vault.example.com/token?secret=8fa3",
            ),
        ];
        result.findings[0].context = format!(
            "cert={slash} from C:\\Users\\PrivateHost\\My Documents\\salary.xlsx for jane.doe@example.com"
        );
        result.attention.clear();
        let path = temp.path().join("values.pdf");
        PdfReport::save(&path, &snapshot(&root, &result, false, true)).expect("save PDF");
        let text = extract(&path);
        assert!(text.contains(&format!("Value: {slash}")));
        assert!(text.contains("postgres://reader:s3cr3t@db.example.com:5432/app"));
        assert!(text.contains("https://vault.example.com/token?secret=8fa3"));
        assert!(text.contains(&format!("cert={slash} from [absolute path omitted]")));
        assert!(text.contains("for jane.doe@example.com"));
        for secret in ["PrivateHost", "My Documents", "salary.xlsx"] {
            assert!(!text.contains(secret));
        }
    }

    #[test]
    fn host_path_values_are_redacted_but_unix_slash_evidence_is_not() {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path().join("source");
        let mut result = result();
        result.findings = vec![
            finding(
                "x",
                "body",
                EntityType::Credential,
                "\\\\PrivateServer\\Share\\token.txt",
            ),
            finding(
                "y",
                "body",
                EntityType::Credential,
                "D:\\backups\\credential.key",
            ),
            finding("z", "body", EntityType::Credential, "/srv/token"),
        ];
        result.attention.clear();
        let path = temp.path().join("path-values.pdf");
        PdfReport::save(&path, &snapshot(&root, &result, false, false)).expect("save PDF");
        let text = extract(&path);
        for secret in ["PrivateServer", "token.txt", "credential.key"] {
            assert!(!text.contains(secret));
        }
        assert!(text.contains("Value: /srv/token"));
        assert_eq!(text.matches(OMITTED).count(), 2);
    }

    #[test]
    fn controls_and_unsupported_glyphs_are_visible_escapes() {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path().join("source");
        let mut result = result();
        result.findings = vec![finding(
            "x",
            "body",
            EntityType::Email,
            "/CN=جين\u{202e}/email=jane.doe@example.com 李明",
        )];
        result.attention.clear();
        let path = temp.path().join("controls.pdf");
        PdfReport::save(&path, &snapshot(&root, &result, false, false)).expect("save PDF");
        let text = extract(&path);
        assert!(text.contains("[U+202E]"));
        assert!(text.contains("[U+674E][U+660E]"));
        assert!(text.contains("/email=jane.doe@example.com"));
        assert!(!text.contains('\u{202e}'));
    }

    #[test]
    fn long_values_wrap_completely_across_pages() {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path().join("source");
        let mut result = result();
        result.findings = (0..24)
            .map(|index| {
                let value = if index == 5 {
                    format!("/BEGIN-SLASH-VALUE/{}/END-SLASH-VALUE", "k".repeat(320))
                } else if index == 6 {
                    format!("{}END-OF-LONG-VALUE", "W".repeat(180))
                } else {
                    format!("person{index}@example.com")
                };
                finding("long.txt", "body", EntityType::Email, &value)
            })
            .collect();
        result.summary.findings = result.findings.len();
        result.attention.clear();
        let path = temp.path().join("multipage.pdf");
        PdfReport::save(&path, &snapshot(&root, &result, false, true)).expect("save PDF");
        let pages = pdf_extract::extract_text_by_pages(&path).expect("extract pages");
        assert!(pages.len() > 1);
        let text = pages.join("\n");
        assert!(text.contains("/BEGIN-SLASH-VALUE/"));
        assert!(text.contains(&"k".repeat(60)));
        assert!(text.contains("/END-SLASH-VALUE"));
        assert!(text.contains("END-OF-LONG-VALUE"));
        assert!(text.contains("24. Email"));
    }

    #[test]
    fn partial_and_empty_reports_do_not_claim_a_complete_clean_scan() {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path().join("source");
        let mut result = result();
        result.findings.clear();
        result.attention.clear();
        result.summary = ScanSummary {
            discovered: 7,
            completed: 2,
            cancelled: true,
            ..ScanSummary::default()
        };
        let path = temp.path().join("partial.pdf");
        PdfReport::save(&path, &snapshot(&root, &result, false, false)).expect("save PDF");
        let text = extract(&path);
        assert!(text.contains("PARTIAL SCAN"));
        assert!(text.contains("2 / 7 files processed"));
        assert!(text.contains("may not have been checked"));
        assert!(text.contains("No PII detected in the checked content"));
    }

    #[test]
    fn save_never_replaces_existing_files_or_symlinks_and_cleans_staging() {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path().join("source");
        let result = result();
        let report = snapshot(&root, &result, false, false);
        let output = temp.path().join("existing.pdf");
        std::fs::write(&output, b"previous report").expect("existing report");
        let error = PdfReport::save(&output, &report).expect_err("existing destination");
        assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(
            std::fs::read(&output).expect("existing bytes"),
            b"previous report"
        );

        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;
            let target = temp.path().join("target.pdf");
            let link = temp.path().join("link.pdf");
            std::fs::write(&target, b"source bytes").expect("target");
            symlink(&target, &link).expect("symlink");
            assert!(PdfReport::save(&link, &report).is_err());
            assert_eq!(
                std::fs::read(&target).expect("target bytes"),
                b"source bytes"
            );
        }
        assert_eq!(
            std::fs::read_dir(temp.path())
                .expect("list tempdir")
                .filter_map(Result::ok)
                .filter(|entry| entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".pii-export-"))
                .count(),
            0
        );
    }
}
