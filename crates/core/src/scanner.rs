//! Deterministic, bounded folder scanning with occurrence-level evidence.

use std::collections::HashSet;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Instant;

use crate::hash::sha256_hex;
use thiserror::Error;
use walkdir::WalkDir;

use crate::custom::{CustomDetector, CustomRuleError};
use crate::detectors::names::NameDetector;
use crate::detectors::{EntitySpan, PatternDetector};
use crate::extract::{ExtractionContext, Extractor, NativeExtractor};
use crate::text::Utf16Index;
use crate::{
    AttentionItem, CoordinateUnit, DEFAULT_CHUNK_OVERLAP_UTF16, DEFAULT_CHUNK_UTF16, EntityType,
    EvidenceKind, EvidenceOrigin, ExtractedPart, Finding, ScanOptions, ScanProgress, ScanResult,
    ScanSummary, SourceRecord,
};

#[derive(Debug, Error)]
pub enum ScanError {
    #[error("Scan root does not exist or is not accessible.")]
    InvalidRoot,
    #[error("Worker count must be between 1 and 8.")]
    InvalidWorkers,
    #[error("File and archive limits must be positive.")]
    InvalidLimits,
    #[error("Phone regions must be supported two-letter country codes, such as US or GB.")]
    InvalidPhoneRegions,
    #[error("No file name is available for the selected root.")]
    MissingRootName,
    #[error(transparent)]
    CustomRules(#[from] CustomRuleError),
}

#[derive(Debug, Clone)]
pub enum ScanEvent {
    Findings(Vec<Finding>),
    Attention(Vec<AttentionItem>),
    Sources(Vec<SourceRecord>),
    Progress(ScanProgress),
}

pub struct Scanner {
    options: Arc<ScanOptions>,
    patterns: PatternDetector,
    custom: CustomDetector,
    names: Option<NameDetector>,
    startup_attention: Vec<AttentionItem>,
    retain_results: bool,
    extractor: Arc<dyn Extractor>,
}

impl Scanner {
    pub fn new(mut options: ScanOptions) -> Result<Self, ScanError> {
        if !(1..=8).contains(&options.workers) {
            return Err(ScanError::InvalidWorkers);
        }
        if options.max_file_bytes == 0
            || options.max_findings == 0
            || options.max_attention == 0
            || options.max_archive_bytes == 0
            || options.max_archive_members == 0
            || options.max_extracted_utf16 == 0
            || options.file_timeout.is_zero()
            || options.ocr_timeout.is_zero()
        {
            return Err(ScanError::InvalidLimits);
        }

        options.phone_regions = options
            .phone_regions
            .iter()
            .map(|region| region.trim().to_ascii_uppercase())
            .collect();
        if options.phone_regions.is_empty()
            || options.phone_regions.iter().any(|region| {
                region.len() != 2 || phonenumber::metadata::DATABASE.by_id(region).is_none()
            })
        {
            return Err(ScanError::InvalidPhoneRegions);
        }
        let patterns = PatternDetector::new(options.phone_regions.clone());
        if options.tesseract_path.is_none() {
            options.tesseract_path = default_asset(if cfg!(windows) {
                "ocr/tesseract.exe"
            } else {
                "ocr/tesseract"
            })
            .or_else(system_tesseract);
        }
        if options.tessdata_path.is_none() {
            options.tessdata_path = default_asset("ocr/tessdata/eng.traineddata")
                .and_then(|path| path.parent().map(Path::to_path_buf));
        }
        let custom = CustomDetector::new(&options.custom_rules)?;
        let mut startup_attention = Vec::new();
        let names = if options.detect_names {
            let model = options
                .model_path
                .clone()
                .or_else(|| default_asset("models/model_quantized.onnx"));
            let vocab = options
                .vocab_path
                .clone()
                .or_else(|| default_asset("models/vocab.txt"));
            match (model, vocab) {
                (Some(model), Some(vocab)) => {
                    let threads = (std::thread::available_parallelism().map_or(1, |n| n.get())
                        / options.workers)
                        .clamp(1, 4);
                    match NameDetector::new(&model, &vocab, threads) {
                        Ok(detector) => Some(detector),
                        Err(error) => {
                            startup_attention.push(AttentionItem {
                                resource_id: "engine".into(),
                                message: format!(
                                    "Local name model could not be loaded ({error}); labelled names and all other detectors remain enabled."
                                ),
                            });
                            None
                        }
                    }
                }
                _ => {
                    startup_attention.push(AttentionItem {
                        resource_id: "engine".into(),
                        message: "Local name model is not installed; labelled names and all other detectors remain enabled. Install the pinned model for broader person-name coverage.".into(),
                    });
                    None
                }
            }
        } else {
            None
        };

        Ok(Self {
            options: Arc::new(options),
            patterns,
            custom,
            names,
            startup_attention,
            retain_results: true,
            extractor: Arc::new(NativeExtractor),
        })
    }

    #[must_use]
    pub fn options(&self) -> &ScanOptions {
        &self.options
    }

    /// In streaming mode every accepted record is delivered through events, but records are
    /// not also retained in the returned vectors. Summary totals and limits remain exact.
    #[must_use]
    pub fn with_result_retention(mut self, retain: bool) -> Self {
        self.retain_results = retain;
        self
    }

    #[must_use]
    pub fn with_extractor(mut self, extractor: Arc<dyn Extractor>) -> Self {
        self.extractor = extractor;
        self
    }

    #[must_use]
    pub fn startup_attention(&self) -> &[AttentionItem] {
        &self.startup_attention
    }

    #[must_use]
    pub fn name_model_available(&self) -> bool {
        self.names.is_some()
    }

    #[must_use]
    pub fn model_path(&self) -> Option<PathBuf> {
        self.options
            .model_path
            .clone()
            .or_else(|| default_asset("models/model_quantized.onnx"))
    }

    #[must_use]
    pub fn vocab_path(&self) -> Option<PathBuf> {
        self.options
            .vocab_path
            .clone()
            .or_else(|| default_asset("models/vocab.txt"))
    }

    pub fn scan(
        &self,
        root: impl AsRef<Path>,
        cancelled: Arc<AtomicBool>,
    ) -> Result<ScanResult, ScanError> {
        self.scan_with_events(root, cancelled, |_| {})
    }

    pub fn scan_with_events<F>(
        &self,
        root: impl AsRef<Path>,
        cancelled: Arc<AtomicBool>,
        callback: F,
    ) -> Result<ScanResult, ScanError>
    where
        F: Fn(ScanEvent) + Send + Sync,
    {
        let started = Instant::now();
        let root = root.as_ref();
        let metadata = std::fs::metadata(root).map_err(|_| ScanError::InvalidRoot)?;
        if !metadata.is_dir() && !metadata.is_file() {
            return Err(ScanError::InvalidRoot);
        }
        let root_display = if metadata.is_file() {
            root.file_name()
                .ok_or(ScanError::MissingRootName)?
                .to_string_lossy()
                .into_owned()
        } else {
            String::new()
        };
        if metadata.is_file() && root.parent().is_none() {
            return Err(ScanError::MissingRootName);
        }

        let (sender, receiver) = crossbeam_channel::bounded::<PathBuf>(256);
        let shared = Shared {
            result: Mutex::new(ScanResult {
                settings: self.options.as_ref().clone(),
                ..ScanResult::default()
            }),
            callback: &callback,
            cancelled: &cancelled,
            options: &self.options,
            discovered: AtomicU64::new(0),
            completed: AtomicU64::new(0),
            limit: Mutex::new(None),
            findings: AtomicUsize::new(0),
            attention: AtomicUsize::new(0),
            retain_results: self.retain_results,
        };
        shared.publish_attention(self.startup_attention.clone());

        std::thread::scope(|scope| {
            let discover_root = root.to_path_buf();
            let discover_base = if metadata.is_dir() {
                root
            } else {
                root.parent().unwrap_or_else(|| Path::new("."))
            };
            let discover_base = discover_base.to_path_buf();
            let root_is_file = metadata.is_file();
            let discover_is_file = root_is_file;
            let discover_options = self.options.clone();
            let discover_shared = &shared;
            let discover_cancelled = cancelled.clone();
            scope.spawn(move || {
                if discover_is_file {
                    discover_shared.discovered.fetch_add(1, Ordering::Relaxed);
                    discover_shared.progress();
                    let _ = sender.send(discover_root);
                    return;
                }

                let walker = WalkDir::new(&discover_root)
                    .follow_links(false)
                    .max_open(64)
                    .into_iter()
                    .filter_entry(|entry| {
                        if discover_cancelled.load(Ordering::Relaxed) {
                            return false;
                        }
                        let relative = logical_relative(&discover_base, entry.path());
                        if entry.file_type().is_symlink() {
                            discover_shared.publish_attention(vec![AttentionItem {
                                resource_id: relative,
                                message: "Symbolic link was not followed.".into(),
                            }]);
                            return false;
                        }
                        if entry.depth() > 0
                            && entry.file_type().is_dir()
                            && let Some(name) = entry.file_name().to_str()
                            && discover_options.excluded_directories.contains(name)
                        {
                            discover_shared.publish_attention(vec![AttentionItem {
                                resource_id: relative,
                                message: "Excluded dependency or system directory was not scanned."
                                    .into(),
                            }]);
                            return false;
                        }
                        true
                    });

                for entry in walker {
                    if discover_cancelled.load(Ordering::Relaxed) {
                        break;
                    }
                    match entry {
                        Ok(entry) if entry.file_type().is_file() => {
                            discover_shared.discovered.fetch_add(1, Ordering::Relaxed);
                            discover_shared.progress();
                            if sender.send(entry.into_path()).is_err() {
                                break;
                            }
                        }
                        Ok(_) => {}
                        Err(error) => {
                            let resource_id = error
                                .path()
                                .map(|path| logical_relative(&discover_base, path))
                                .unwrap_or_else(|| "discovery".into());
                            let reason = error.io_error().map_or_else(
                                || "directory traversal failed".into(),
                                ToString::to_string,
                            );
                            discover_shared.publish_attention(vec![AttentionItem {
                                resource_id,
                                message: format!(
                                    "Filesystem entry could not be inspected: {reason}"
                                ),
                            }]);
                        }
                    }
                }
            });

            for _ in 0..self.options.workers {
                let receiver = receiver.clone();
                let worker_shared = &shared;
                let worker_root_name = root_display.clone();
                let worker_base = if root_is_file {
                    root.parent()
                        .unwrap_or_else(|| Path::new("."))
                        .to_path_buf()
                } else {
                    root.to_path_buf()
                };
                scope.spawn(move || {
                    while let Ok(path) = receiver.recv() {
                        if worker_shared.cancelled.load(Ordering::Relaxed) {
                            break;
                        }
                        let relative = if root_is_file {
                            worker_root_name.clone()
                        } else {
                            logical_relative(&worker_base, &path)
                        };
                        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                            self.process_root(&path, &relative, worker_shared);
                        }));
                        if result.is_err() {
                            worker_shared.publish_attention(vec![AttentionItem {
                                resource_id: relative,
                                message: "A parser failed unexpectedly; remaining content was not checked.".into(),
                            }]);
                        }
                        worker_shared.completed.fetch_add(1, Ordering::Relaxed);
                        worker_shared.progress();
                    }
                });
            }
            // Only workers own receiving endpoints. A producer blocked on the bounded queue
            // must wake if all workers stop, including when a callback unwinds.
            drop(receiver);
        });

        Ok(shared.finish(started))
    }

    /// Scan one root resource with a caller-supplied logical identity. This supports durable
    /// coordinators without losing parent-directory filename evidence or nested provenance.
    /// Engine-level startup warnings are available separately through `startup_attention()`.
    pub fn scan_resource_with_events<F>(
        &self,
        path: &Path,
        resource_id: &str,
        cancelled: Arc<AtomicBool>,
        callback: F,
    ) -> Result<ScanResult, ScanError>
    where
        F: Fn(ScanEvent) + Send + Sync,
    {
        let metadata = std::fs::symlink_metadata(path).map_err(|_| ScanError::InvalidRoot)?;
        if !metadata.is_file() || resource_id.is_empty() || resource_id.contains('\0') {
            return Err(ScanError::InvalidRoot);
        }
        let started = Instant::now();
        let shared = Shared {
            result: Mutex::new(ScanResult {
                settings: self.options.as_ref().clone(),
                ..ScanResult::default()
            }),
            callback: &callback,
            cancelled: &cancelled,
            options: &self.options,
            discovered: AtomicU64::new(1),
            completed: AtomicU64::new(0),
            limit: Mutex::new(None),
            findings: AtomicUsize::new(0),
            attention: AtomicUsize::new(0),
            retain_results: self.retain_results,
        };
        if !cancelled.load(Ordering::Relaxed) {
            if std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                self.process_root(path, resource_id, &shared)
            }))
            .is_err()
            {
                shared.publish_attention(vec![AttentionItem {
                    resource_id: resource_id.into(),
                    message: "A parser failed unexpectedly; remaining content was not checked."
                        .into(),
                }]);
            }
            shared.completed.store(1, Ordering::Relaxed);
            shared.progress();
        }
        Ok(shared.finish(started))
    }

    /// Detect directly in supplied text without filesystem staging or document extraction.
    pub fn detect_text(&self, text: &str, cancelled: Arc<AtomicBool>) -> ScanResult {
        self.detect_text_with_events(text, cancelled, |_| {})
    }

    pub fn detect_text_with_events<F>(
        &self,
        text: &str,
        cancelled: Arc<AtomicBool>,
        callback: F,
    ) -> ScanResult
    where
        F: Fn(ScanEvent) + Send + Sync,
    {
        let started = Instant::now();
        let shared = Shared {
            result: Mutex::new(ScanResult {
                settings: self.options.as_ref().clone(),
                ..ScanResult::default()
            }),
            callback: &callback,
            cancelled: &cancelled,
            options: &self.options,
            discovered: AtomicU64::new(1),
            completed: AtomicU64::new(0),
            limit: Mutex::new(None),
            findings: AtomicUsize::new(0),
            attention: AtomicUsize::new(0),
            retain_results: self.retain_results,
        };
        shared.publish_attention(self.startup_attention.clone());
        shared.publish_sources(vec![SourceRecord {
            resource_id: "stdin".into(),
            size: text.len() as u64,
            sha256: Some(sha256_hex(text.as_bytes())),
        }]);
        let origin = EvidenceOrigin::text("stdin", "body", "decoded-text");
        let index = Utf16Index::new(text);
        let end = index.byte_offset_floor(self.options.max_extracted_utf16);
        let part =
            ExtractedPart::new(&text[..end], origin).with_continuations(false, end < text.len());
        if end < text.len() {
            shared.publish_attention(vec![AttentionItem {
                resource_id: "stdin".into(),
                message: "Total extracted text limit reached; remaining input was not checked."
                    .into(),
            }]);
        }
        let deadline = Instant::now().checked_add(self.options.file_timeout);
        let mut dedup = HashSet::new();
        let mut pending = Vec::new();
        self.detect_part(&part, None, deadline, &shared, &mut dedup, &mut pending);
        shared.publish_findings(take_batch(&mut pending, usize::MAX));
        shared.completed.store(1, Ordering::Relaxed);
        shared.progress();

        shared.finish(started)
    }

    fn process_root(&self, path: &Path, resource_id: &str, shared: &Shared<'_>) {
        let mut dedup = HashSet::new();
        let mut pending = Vec::new();
        let filename_text = if resource_id.contains('_') {
            resource_id.replace('_', " ")
        } else {
            resource_id.to_owned()
        };
        let representation = if filename_text == resource_id {
            "filename"
        } else {
            "synthesized-filename"
        };
        let origin = EvidenceOrigin {
            resource_id: resource_id.to_owned(),
            stream_id: "filename".into(),
            kind: EvidenceKind::Filename,
            representation: representation.into(),
            chunk_start: 0,
            coordinate_unit: CoordinateUnit::Utf16CodeUnits,
            stride: 1,
        };
        self.detect_part(
            &ExtractedPart::new(filename_text, origin),
            None,
            None,
            shared,
            &mut dedup,
            &mut pending,
        );
        shared.publish_findings(take_batch(&mut pending, usize::MAX));

        let before = match std::fs::metadata(path) {
            Ok(metadata) => metadata,
            Err(error) => {
                shared.publish_attention(vec![AttentionItem {
                    resource_id: resource_id.into(),
                    message: format!("File metadata could not be read: {error}"),
                }]);
                return;
            }
        };
        if before.len() > self.options.max_file_bytes {
            shared.publish_sources(vec![SourceRecord {
                resource_id: resource_id.into(),
                size: before.len(),
                sha256: None,
            }]);
            shared.publish_attention(vec![AttentionItem {
                resource_id: resource_id.into(),
                message: format!(
                    "File exceeds the {} byte limit; only its name was checked.",
                    self.options.max_file_bytes
                ),
            }]);
            return;
        }

        let data = match read_bounded(path, self.options.max_file_bytes) {
            Ok(data) => data,
            Err(error) => {
                shared.publish_attention(vec![AttentionItem {
                    resource_id: resource_id.into(),
                    message: format!("File could not be read completely: {error}"),
                }]);
                return;
            }
        };
        let digest = sha256_hex(&data);
        shared.publish_sources(vec![SourceRecord {
            resource_id: resource_id.into(),
            size: data.len() as u64,
            sha256: Some(digest),
        }]);

        let context = ExtractionContext::for_root(self.options.clone(), shared.cancelled.clone());
        let extraction = self.extractor.extract(resource_id, &data, &context);
        if extraction.partial && extraction.attention.is_empty() {
            shared.publish_attention(vec![AttentionItem {
                resource_id: resource_id.into(),
                message: "The extractor returned only a partial representation; content was not fully checked.".into(),
            }]);
        }
        shared.publish_attention(extraction.attention);
        for part in extraction.parts {
            if shared.cancelled.load(Ordering::Relaxed) {
                break;
            }
            self.detect_part(
                &part,
                part.location.as_deref(),
                context.deadline(),
                shared,
                &mut dedup,
                &mut pending,
            );
            if pending.len() >= 256 {
                shared.publish_findings(take_batch(&mut pending, 256));
            }
        }
        shared.publish_findings(take_batch(&mut pending, usize::MAX));
        if context.is_cancelled() && !shared.cancelled.load(Ordering::Relaxed) {
            shared.publish_attention(vec![AttentionItem {
                resource_id: resource_id.into(),
                message: "The per-file time limit was reached; content was not fully checked."
                    .into(),
            }]);
        }

        match std::fs::metadata(path) {
            Ok(after)
                if after.len() != before.len()
                    || after.modified().ok() != before.modified().ok() =>
            {
                shared.publish_attention(vec![AttentionItem {
                    resource_id: resource_id.into(),
                    message: "Source changed while it was being scanned; the hash identifies the bytes read, not a stable snapshot.".into(),
                }]);
            }
            Err(_) => shared.publish_attention(vec![AttentionItem {
                resource_id: resource_id.into(),
                message: "Source metadata could not be verified after scanning.".into(),
            }]),
            _ => {}
        }
    }

    fn detect_part(
        &self,
        part: &ExtractedPart,
        location: Option<&str>,
        file_deadline: Option<Instant>,
        shared: &Shared<'_>,
        dedup: &mut HashSet<(String, String, EntityType, u64, u64)>,
        pending: &mut Vec<Finding>,
    ) {
        if part.text.is_empty() {
            return;
        }
        if part.origin.coordinate_unit == CoordinateUnit::Bytes {
            self.detect_chunk(
                part,
                &part.text,
                part.origin.chunk_start,
                0,
                location,
                file_deadline,
                shared,
                dedup,
                pending,
            );
            return;
        }

        let index = Utf16Index::new(&part.text);
        for chunk in index.chunks(DEFAULT_CHUNK_UTF16, DEFAULT_CHUNK_OVERLAP_UTF16) {
            if shared.cancelled.load(Ordering::Relaxed)
                || file_deadline.is_some_and(|deadline| Instant::now() >= deadline)
            {
                break;
            }
            let chunk_start = part.origin.chunk_start.saturating_add(
                (chunk.utf16_start as u64).saturating_mul(u64::from(part.origin.stride)),
            );
            self.detect_chunk(
                part,
                chunk.text,
                chunk_start,
                chunk.byte_start,
                location,
                file_deadline,
                shared,
                dedup,
                pending,
            );
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn detect_chunk(
        &self,
        part: &ExtractedPart,
        text: &str,
        chunk_start: u64,
        chunk_byte_start: usize,
        location: Option<&str>,
        file_deadline: Option<Instant>,
        shared: &Shared<'_>,
        dedup: &mut HashSet<(String, String, EntityType, u64, u64)>,
        pending: &mut Vec<Finding>,
    ) {
        if file_deadline.is_some_and(|deadline| Instant::now() >= deadline) {
            return;
        }
        let boundaries = (
            part.continues_before || chunk_byte_start > 0,
            part.continues_after || chunk_byte_start.saturating_add(text.len()) < part.text.len(),
        );
        let pattern_spans = self.patterns.detect(text);
        self.publish_spans(
            pattern_spans,
            part,
            text,
            chunk_start,
            boundaries,
            file_deadline,
            shared,
            dedup,
            pending,
        );
        if shared.cancelled.load(Ordering::Relaxed)
            || file_deadline.is_some_and(|deadline| Instant::now() >= deadline)
        {
            return;
        }
        if !self.custom.is_empty() {
            let custom_spans = self.custom.detect(text);
            self.publish_spans(
                custom_spans,
                part,
                text,
                chunk_start,
                boundaries,
                file_deadline,
                shared,
                dedup,
                pending,
            );
        }
        if shared.cancelled.load(Ordering::Relaxed)
            || file_deadline.is_some_and(|deadline| Instant::now() >= deadline)
            || !self.options.detect_names
        {
            return;
        }
        if !self.names_plausible(part, location) {
            return;
        }
        if let Some(names) = &self.names {
            match names.detect(
                text,
                location.unwrap_or(""),
                &self.options.phone_regions,
                shared.cancelled,
            ) {
                Ok(spans) => self.publish_spans(
                    spans,
                    part,
                    text,
                    chunk_start,
                    boundaries,
                    file_deadline,
                    shared,
                    dedup,
                    pending,
                ),
                Err(error) => shared.publish_attention(vec![AttentionItem {
                    resource_id: part.origin.resource_id.clone(),
                    message: format!("Name inference was incomplete: {error}"),
                }]),
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn publish_spans(
        &self,
        spans: Vec<EntitySpan>,
        part: &ExtractedPart,
        text: &str,
        chunk_start: u64,
        boundaries: (bool, bool),
        file_deadline: Option<Instant>,
        shared: &Shared<'_>,
        dedup: &mut HashSet<(String, String, EntityType, u64, u64)>,
        pending: &mut Vec<Finding>,
    ) {
        let index = Utf16Index::new(text);
        for span in spans {
            if shared.cancelled.load(Ordering::Relaxed)
                || file_deadline.is_some_and(|deadline| Instant::now() >= deadline)
            {
                break;
            }
            let Some(end_byte) = span.start.checked_add(span.length) else {
                continue;
            };
            if end_byte > text.len()
                || !text.is_char_boundary(span.start)
                || !text.is_char_boundary(end_byte)
            {
                continue;
            }
            // Neighboring overlapping chunks contain the full occurrence. Accepting a
            // match clipped against an artificial edge creates false prefixes/suffixes.
            if (boundaries.0 && span.start == 0) || (boundaries.1 && end_byte == text.len()) {
                continue;
            }
            let Some(local_start) = index.utf16_offset(span.start) else {
                continue;
            };
            let Some(local_end) = index.utf16_offset(end_byte) else {
                continue;
            };
            let local_length = local_end - local_start;
            let stride = u64::from(part.origin.stride);
            let start = chunk_start.saturating_add((local_start as u64).saturating_mul(stride));
            let length = (local_length as u64).saturating_mul(stride);
            let key = (
                part.origin.resource_id.clone(),
                part.origin.stream_id.clone(),
                span.entity_type,
                start,
                length,
            );
            if !dedup.insert(key) {
                continue;
            }

            let mut origin = part.origin.clone();
            origin.chunk_start = chunk_start;
            let (local_context_start, context) = if self.options.include_context {
                index
                    .context(local_start, local_length, 80, 100)
                    .unwrap_or((0, ""))
            } else {
                (0, "")
            };
            let context_start =
                chunk_start.saturating_add((local_context_start as u64).saturating_mul(stride));
            let finding = Finding {
                entity_type: span.entity_type,
                value: text[span.start..end_byte].trim().to_owned(),
                start,
                length,
                context: context.to_owned(),
                context_start,
                detector_start: local_start as u64,
                detector_length: local_length as u64,
                confidence: span.confidence,
                method: span.method,
                origin,
            };
            pending.push(finding);
            if pending.len() >= 256 {
                shared.publish_findings(take_batch(pending, 256));
            }
        }
    }

    fn names_plausible(&self, part: &ExtractedPart, location: Option<&str>) -> bool {
        match part.origin.kind {
            EvidenceKind::Metadata => {
                let text = location.unwrap_or("").to_ascii_lowercase();
                ["author", "creator", "owner", "person", "name", "contact"]
                    .iter()
                    .any(|needle| text.contains(needle))
            }
            EvidenceKind::Body
            | EvidenceKind::Filename
            | EvidenceKind::ArchiveMemberName
            | EvidenceKind::Ocr => true,
            EvidenceKind::BinaryStrings => false,
        }
    }
}

struct Shared<'a> {
    result: Mutex<ScanResult>,
    callback: &'a (dyn Fn(ScanEvent) + Send + Sync),
    cancelled: &'a Arc<AtomicBool>,
    options: &'a Arc<ScanOptions>,
    discovered: AtomicU64,
    completed: AtomicU64,
    limit: Mutex<Option<String>>,
    findings: AtomicUsize,
    attention: AtomicUsize,
    retain_results: bool,
}

impl Shared<'_> {
    fn publish_findings(&self, findings: Vec<Finding>) {
        if findings.is_empty() {
            return;
        }
        let offered = findings.len();
        let mut batch = Vec::new();
        let reached;
        {
            let mut result = lock(&self.result);
            let available = self
                .options
                .max_findings
                .saturating_sub(self.findings.load(Ordering::Relaxed));
            batch.extend(findings.into_iter().take(available));
            reached = offered > available
                || self.findings.load(Ordering::Relaxed) + batch.len() >= self.options.max_findings;
            self.findings.fetch_add(batch.len(), Ordering::Relaxed);
            if self.retain_results {
                result.findings.extend(batch.clone());
            }
        }
        if reached {
            self.set_limit("finding limit");
        }
        if !batch.is_empty() {
            (self.callback)(ScanEvent::Findings(batch));
        }
        self.progress();
    }

    fn publish_attention(&self, attention: Vec<AttentionItem>) {
        if attention.is_empty() {
            return;
        }
        let offered = attention.len();
        let mut batch = Vec::new();
        let reached;
        {
            let mut result = lock(&self.result);
            let available = self
                .options
                .max_attention
                .saturating_sub(self.attention.load(Ordering::Relaxed));
            batch.extend(attention.into_iter().take(available));
            reached = offered > available
                || self.attention.load(Ordering::Relaxed) + batch.len()
                    >= self.options.max_attention;
            self.attention.fetch_add(batch.len(), Ordering::Relaxed);
            if self.retain_results {
                result.attention.extend(batch.clone());
            }
        }
        if reached {
            self.set_limit("attention limit");
        }
        if !batch.is_empty() {
            (self.callback)(ScanEvent::Attention(batch));
        }
        self.progress();
    }

    fn set_limit(&self, name: &str) {
        let mut limit = lock(&self.limit);
        if limit.is_none() {
            *limit = Some(name.to_owned());
        }
        drop(limit);
        self.cancelled.store(true, Ordering::Relaxed);
    }

    fn publish_sources(&self, sources: Vec<SourceRecord>) {
        if self.retain_results {
            lock(&self.result).sources.extend(sources.clone());
        }
        if !sources.is_empty() {
            (self.callback)(ScanEvent::Sources(sources));
        }
    }

    fn progress(&self) {
        let progress = ScanProgress {
            discovered: self.discovered.load(Ordering::Relaxed),
            completed: self.completed.load(Ordering::Relaxed),
            findings: self.findings.load(Ordering::Relaxed),
            attention: self.attention.load(Ordering::Relaxed),
        };
        (self.callback)(ScanEvent::Progress(progress));
    }

    fn finish(self, started: Instant) -> ScanResult {
        let mut result = into_inner(self.result);
        result.summary = ScanSummary {
            discovered: self.discovered.load(Ordering::Relaxed),
            completed: self.completed.load(Ordering::Relaxed),
            findings: self.findings.load(Ordering::Relaxed),
            attention: self.attention.load(Ordering::Relaxed),
            cancelled: self.cancelled.load(Ordering::Relaxed),
            limit_reached: into_inner(self.limit),
            elapsed_ms: started.elapsed().as_millis() as u64,
        };
        result.sort_deterministically();
        result
    }
}

fn read_bounded(path: &Path, limit: u64) -> std::io::Result<Vec<u8>> {
    let file = File::open(path)?;
    let mut data = Vec::with_capacity((limit.min(8 * 1024 * 1024) as usize).min(1024 * 1024));
    file.take(limit.saturating_add(1)).read_to_end(&mut data)?;
    if data.len() as u64 > limit {
        return Err(std::io::Error::new(
            std::io::ErrorKind::FileTooLarge,
            "file grew beyond the configured byte limit while reading",
        ));
    }
    Ok(data)
}

fn logical_relative(base: &Path, path: &Path) -> String {
    path.strip_prefix(base)
        .unwrap_or_else(|_| path.file_name().map(Path::new).unwrap_or(path))
        .to_string_lossy()
        .replace('\\', "/")
}

fn default_asset(relative: &str) -> Option<PathBuf> {
    let mut candidates = Vec::new();
    if let Ok(executable) = std::env::current_exe()
        && let Some(parent) = executable.parent()
    {
        candidates.push(parent.join("assets").join(relative));
        candidates.push(parent.join("..").join("assets").join(relative));
    }
    candidates.push(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../assets")
            .join(relative),
    );
    candidates.into_iter().find(|path| path.is_file())
}

fn system_tesseract() -> Option<PathBuf> {
    let executable = if cfg!(windows) {
        "tesseract.exe"
    } else {
        "tesseract"
    };
    #[allow(unused_mut)] // Extra installation paths are platform-specific.
    let mut directories: Vec<PathBuf> = std::env::var_os("PATH")
        .map(|path| std::env::split_paths(&path).collect())
        .unwrap_or_default();
    // Finder-launched apps do not normally inherit a terminal's Homebrew PATH.
    #[cfg(target_os = "macos")]
    directories.extend([
        PathBuf::from("/opt/homebrew/bin"),
        PathBuf::from("/usr/local/bin"),
    ]);
    #[cfg(windows)]
    if let Some(program_files) = std::env::var_os("ProgramFiles") {
        directories.push(PathBuf::from(program_files).join("Tesseract-OCR"));
    }
    directories
        .into_iter()
        .map(|directory| directory.join(executable))
        .find(|path| path.is_file())
}

fn take_batch<T>(values: &mut Vec<T>, maximum: usize) -> Vec<T> {
    let count = maximum.min(values.len());
    values.drain(..count).collect()
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn into_inner<T>(mutex: Mutex<T>) -> T {
    mutex
        .into_inner()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}
