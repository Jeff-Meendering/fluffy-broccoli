//! Bounded, exact-span evaluation of text detectors.
//!
//! The input callback uses the detector crate's UTF-8 byte spans. Public gold labels and all
//! reported matches use UTF-16 code-unit offsets. Neither source text nor input paths are included
//! in reports or validation errors.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs::File;
use std::io::{self, BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use serde::ser::SerializeStruct;
use serde::{Deserialize, Serialize, Serializer};
use sha2::{Digest, Sha256};

use crate::detectors::EntitySpan;
use crate::{ENGINE_VERSION, EntityType, Utf16Index};

pub const MAX_TEXT_UTF16: usize = 100_000;
pub const MAX_ANNOTATIONS: usize = 10_000;
pub const MAX_RECORD_UTF16: usize = 512_000;
// A valid UTF-8 record cannot exceed three bytes per UTF-16 code unit. This hard byte ceiling
// prevents an unterminated line from growing without bound before its UTF-16 length is checked.
const MAX_RECORD_BYTES: usize = MAX_RECORD_UTF16 * 3;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ExpectedEntity {
    #[serde(rename = "type", alias = "Type")]
    pub entity_type: EntityType,
    #[serde(alias = "Start")]
    pub start: i64,
    #[serde(alias = "Length")]
    pub length: i64,
}

impl ExpectedEntity {
    #[must_use]
    pub const fn new(entity_type: EntityType, start: i64, length: i64) -> Self {
        Self {
            entity_type,
            start,
            length,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvaluationCase {
    #[serde(alias = "Text")]
    pub text: String,
    #[serde(alias = "Entities")]
    pub entities: Vec<ExpectedEntity>,
}

impl EvaluationCase {
    #[must_use]
    pub fn new(text: impl Into<String>, entities: Vec<ExpectedEntity>) -> Self {
        Self {
            text: text.into(),
            entities,
        }
    }
}

#[derive(Debug, Clone)]
pub struct EvaluationOptions {
    /// Records whether model-backed name detection was enabled. The supplied detector controls
    /// prediction coverage; labelled-name rules can still emit Person when inference is off.
    pub names_enabled: bool,
    /// Optional local model bytes to fingerprint. Paths are never copied into the report.
    pub model_path: Option<PathBuf>,
    /// Optional local tokenizer/vocabulary bytes to fingerprint.
    pub vocab_path: Option<PathBuf>,
    /// Canonical bytes describing the effective detector configuration. Only their SHA-256 is
    /// reported. When omitted, the name setting itself is fingerprinted.
    pub config: Option<Vec<u8>>,
}

impl Default for EvaluationOptions {
    fn default() -> Self {
        Self {
            names_enabled: true,
            model_path: None,
            vocab_path: None,
            config: None,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AccuracyCounts {
    pub true_positive: u64,
    pub false_positive: u64,
    pub false_negative: u64,
}

impl AccuracyCounts {
    #[must_use]
    pub const fn new(true_positive: u64, false_positive: u64, false_negative: u64) -> Self {
        Self {
            true_positive,
            false_positive,
            false_negative,
        }
    }

    #[must_use]
    pub const fn gold_entities(self) -> u64 {
        self.true_positive + self.false_negative
    }

    #[must_use]
    pub fn false_negative_proportion(self) -> Option<f64> {
        let gold = self.gold_entities();
        (gold != 0).then(|| self.false_negative as f64 / gold as f64)
    }

    #[must_use]
    pub fn precision(self) -> Option<f64> {
        let predicted = self.true_positive + self.false_positive;
        (predicted != 0).then(|| self.true_positive as f64 / predicted as f64)
    }

    #[must_use]
    pub fn recall(self) -> Option<f64> {
        let gold = self.gold_entities();
        (gold != 0).then(|| self.true_positive as f64 / gold as f64)
    }

    #[must_use]
    pub fn f1(self) -> Option<f64> {
        let denominator = 2 * self.true_positive + self.false_positive + self.false_negative;
        (denominator != 0).then(|| 2.0 * self.true_positive as f64 / denominator as f64)
    }

    fn add(&mut self, other: Self) {
        self.true_positive += other.true_positive;
        self.false_positive += other.false_positive;
        self.false_negative += other.false_negative;
    }
}

impl Serialize for AccuracyCounts {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("AccuracyCounts", 8)?;
        state.serialize_field("true_positive", &self.true_positive)?;
        state.serialize_field("false_positive", &self.false_positive)?;
        state.serialize_field("false_negative", &self.false_negative)?;
        state.serialize_field("gold_entities", &self.gold_entities())?;
        state.serialize_field(
            "false_negative_proportion",
            &self.false_negative_proportion(),
        )?;
        state.serialize_field("precision", &self.precision())?;
        state.serialize_field("recall", &self.recall())?;
        state.serialize_field("f1", &self.f1())?;
        state.end()
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct AccuracyReport {
    pub schema_version: u32,
    pub corpus_sha256: String,
    pub model_sha256: Option<String>,
    pub vocab_sha256: Option<String>,
    pub config_sha256: String,
    pub names_enabled: bool,
    pub cases: u64,
    /// Total input size in UTF-16 code units, not bytes or Unicode scalar values.
    pub characters: u64,
    pub seconds: f64,
    pub micro: AccuracyCounts,
    pub by_type: BTreeMap<String, AccuracyCounts>,
    pub clean_documents: u64,
    pub false_positives_on_clean_documents: u64,
    pub false_positives_per_clean_document: Option<f64>,
    pub engine_version: String,
    pub matching: String,
    pub interpretation: String,
}

impl AccuracyReport {
    #[must_use]
    pub fn false_positives_per_clean_document(&self) -> Option<f64> {
        self.false_positives_per_clean_document
    }

    /// Writes pretty JSON through a same-directory temporary file and an atomic no-clobber link.
    pub fn save(&self, destination: impl AsRef<Path>) -> io::Result<()> {
        AccuracyEvaluation::save(destination, self)
    }
}

#[derive(Debug)]
pub enum EvaluationError {
    Io {
        operation: &'static str,
        source: io::Error,
    },
    InvalidJson {
        line: u64,
    },
    InvalidCase {
        line: u64,
    },
    InvalidEntity {
        line: u64,
    },
    DuplicateGold {
        line: u64,
    },
    OversizedRecord {
        line: u64,
    },
    InvalidPrediction {
        line: u64,
    },
    EmptyCorpus,
}

impl fmt::Display for EvaluationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { operation, source } => write!(formatter, "{operation}: {source}"),
            Self::InvalidJson { line } => write!(
                formatter,
                "Invalid evaluation JSON at line {line}. No source text was logged."
            ),
            Self::InvalidCase { line } => {
                write!(
                    formatter,
                    "Invalid or oversized evaluation case at line {line}."
                )
            }
            Self::InvalidEntity { line } => {
                write!(
                    formatter,
                    "Invalid entity label or UTF-16 span at line {line}."
                )
            }
            Self::DuplicateGold { line } => {
                write!(formatter, "Duplicate gold entity at line {line}.")
            }
            Self::OversizedRecord { line } => write!(
                formatter,
                "Evaluation record at line {line} exceeds 512,000 UTF-16 code units."
            ),
            Self::InvalidPrediction { line } => {
                write!(
                    formatter,
                    "Detector returned an invalid byte span at line {line}."
                )
            }
            Self::EmptyCorpus => formatter.write_str("Evaluation corpus contains no cases."),
        }
    }
}

impl std::error::Error for EvaluationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

pub struct AccuracyEvaluation;

impl AccuracyEvaluation {
    /// Evaluates one JSON object per line. Blank lines are ignored. The callback is invoked once
    /// per nonblank record and returns detector spans as UTF-8 byte offsets into that exact text.
    pub fn run<P, F>(
        corpus: P,
        options: EvaluationOptions,
        mut detect: F,
    ) -> Result<AccuracyReport, EvaluationError>
    where
        P: AsRef<Path>,
        F: FnMut(&str) -> Vec<EntitySpan>,
    {
        let mut input = File::open(corpus.as_ref()).map_err(|source| EvaluationError::Io {
            operation: "Could not open the evaluation corpus",
            source,
        })?;
        let corpus_sha256 = hash_reader(&mut input).map_err(|source| EvaluationError::Io {
            operation: "Could not hash the evaluation corpus",
            source,
        })?;
        input
            .seek(SeekFrom::Start(0))
            .map_err(|source| EvaluationError::Io {
                operation: "Could not rewind the evaluation corpus",
                source,
            })?;
        let model_sha256 = options
            .model_path
            .as_deref()
            .map(|path| hash_named_file(path, "Could not read the model fingerprint input"))
            .transpose()?;
        let vocab_sha256 = options
            .vocab_path
            .as_deref()
            .map(|path| hash_named_file(path, "Could not read the vocabulary fingerprint input"))
            .transpose()?;
        let default_config;
        let config = match options.config.as_deref() {
            Some(config) => config,
            None => {
                default_config = if options.names_enabled {
                    b"names_enabled=true".as_slice()
                } else {
                    b"names_enabled=false".as_slice()
                };
                default_config
            }
        };
        let config_sha256 = hex_bytes(&Sha256::digest(config));

        let started = Instant::now();
        let mut reader = BufReader::new(input);
        let mut line = 0_u64;
        let mut cases = 0_u64;
        let mut characters = 0_u64;
        let mut clean_documents = 0_u64;
        let mut clean_false_positives = 0_u64;
        let mut totals: BTreeMap<EntityType, AccuracyCounts> = BTreeMap::new();

        while let Some(record) = read_record(&mut reader, line + 1)? {
            line += 1;
            let record =
                std::str::from_utf8(&record).map_err(|_| EvaluationError::InvalidJson { line })?;
            let record = if line == 1 {
                record.strip_prefix('\u{feff}').unwrap_or(record)
            } else {
                record
            };
            if record.encode_utf16().count() > MAX_RECORD_UTF16 {
                return Err(EvaluationError::OversizedRecord { line });
            }
            if record.trim().is_empty() {
                continue;
            }
            let item: EvaluationCase =
                serde_json::from_str(record).map_err(|_| EvaluationError::InvalidJson { line })?;
            let text_units = item.text.encode_utf16().count();
            if text_units > MAX_TEXT_UTF16 || item.entities.len() > MAX_ANNOTATIONS {
                return Err(EvaluationError::InvalidCase { line });
            }
            for entity in &item.entities {
                if entity.start < 0
                    || entity.length <= 0
                    || entity.start > text_units as i64
                    || entity.length > text_units as i64 - entity.start
                {
                    return Err(EvaluationError::InvalidEntity { line });
                }
            }
            let expected: BTreeSet<ExpectedEntity> = item.entities.iter().cloned().collect();
            if expected.len() != item.entities.len() {
                return Err(EvaluationError::DuplicateGold { line });
            }

            let index = Utf16Index::new(&item.text);
            let mut predicted = BTreeSet::new();
            for span in detect(&item.text) {
                let Some(end) = span.start.checked_add(span.length) else {
                    return Err(EvaluationError::InvalidPrediction { line });
                };
                if span.length == 0
                    || end > item.text.len()
                    || !item.text.is_char_boundary(span.start)
                    || !item.text.is_char_boundary(end)
                {
                    return Err(EvaluationError::InvalidPrediction { line });
                }
                let Some(start) = index.utf16_offset(span.start) else {
                    return Err(EvaluationError::InvalidPrediction { line });
                };
                let Some(end) = index.utf16_offset(end) else {
                    return Err(EvaluationError::InvalidPrediction { line });
                };
                predicted.insert(ExpectedEntity::new(
                    span.entity_type,
                    start as i64,
                    (end - start) as i64,
                ));
            }

            if expected.is_empty() {
                clean_documents += 1;
                clean_false_positives += predicted.len() as u64;
            }
            accumulate_case(&expected, &predicted, &mut totals);
            cases += 1;
            characters += text_units as u64;
        }
        if cases == 0 {
            return Err(EvaluationError::EmptyCorpus);
        }

        let micro =
            totals
                .values()
                .copied()
                .fold(AccuracyCounts::default(), |mut total, counts| {
                    total.add(counts);
                    total
                });
        let by_type = totals
            .into_iter()
            .map(|(kind, counts)| (kind.as_str().to_owned(), counts))
            .collect();
        Ok(AccuracyReport {
            schema_version: 2,
            corpus_sha256,
            model_sha256,
            vocab_sha256,
            config_sha256,
            names_enabled: options.names_enabled,
            cases,
            characters,
            seconds: started.elapsed().as_secs_f64(),
            micro,
            by_type,
            clean_documents,
            false_positives_on_clean_documents: clean_false_positives,
            false_positives_per_clean_document: (clean_documents != 0)
                .then(|| clean_false_positives as f64 / clean_documents as f64),
            engine_version: ENGINE_VERSION.to_owned(),
            matching: "Exact type and UTF-16 start/length; duplicate predictions counted once. Text detector evaluation only; excludes file extraction and OCR.".to_owned(),
            interpretation: "Scores describe this labelled corpus only. Negative controls and representative independent labels are required. Model scores are not calibrated probabilities.".to_owned(),
        })
    }

    /// Saves JSON atomically without replacing an existing file, symlink, or other directory entry.
    pub fn save(destination: impl AsRef<Path>, report: &AccuracyReport) -> io::Result<()> {
        save_non_overwriting(destination.as_ref(), ".pii-evaluation-", |file| {
            serde_json::to_writer_pretty(&mut *file, report).map_err(io::Error::other)?;
            file.write_all(b"\n")
        })
    }
}

/// Convenience entry point using the default evaluation provenance options.
pub fn evaluate_jsonl<P, F>(corpus: P, detect: F) -> Result<AccuracyReport, EvaluationError>
where
    P: AsRef<Path>,
    F: FnMut(&str) -> Vec<EntitySpan>,
{
    AccuracyEvaluation::run(corpus, EvaluationOptions::default(), detect)
}

pub fn evaluate_jsonl_with_options<P, F>(
    corpus: P,
    options: EvaluationOptions,
    detect: F,
) -> Result<AccuracyReport, EvaluationError>
where
    P: AsRef<Path>,
    F: FnMut(&str) -> Vec<EntitySpan>,
{
    AccuracyEvaluation::run(corpus, options, detect)
}

pub fn save_evaluation_json(
    destination: impl AsRef<Path>,
    report: &AccuracyReport,
) -> io::Result<()> {
    AccuracyEvaluation::save(destination, report)
}

fn accumulate_case(
    expected: &BTreeSet<ExpectedEntity>,
    predicted: &BTreeSet<ExpectedEntity>,
    totals: &mut BTreeMap<EntityType, AccuracyCounts>,
) {
    let mut expected_by_type: BTreeMap<EntityType, BTreeSet<(i64, i64)>> = BTreeMap::new();
    let mut predicted_by_type: BTreeMap<EntityType, BTreeSet<(i64, i64)>> = BTreeMap::new();
    for entity in expected {
        expected_by_type
            .entry(entity.entity_type)
            .or_default()
            .insert((entity.start, entity.length));
    }
    for entity in predicted {
        predicted_by_type
            .entry(entity.entity_type)
            .or_default()
            .insert((entity.start, entity.length));
    }

    let kinds: BTreeSet<EntityType> = expected_by_type
        .keys()
        .chain(predicted_by_type.keys())
        .copied()
        .collect();
    for kind in kinds {
        let empty = BTreeSet::new();
        let gold = expected_by_type.get(&kind).unwrap_or(&empty);
        let found = predicted_by_type.get(&kind).unwrap_or(&empty);
        let true_positive = found.intersection(gold).count() as u64;
        let counts = AccuracyCounts::new(
            true_positive,
            found.len() as u64 - true_positive,
            gold.len() as u64 - true_positive,
        );
        totals.entry(kind).or_default().add(counts);
    }
}

fn read_record<R: BufRead>(reader: &mut R, line: u64) -> Result<Option<Vec<u8>>, EvaluationError> {
    let mut record = Vec::new();
    loop {
        let available = reader.fill_buf().map_err(|source| EvaluationError::Io {
            operation: "Could not read the evaluation corpus",
            source,
        })?;
        if available.is_empty() {
            if record.is_empty() {
                return Ok(None);
            }
            while record.last() == Some(&b'\r') {
                record.pop();
            }
            return Ok(Some(record));
        }
        let newline = available.iter().position(|byte| *byte == b'\n');
        let content_bytes = newline.unwrap_or(available.len());
        if record.len().saturating_add(content_bytes) > MAX_RECORD_BYTES {
            return Err(EvaluationError::OversizedRecord { line });
        }
        if let Some(position) = newline {
            record.extend_from_slice(&available[..position]);
            reader.consume(position + 1);
            while record.last() == Some(&b'\r') {
                record.pop();
            }
            return Ok(Some(record));
        }
        record.extend_from_slice(available);
        reader.consume(content_bytes);
    }
}

fn hash_named_file(path: &Path, operation: &'static str) -> Result<String, EvaluationError> {
    let mut file = File::open(path).map_err(|source| EvaluationError::Io { operation, source })?;
    hash_reader(&mut file).map_err(|source| EvaluationError::Io { operation, source })
}

fn hash_reader(reader: &mut impl Read) -> io::Result<String> {
    let mut hash = Sha256::new();
    let mut buffer = [0_u8; 65_536];
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hash.update(&buffer[..read]);
    }
    buffer.fill(0);
    Ok(hex_bytes(&hash.finalize()))
}

fn hex_bytes(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
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
                "That filename already exists. Choose a new filename; existing files are never overwritten.",
            ))
        }
        Err(error) => {
            #[cfg(windows)]
            {
                // Windows rename is non-overwriting. POSIX rename is deliberately not a fallback:
                // it would replace an existing destination and violate the export contract.
                match std::fs::rename(&staging.0, &target) {
                    Ok(()) => Ok(()),
                    Err(_) if std::fs::symlink_metadata(&target).is_ok() => Err(io::Error::new(
                        io::ErrorKind::AlreadyExists,
                        "That filename already exists; existing files are never overwritten.",
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

#[cfg(test)]
mod tests {
    use super::*;

    fn entity(kind: EntityType, start: i64, length: i64) -> ExpectedEntity {
        ExpectedEntity::new(kind, start, length)
    }

    fn write_corpus(directory: &Path, cases: &[EvaluationCase]) -> PathBuf {
        let path = directory.join("labelled.jsonl");
        let mut output = String::new();
        for case in cases {
            output.push_str(&serde_json::to_string(case).expect("serialize test case"));
            output.push('\n');
        }
        std::fs::write(&path, output).expect("write test corpus");
        path
    }

    #[test]
    fn exact_spans_deduplicate_predictions_and_compute_metrics() {
        let temp = tempfile::tempdir().expect("tempdir");
        let path = write_corpus(
            temp.path(),
            &[
                EvaluationCase::new(
                    "a@example.com b@example.com",
                    vec![entity(EntityType::Email, 0, 13)],
                ),
                EvaluationCase::new("nothing", vec![entity(EntityType::Person, 0, 7)]),
                EvaluationCase::new("c@example.com", vec![entity(EntityType::Email, 0, 12)]),
            ],
        );
        let report = AccuracyEvaluation::run(&path, EvaluationOptions::default(), |text| {
            let mut spans = Vec::new();
            for (index, _) in text.match_indices("@example.com") {
                let start = index - 1;
                spans.push(EntitySpan::new(EntityType::Email, start, 13, 1.0, "test"));
                spans.push(spans[0].clone());
            }
            spans
        })
        .expect("evaluation");

        assert_eq!(report.cases, 3);
        assert_eq!(report.micro, AccuracyCounts::new(1, 2, 2));
        assert_eq!(report.by_type["Email"], AccuracyCounts::new(1, 2, 1));
        assert_eq!(report.micro.precision(), Some(1.0 / 3.0));
        assert_eq!(report.micro.recall(), Some(1.0 / 3.0));
        assert_eq!(report.micro.f1(), Some(1.0 / 3.0));
        assert_eq!(report.by_type["Person"].precision(), None);
        assert_eq!(report.corpus_sha256.len(), 64);
        assert_eq!(report.config_sha256.len(), 64);
        let json = serde_json::to_string(&report).expect("serialize report");
        assert!(!json.contains("example.com"));
        assert!(!json.contains(path.to_str().expect("UTF-8 temp path")));
        assert!(json.contains("\"precision\":null"));
    }

    #[test]
    fn negative_controls_have_undefined_metrics_and_clean_fp_rate() {
        let temp = tempfile::tempdir().expect("tempdir");
        let path = write_corpus(temp.path(), &[EvaluationCase::new("nothing", Vec::new())]);
        let report = evaluate_jsonl(path, |_| Vec::new()).expect("evaluation");
        assert_eq!(report.micro.precision(), None);
        assert_eq!(report.micro.recall(), None);
        assert_eq!(report.micro.f1(), None);
        assert_eq!(report.micro.false_negative_proportion(), None);
        assert_eq!(report.clean_documents, 1);
        assert_eq!(report.false_positives_per_clean_document, Some(0.0));
    }

    #[test]
    fn clean_document_false_positives_and_miss_rate_are_independent() {
        let temp = tempfile::tempdir().expect("tempdir");
        let path = write_corpus(
            temp.path(),
            &[
                EvaluationCase::new("a@example.com b@example.com", Vec::new()),
                EvaluationCase::new("Tom", vec![entity(EntityType::Person, 0, 3)]),
            ],
        );
        let report = AccuracyEvaluation::run(&path, EvaluationOptions::default(), |text| {
            text.match_indices("@example.com")
                .map(|(index, _)| EntitySpan::new(EntityType::Email, index - 1, 13, 1.0, "test"))
                .collect()
        })
        .expect("evaluation");
        assert_eq!(report.micro.false_negative_proportion(), Some(1.0));
        assert_eq!(report.clean_documents, 1);
        assert_eq!(report.false_positives_on_clean_documents, 2);
        assert_eq!(report.false_positives_per_clean_document, Some(2.0));
    }

    #[test]
    fn detector_byte_spans_are_scored_as_utf16() {
        let temp = tempfile::tempdir().expect("tempdir");
        let text = "😀 a@example.com";
        let path = write_corpus(
            temp.path(),
            &[EvaluationCase::new(
                text,
                vec![entity(EntityType::Email, 3, 13)],
            )],
        );
        let report = evaluate_jsonl(path, |_| {
            vec![EntitySpan::new(
                EntityType::Email,
                "😀 ".len(),
                13,
                1.0,
                "test",
            )]
        })
        .expect("evaluation");
        assert_eq!(report.micro, AccuracyCounts::new(1, 0, 0));
        assert_eq!(report.characters, text.encode_utf16().count() as u64);
    }

    #[test]
    fn model_setting_does_not_hide_labelled_name_predictions() {
        let directory = tempfile::tempdir().expect("directory");
        let corpus = write_corpus(
            directory.path(),
            &[EvaluationCase::new(
                "Tom",
                vec![entity(EntityType::Person, 0, 3)],
            )],
        );
        let report = evaluate_jsonl_with_options(
            corpus,
            EvaluationOptions {
                names_enabled: false,
                ..EvaluationOptions::default()
            },
            |_| {
                vec![EntitySpan::new(
                    EntityType::Person,
                    0,
                    3,
                    0.9,
                    "labelled name",
                )]
            },
        )
        .expect("evaluation");
        assert!(!report.names_enabled);
        assert_eq!(report.micro, AccuracyCounts::new(1, 0, 0));
    }

    #[test]
    fn invalid_gold_duplicates_predictions_and_limits_are_rejected_without_echo() {
        let temp = tempfile::tempdir().expect("tempdir");
        let path = temp.path().join("bad.jsonl");
        for (start, length) in [(-1, 1), (0, 0), (0, i64::MAX), (i64::MAX, 1)] {
            let case = EvaluationCase::new(
                "secret@example.com",
                vec![entity(EntityType::Email, start, length)],
            );
            std::fs::write(&path, serde_json::to_string(&case).expect("case JSON"))
                .expect("write corpus");
            let error = evaluate_jsonl(&path, |_| Vec::new()).expect_err("invalid gold");
            assert!(!error.to_string().contains("secret@example.com"));
        }

        let duplicate = EvaluationCase::new(
            "a@example.com",
            vec![
                entity(EntityType::Email, 0, 13),
                entity(EntityType::Email, 0, 13),
            ],
        );
        std::fs::write(&path, serde_json::to_string(&duplicate).expect("case JSON"))
            .expect("write corpus");
        assert!(matches!(
            evaluate_jsonl(&path, |_| Vec::new()),
            Err(EvaluationError::DuplicateGold { .. })
        ));

        let clean = EvaluationCase::new("a@example.com", Vec::new());
        std::fs::write(&path, serde_json::to_string(&clean).expect("case JSON"))
            .expect("write corpus");
        assert!(matches!(
            evaluate_jsonl(&path, |_| vec![EntitySpan::new(
                EntityType::Email,
                1,
                usize::MAX,
                1.0,
                "test"
            )]),
            Err(EvaluationError::InvalidPrediction { .. })
        ));

        let too_many = EvaluationCase::new(
            String::new(),
            vec![entity(EntityType::Person, 0, 1); MAX_ANNOTATIONS + 1],
        );
        std::fs::write(&path, serde_json::to_string(&too_many).expect("case JSON"))
            .expect("write corpus");
        assert!(matches!(
            evaluate_jsonl(&path, |_| Vec::new()),
            Err(EvaluationError::InvalidCase { .. })
        ));

        std::fs::write(
            &path,
            format!("{{\"text\":\"{}\",\"entities\":[]}}", "x".repeat(100_001)),
        )
        .expect("write oversized text");
        assert!(matches!(
            evaluate_jsonl(&path, |_| Vec::new()),
            Err(EvaluationError::InvalidCase { .. })
        ));

        std::fs::write(&path, "x".repeat(512_001)).expect("write oversized record");
        assert!(matches!(
            evaluate_jsonl(&path, |_| Vec::new()),
            Err(EvaluationError::OversizedRecord { .. })
        ));
        std::fs::write(&path, " ".repeat(512_001)).expect("write oversized blank record");
        assert!(matches!(
            evaluate_jsonl(&path, |_| Vec::new()),
            Err(EvaluationError::OversizedRecord { .. })
        ));
    }

    #[test]
    fn malformed_json_and_empty_corpora_do_not_echo_source_text() {
        let temp = tempfile::tempdir().expect("tempdir");
        let path = temp.path().join("bad.jsonl");
        std::fs::write(&path, "{ secret@example.com }").expect("write malformed JSON");
        let error = evaluate_jsonl(&path, |_| Vec::new()).expect_err("malformed JSON");
        assert!(!error.to_string().contains("secret@example.com"));
        std::fs::write(&path, "\n\r\n").expect("write blank corpus");
        assert!(matches!(
            evaluate_jsonl(&path, |_| Vec::new()),
            Err(EvaluationError::EmptyCorpus)
        ));
    }

    #[test]
    fn fingerprints_cover_model_vocab_and_config_without_paths() {
        let temp = tempfile::tempdir().expect("tempdir");
        let corpus = write_corpus(temp.path(), &[EvaluationCase::new("clean", Vec::new())]);
        let model = temp.path().join("private-model.onnx");
        let vocab = temp.path().join("private-vocab.txt");
        std::fs::write(&model, b"model").expect("model");
        std::fs::write(&vocab, b"vocab").expect("vocab");
        let options = EvaluationOptions {
            model_path: Some(model.clone()),
            vocab_path: Some(vocab.clone()),
            config: Some(b"threshold=0.5".to_vec()),
            ..EvaluationOptions::default()
        };
        let report = AccuracyEvaluation::run(corpus, options, |_| Vec::new()).expect("evaluation");
        assert!(report.model_sha256.is_some());
        assert!(report.vocab_sha256.is_some());
        let json = serde_json::to_string(&report).expect("report JSON");
        assert!(!json.contains("private-model"));
        assert!(!json.contains("private-vocab"));
        assert!(!json.contains("threshold"));
    }

    #[test]
    fn export_is_atomic_and_never_overwrites_or_leaves_staging_files() {
        let temp = tempfile::tempdir().expect("tempdir");
        let corpus = write_corpus(temp.path(), &[EvaluationCase::new("clean", Vec::new())]);
        let report = evaluate_jsonl(corpus, |_| Vec::new()).expect("evaluation");
        let output = temp.path().join("result.json");
        report.save(&output).expect("first save");
        let original = std::fs::read(&output).expect("read output");
        let error = report.save(&output).expect_err("existing output");
        assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(std::fs::read(&output).expect("preserved output"), original);
        let value: serde_json::Value =
            serde_json::from_slice(&original).expect("valid JSON report");
        assert_eq!(value["micro"]["precision"], serde_json::Value::Null);
        assert_eq!(value["false_positives_per_clean_document"], 0.0);
        assert_eq!(
            std::fs::read_dir(temp.path())
                .expect("list tempdir")
                .filter_map(Result::ok)
                .filter(|entry| entry.file_name().to_string_lossy().ends_with(".tmp"))
                .count(),
            0
        );
    }
}
