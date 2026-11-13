//! Local, ONNX-backed person-name detection.
//!
//! All public offsets are UTF-8 byte offsets. The model is deliberately used only for
//! person names; the other NER labels are ignored.

// The implementation-only helpers intentionally remain next to their public stub. This keeps
// feature-disabled builds quiet without maintaining a second copy of the shared text utilities.
#![cfg_attr(not(feature = "ner"), allow(dead_code))]

use std::borrow::Cow;
use std::collections::{BTreeSet, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::LazyLock;
#[cfg(feature = "ner")]
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

use regex::Regex;
use thiserror::Error;

use crate::EntityType;
use crate::detectors::{EntitySpan, PatternDetector};

const PACKET: usize = 254;
const OVERLAP: usize = 24;
const BATCH: usize = 8;
const CLS_ID: i64 = 101;
const SEP_ID: i64 = 102;
const UNKNOWN_ID: i64 = 100;
const LABEL_COUNT: usize = 9;
const CONFIDENCE_THRESHOLD: f64 = 0.60;
const MAX_CACHED_TEXT_BYTES: usize = 32_768;
const MAX_CACHE_ENTRIES: usize = 2_048;
const MAX_CACHE_CHARACTERS: usize = 2_000_000;

static WORDS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\p{L}[\p{L}\p{M}\p{N}]*|\p{N}+|[^\s]")
        .unwrap_or_else(|error| panic!("invalid built-in word regex: {error}"))
});
static TABLE_ROWS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?m)^\[Table\] [^\r\n]*")
        .unwrap_or_else(|error| panic!("invalid built-in table regex: {error}"))
});
static TABLE_ID: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\A[A-Za-z]{1,3}[0-9]{2,}\z")
        .unwrap_or_else(|error| panic!("invalid built-in table ID regex: {error}"))
});
static FULL_NAME_CELL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\Afull[ \t]+name[ \t]*:[ \t]*\p{L}[\p{L}\p{M}.'’ \t-]{0,100}\z")
        .unwrap_or_else(|error| panic!("invalid built-in full-name regex: {error}"))
});
static POSTAL_ADDRESS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)\A[0-9]{1,6}[^\r\n|:]{1,150},[ \t]*[\p{L} .'-]{1,80}[ \t]+(?:[0-9]{5}(?:-[0-9]{4})?|[A-Z][A-Z0-9]{1,3}[ \t]+[0-9][A-Z]{2})\z",
    )
    .unwrap_or_else(|error| panic!("invalid built-in postal-address regex: {error}"))
});
static ONLY_LABEL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\A\s*(?:[\p{L}][\p{L} .'’/-]{0,30}:)?\s*\z")
        .unwrap_or_else(|error| panic!("invalid built-in label regex: {error}"))
});
static PERSON_METADATA_KEY: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)creator|author|from|to\b|cc|owner|modif|artist|contributor|publisher|title|subject|comment|description|keyword|name|sender|recipient|initial|manager|company|organi|user")
        .unwrap_or_else(|error| panic!("invalid built-in metadata-key regex: {error}"))
});

static NOT_NAMES: LazyLock<HashSet<&'static str>> = LazyLock::new(|| {
    [
        "regards",
        "sincerely",
        "dear",
        "thanks",
        "thank",
        "cheers",
        "hello",
        "hi",
        "hey",
        "best",
        "yours",
        "faithfully",
        "truly",
        "greetings",
        "please",
        "note",
        "subject",
        "re",
        "fw",
        "fwd",
        "attn",
        "confidential",
        "draft",
        "copy",
        "page",
        "total",
        "invoice",
        "date",
        "name",
        "user",
        "admin",
        "administrator",
        "customer",
        "client",
        "patient",
        "guest",
        "member",
        "unknown",
        "none",
        "null",
        "test",
        "sample",
        "example",
        "error",
        "warning",
        "ok",
        "sir",
        "madam",
        "mr",
        "mrs",
        "ms",
        "dr",
        "team",
        "support",
        "sales",
        "info",
        "mon",
        "tue",
        "wed",
        "thu",
        "fri",
        "sat",
        "sun",
        "jan",
        "feb",
        "mar",
        "apr",
        "may",
        "jun",
        "jul",
        "aug",
        "sep",
        "oct",
        "nov",
        "dec",
        "cache",
        "memo",
        "display",
        "thumbnail",
        "summary",
        "report",
        "notice",
        "agenda",
        "minutes",
        "attachment",
        "untitled",
        "document",
        "sheet",
        "slide",
        "pattern",
        "findings",
        "source",
        "location",
        "value",
        "detection",
        "context",
        "page",
        "type",
        "score",
        "model",
        "local",
        "review",
    ]
    .into_iter()
    .collect()
});
static KEEP_UPPERCASE: LazyLock<HashSet<&'static str>> = LazyLock::new(|| {
    [
        "DOB", "SSN", "ID", "NAME", "TEL", "PHONE", "FAX", "EMAIL", "ADDRESS", "DATE", "REF", "NO",
        "PO", "ZIP", "USA", "UK", "EU", "US", "UN", "ISBN", "VAT", "TIN", "NI", "NHS", "IBAN",
        "BIC", "PIN", "DL", "MRN", "ACCT", "AMT", "TOTAL", "PAID", "DUE", "NOTE", "PAGE", "ATTN",
        "RE", "CC", "BCC", "FROM", "TO", "CV", "MM", "DD", "YYYY", "AM", "PM", "NA", "TBD", "TBA",
        "ASAP", "FYI", "URL", "HTTP", "HTTPS", "WWW", "COM", "PDF", "DOC", "XLS", "CSV", "IP",
        "MAC", "API", "KEY", "LOGIN", "USER", "PASSWORD", "OK", "YES", "AND", "OR", "THE", "OF",
        "IN", "AT", "BY", "FOR", "WITH", "ON", "IS", "ARE", "WAS", "AN", "IT", "AS", "BE", "THIS",
        "THAT", "NOT", "ALL", "ANY", "PER", "VIA", "ETC",
    ]
    .into_iter()
    .collect()
});

#[derive(Debug, Error)]
pub enum NameError {
    #[error("local person-name detection is unavailable: rebuild with the `ner` feature")]
    Unavailable,
    #[error("person-name detection was cancelled")]
    Cancelled,
    #[error("could not read {path}: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("invalid NER vocabulary: {0}")]
    InvalidVocabulary(String),
    #[error("local person-name inference failed: {0}")]
    Inference(String),
    #[error("local person-name inference session is unavailable after another thread panicked")]
    SessionPoisoned,
    #[error("local person-name model returned an invalid output: {0}")]
    InvalidModelOutput(String),
}

/// One model input token. `start` and `end` are UTF-8 byte offsets in the supplied text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NameToken {
    pub id: i64,
    pub start: usize,
    pub end: usize,
}

/// Diagnostic view of the model's decision for one word piece.
#[derive(Debug, Clone, PartialEq)]
pub struct TokenInspection {
    pub piece: String,
    /// 1 is B-PER, 2 is I-PER, and the remaining labels follow the pinned model config.
    pub label: usize,
    pub score: f64,
}

#[derive(Debug, Hash, PartialEq, Eq)]
struct CacheKey {
    text: String,
    phone_regions: Vec<String>,
}

#[derive(Debug, Default)]
struct DetectionCache {
    entries: HashMap<CacheKey, Vec<EntitySpan>>,
    characters: usize,
}

impl DetectionCache {
    fn insert(&mut self, key: CacheKey, spans: Vec<EntitySpan>) {
        let characters = key
            .phone_regions
            .iter()
            .fold(key.text.len(), |total, region| {
                total.saturating_add(region.len())
            });
        if key.text.len() > MAX_CACHED_TEXT_BYTES
            || self.entries.contains_key(&key)
            || self.entries.len() >= MAX_CACHE_ENTRIES
            || self.characters.saturating_add(characters) > MAX_CACHE_CHARACTERS
        {
            return;
        }
        self.characters += characters;
        self.entries.insert(key, spans);
    }
}

/// Returns whether model inference is useful for this extraction location.
///
/// Technical metadata is skipped, while author-like and other person-bearing keys remain visible.
#[must_use]
pub fn names_plausible(location: &str) -> bool {
    location
        .strip_prefix("metadata:")
        .is_none_or(|key| PERSON_METADATA_KEY.is_match(key))
}

fn check_cancelled(cancelled: &AtomicBool) -> Result<(), NameError> {
    if cancelled.load(Ordering::Acquire) {
        Err(NameError::Cancelled)
    } else {
        Ok(())
    }
}

fn is_not_name(value: &str) -> bool {
    let trimmed = value.trim_end_matches(['.', ',', ':']);
    NOT_NAMES.contains(trimmed) || NOT_NAMES.contains(trimmed.to_ascii_lowercase().as_str())
}

// The cased model needs capitals, except for scripts that do not encode case. Numeric-only
// packets remain ineligible, so the caseless-script fix does not add inference on numeric cells.
fn model_candidate_start(character: char) -> bool {
    character.is_uppercase() || (character.is_alphabetic() && !character.is_lowercase())
}

/// Restores the case pattern expected by the cased model without moving any UTF-8 offset.
/// A Unicode lowercase mapping is applied only when it occupies exactly the same byte count.
#[must_use]
pub fn truecase(text: &str) -> String {
    let mut result: Option<Vec<u8>> = None;
    let mut run: Vec<(usize, usize)> = Vec::new();
    let mut i = 0;

    while i <= text.len() {
        let start = i;
        let mut all_upper = true;
        let mut letters = 0;
        while i < text.len() {
            let character = text[i..].chars().next().unwrap_or('\0');
            let quote_joins_letters = matches!(character, '\'' | '’')
                && text[i + character.len_utf8()..]
                    .chars()
                    .next()
                    .is_some_and(char::is_alphabetic);
            if !character.is_alphabetic() && !quote_joins_letters {
                break;
            }
            if character.is_alphabetic() {
                letters += 1;
                if !character.is_uppercase() {
                    all_upper = false;
                }
            }
            i += character.len_utf8();
        }

        let word =
            i > start && letters >= 2 && all_upper && !KEEP_UPPERCASE.contains(&text[start..i]);
        if word {
            run.push((start, i));
        }
        let continues = word
            && i < text.len()
            && matches!(text[i..].chars().next(), Some(' ' | '\t' | '.' | ',' | '-'))
            && text[i + 1..]
                .chars()
                .next()
                .is_some_and(char::is_alphabetic);
        if !continues {
            let restore = run.len() >= 2
                || run
                    .first()
                    .is_some_and(|&(start, end)| text[start..end].encode_utf16().count() >= 4);
            if restore {
                let bytes = result.get_or_insert_with(|| text.as_bytes().to_vec());
                for &(start, end) in &run {
                    let mut first = true;
                    let mut previous = '\0';
                    for (relative, character) in text[start..end].char_indices() {
                        if !first && !matches!(previous, '\'' | '’') {
                            let mut lowercase = character.to_lowercase();
                            let Some(lower) = lowercase.next() else {
                                continue;
                            };
                            if lowercase.next().is_none()
                                && lower.len_utf8() == character.len_utf8()
                            {
                                let mut buffer = [0; 4];
                                let replacement = lower.encode_utf8(&mut buffer).as_bytes();
                                let position = start + relative;
                                bytes[position..position + replacement.len()]
                                    .copy_from_slice(replacement);
                            }
                        }
                        first = false;
                        previous = character;
                    }
                }
            }
            run.clear();
        }

        if i == text.len() {
            i += 1;
        } else {
            let consumed = i.max(start);
            i = consumed + text[consumed..].chars().next().map_or(1, char::len_utf8);
        }
    }

    result.map_or_else(
        || text.to_owned(),
        |bytes| String::from_utf8(bytes).unwrap_or_else(|_| text.to_owned()),
    )
}

/// Blanks machine-generated runs while retaining all byte offsets.
pub fn mask_noise(text: &str, cancelled: &AtomicBool) -> Result<String, NameError> {
    let mut result: Option<Vec<u8>> = None;
    let mut i = 0;
    while i < text.len() {
        if i & 4_095 == 0 {
            check_cancelled(cancelled)?;
        }
        let character = text[i..].chars().next().unwrap_or('\0');
        if character.is_whitespace() {
            i += character.len_utf8();
            continue;
        }
        let start = i;
        while i < text.len() {
            let character = text[i..].chars().next().unwrap_or('\0');
            if character.is_whitespace() {
                break;
            }
            i += character.len_utf8();
        }
        let mut run = start;
        while run < i {
            while run < i {
                let character = text[run..].chars().next().unwrap_or('\0');
                if !is_structural(character) {
                    break;
                }
                run += character.len_utf8();
            }
            let run_start = run;
            let mut letters = 0;
            let mut digits = 0;
            let mut upper = 0;
            let mut lower = 0;
            let mut others = 0;
            let mut longest = 0;
            let mut current = 0;
            while run < i {
                let character = text[run..].chars().next().unwrap_or('\0');
                if is_structural(character) {
                    break;
                }
                if character.is_alphabetic() {
                    letters += 1;
                    current += 1;
                    longest = longest.max(current);
                    if character.is_uppercase() {
                        upper += 1;
                    } else {
                        lower += 1;
                    }
                } else {
                    current = 0;
                    if character.is_numeric() {
                        digits += 1;
                    } else {
                        others += 1;
                    }
                }
                run += character.len_utf8();
            }
            let length = text[run_start..run].chars().count();
            let noise = (length >= 12 && digits > 0 && letters > 0 && longest <= 4)
                || (length >= 16 && digits > 0 && upper > 0 && lower > 0)
                || (length >= 10 && letters == 0)
                || (length >= 20 && others >= 2 && longest <= 6);
            if noise {
                result.get_or_insert_with(|| text.as_bytes().to_vec())[run_start..run].fill(b' ');
            }
        }
    }
    Ok(result.map_or_else(
        || text.to_owned(),
        |bytes| String::from_utf8(bytes).unwrap_or_else(|_| text.to_owned()),
    ))
}

fn is_structural(character: char) -> bool {
    character.is_whitespace()
        || matches!(
            character,
            '"' | '\''
                | '`'
                | '{'
                | '}'
                | '['
                | ']'
                | '('
                | ')'
                | ','
                | ';'
                | ':'
                | '|'
                | '='
                | '<'
                | '>'
                | '&'
                | '?'
                | '#'
                | '*'
                | '\\'
                | '/'
                | '@'
        )
}

fn mask_table_rows<'a>(
    text: &'a str,
    phone_regions: &BTreeSet<String>,
    cancelled: &AtomicBool,
) -> Result<Cow<'a, str>, NameError> {
    if !text.contains("[Table] ") {
        return Ok(Cow::Borrowed(text));
    }
    let patterns = PatternDetector::new(phone_regions);
    let mut output: Option<Vec<u8>> = None;
    for row in TABLE_ROWS.find_iter(text) {
        check_cancelled(cancelled)?;
        let bytes = output.get_or_insert_with(|| text.as_bytes().to_vec());
        let marker_end = row.start() + "[Table] ".len();
        bytes[row.start()..marker_end].fill(b' ');
        let cells = &text[marker_end..row.end()];
        let mut cell_start = 0;
        loop {
            check_cancelled(cancelled)?;
            let relative_end = cells[cell_start..]
                .find('|')
                .map_or(cells.len(), |end| cell_start + end);
            let absolute_start = marker_end + cell_start;
            let absolute_end = marker_end + relative_end;
            if is_structured_cell(text[absolute_start..absolute_end].trim(), &patterns) {
                bytes[absolute_start..absolute_end].fill(b' ');
            }
            if relative_end == cells.len() {
                break;
            }
            cell_start = relative_end + 1;
        }
    }
    Ok(output.map_or_else(
        || Cow::Borrowed(text),
        |bytes| Cow::Owned(String::from_utf8(bytes).unwrap_or_else(|_| text.to_owned())),
    ))
}

fn is_structured_cell(cell: &str, patterns: &PatternDetector) -> bool {
    if !cell.chars().any(char::is_alphabetic)
        || TABLE_ID.is_match(cell)
        || FULL_NAME_CELL.is_match(cell)
    {
        return true;
    }
    let mut remaining: Option<Vec<u8>> = None;
    for span in patterns.detect(cell) {
        if span.start == 0 && span.length == cell.len() {
            return true;
        }
        // A street followed by a city and postal code is one structured address. Requiring
        // the suffix avoids masking prose that merely follows a street name.
        if span.start == 0
            && span.entity_type == EntityType::StreetAddress
            && POSTAL_ADDRESS.is_match(cell)
        {
            return true;
        }
        remaining.get_or_insert_with(|| cell.as_bytes().to_vec())
            [span.start..span.start + span.length]
            .fill(b' ');
    }
    remaining.is_some_and(|bytes| {
        String::from_utf8(bytes).is_ok_and(|remaining| ONLY_LABEL.is_match(&remaining))
    })
}

#[cfg(feature = "ner")]
mod implementation {
    use std::time::Duration;

    use ndarray::{Array2, Array3, Ix3};
    use ort::session::RunOptions;
    use ort::session::Session;
    use ort::session::builder::GraphOptimizationLevel;
    use ort::value::TensorRef;

    use super::*;

    /// A tokenizer plus one inference session shared safely by scan workers.
    #[derive(Debug)]
    pub struct NameDetector {
        vocabulary: HashMap<String, i64>,
        // ort 2.0 rc requires `&mut Session` for inference. Serializing access is necessary for
        // memory safety; per-run options still isolate cancellation between callers.
        session: Mutex<Session>,
        cache: Mutex<DetectionCache>,
    }

    impl NameDetector {
        pub fn new(
            model_path: impl AsRef<Path>,
            vocab_path: impl AsRef<Path>,
            threads: usize,
        ) -> Result<Self, NameError> {
            let vocab_path = vocab_path.as_ref();
            let vocabulary_text =
                std::fs::read_to_string(vocab_path).map_err(|source| NameError::Read {
                    path: vocab_path.to_path_buf(),
                    source,
                })?;
            let mut vocabulary = HashMap::with_capacity(vocabulary_text.lines().count());
            for (index, piece) in vocabulary_text.lines().enumerate() {
                let id = i64::try_from(index).map_err(|_| {
                    NameError::InvalidVocabulary("vocabulary has too many entries".to_owned())
                })?;
                if vocabulary.insert(piece.to_owned(), id).is_some() {
                    return Err(NameError::InvalidVocabulary(format!(
                        "duplicate vocabulary entry at line {}",
                        index + 1
                    )));
                }
            }
            if vocabulary.is_empty() {
                return Err(NameError::InvalidVocabulary(
                    "vocabulary is empty".to_owned(),
                ));
            }
            for &(piece, id) in &[("[UNK]", UNKNOWN_ID), ("[CLS]", CLS_ID), ("[SEP]", SEP_ID)] {
                if vocabulary.get(piece) != Some(&id) {
                    return Err(NameError::InvalidVocabulary(format!(
                        "expected {piece} at ID {id}"
                    )));
                }
            }

            let environment = ort::init()
                .build()
                .map_err(|error| NameError::Inference(error.to_string()))?;
            let session = Session::builder(&environment)
                .map_err(|error| NameError::Inference(error.to_string()))?
                .with_auto_device(ort::session::builder::AutoDevicePolicy::PreferCPU)
                .map_err(|error| NameError::Inference(error.to_string()))?
                .with_intra_threads(threads.clamp(1, 16))
                .map_err(|error| NameError::Inference(error.to_string()))?
                .with_inter_threads(1)
                .map_err(|error| NameError::Inference(error.to_string()))?
                .with_optimization_level(GraphOptimizationLevel::All)
                .map_err(|error| NameError::Inference(error.to_string()))?
                .commit_from_file(model_path.as_ref())
                .map_err(|error| NameError::Inference(error.to_string()))?;
            Ok(Self {
                vocabulary,
                session: Mutex::new(session),
                cache: Mutex::new(DetectionCache::default()),
            })
        }

        /// Tokenizes text with the pinned cased WordPiece vocabulary.
        pub fn tokenize(&self, text: &str) -> Vec<NameToken> {
            self.tokenize_cancellable(text, &AtomicBool::new(false))
                .unwrap_or_default()
        }

        fn tokenize_cancellable(
            &self,
            text: &str,
            cancelled: &AtomicBool,
        ) -> Result<Vec<NameToken>, NameError> {
            let mut result = Vec::new();
            for word in WORDS.find_iter(text) {
                check_cancelled(cancelled)?;
                let word_text = word.as_str();
                if word_text.encode_utf16().count() > 100 {
                    result.push(NameToken {
                        id: UNKNOWN_ID,
                        start: word.start(),
                        end: word.end(),
                    });
                    continue;
                }
                let initial_count = result.len();
                let mut start = 0;
                while start < word_text.len() {
                    let mut end = word_text.len();
                    let mut found = None;
                    while end > start {
                        let piece = &word_text[start..end];
                        let candidate;
                        let key = if start == 0 {
                            piece
                        } else {
                            candidate = format!("##{piece}");
                            &candidate
                        };
                        if let Some(&id) = self.vocabulary.get(key) {
                            found = Some((id, end));
                            break;
                        }
                        let Some((previous, _)) = word_text[start..end].char_indices().next_back()
                        else {
                            break;
                        };
                        if previous == 0 {
                            break;
                        }
                        end = start + previous;
                    }
                    let Some((id, end)) = found else {
                        result.truncate(initial_count);
                        result.push(NameToken {
                            id: UNKNOWN_ID,
                            start: word.start(),
                            end: word.end(),
                        });
                        break;
                    };
                    result.push(NameToken {
                        id,
                        start: word.start() + start,
                        end: word.start() + end,
                    });
                    start = end;
                }
            }
            Ok(result)
        }

        /// Runs one diagnostic packet without noise masking or post-processing.
        pub fn inspect(&self, text: &str) -> Result<Vec<TokenInspection>, NameError> {
            let cancelled = AtomicBool::new(false);
            check_cancelled(&cancelled)?;
            let cased = truecase(text);
            let tokens = self.tokenize_cancellable(&cased, &cancelled)?;
            let count = tokens.len().min(PACKET);
            if count == 0 {
                return Ok(Vec::new());
            }
            let length = count + 2;
            let mut ids = Array2::<i64>::zeros((1, length));
            let mut mask = Array2::<i64>::zeros((1, length));
            ids[[0, 0]] = CLS_ID;
            ids[[0, count + 1]] = SEP_ID;
            mask.row_mut(0).fill(1);
            for (i, token) in tokens.iter().take(count).enumerate() {
                ids[[0, i + 1]] = token.id;
            }
            let logits = self.run_batch(ids, mask, &cancelled)?;
            let mut output = Vec::with_capacity(count);
            for (i, token) in tokens.iter().take(count).enumerate() {
                let (label, score) = best_label(&logits, 0, i + 1)?;
                output.push(TokenInspection {
                    piece: cased[token.start..token.end].to_owned(),
                    label,
                    score,
                });
            }
            Ok(output)
        }

        /// Detects person names with UTF-8 byte spans in `text`.
        ///
        /// `phone_regions` participates in cache identity so the API can share the scanner's
        /// structured-cell policy without permitting cross-configuration cache reuse.
        pub fn detect(
            &self,
            text: &str,
            location: &str,
            phone_regions: &BTreeSet<String>,
            cancelled: &AtomicBool,
        ) -> Result<Vec<EntitySpan>, NameError> {
            check_cancelled(cancelled)?;
            if !names_plausible(location) {
                return Ok(Vec::new());
            }
            // Numeric-only cells cannot produce a model name and are never cached; avoid even
            // allocating their cache key. Table rows still need structured-cell masking first.
            if !text.contains("[Table] ") && !text.chars().any(char::is_alphabetic) {
                return Ok(Vec::new());
            }
            let cache_characters = phone_regions.iter().fold(text.len(), |total, region| {
                total.saturating_add(region.len())
            });
            let cache_key = (text.len() <= MAX_CACHED_TEXT_BYTES
                && cache_characters <= MAX_CACHE_CHARACTERS)
                .then(|| CacheKey {
                    text: text.to_owned(),
                    phone_regions: phone_regions.iter().cloned().collect(),
                });
            if let Some(cache_key) = &cache_key
                && let Some(cached) = self
                    .cache
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .entries
                    .get(cache_key)
            {
                return Ok(cached.clone());
            }

            let masked_tables = mask_table_rows(text, phone_regions, cancelled)?;
            let model_text = masked_tables.as_ref();
            if model_text.trim().is_empty() || !model_text.chars().any(char::is_alphabetic) {
                return Ok(Vec::new());
            }
            check_cancelled(cancelled)?;
            let truecased = truecase(model_text);
            let cased = mask_noise(&truecased, cancelled)?;
            if !cased.chars().any(char::is_alphabetic) {
                return Ok(Vec::new());
            }
            let tokens = self.tokenize_cancellable(&cased, cancelled)?;
            let mut found = Vec::new();
            let starts = packet_starts(&tokens, &cased);

            for group in starts.chunks(BATCH) {
                check_cancelled(cancelled)?;
                let longest = group
                    .iter()
                    .map(|&start| PACKET.min(tokens.len() - start))
                    .max()
                    .unwrap_or(0);
                if longest == 0 {
                    continue;
                }
                let length = longest + 2;
                let mut ids = Array2::<i64>::zeros((group.len(), length));
                let mut mask = Array2::<i64>::zeros((group.len(), length));
                for (row, &start) in group.iter().enumerate() {
                    let count = PACKET.min(tokens.len() - start);
                    ids[[row, 0]] = CLS_ID;
                    ids[[row, count + 1]] = SEP_ID;
                    for i in 0..=count + 1 {
                        mask[[row, i]] = 1;
                    }
                    for i in 0..count {
                        ids[[row, i + 1]] = tokens[start + i].id;
                    }
                }
                let logits = self.run_batch(ids, mask, cancelled)?;
                for (row, &start) in group.iter().enumerate() {
                    let count = PACKET.min(tokens.len() - start);
                    let mut pending: Option<PendingEntity> = None;
                    for i in 0..count {
                        let (best, score) = best_label(&logits, row, i + 1)?;
                        let token = tokens[start + i];
                        if let Some(entity) = &pending
                            && masked_between(&truecased, &cased, entity.end, token.start)
                        {
                            flush_entity(&mut pending, text, &mut found);
                        }
                        let character = text[token.start..].chars().next().unwrap_or('\0');
                        if !character.is_alphanumeric() {
                            let glue = pending.as_ref().is_some_and(|entity| {
                                token.start == entity.end
                                    && token.end == token.start + character.len_utf8()
                                    && matches!(character, '.' | '\'' | '’' | '-')
                            });
                            if glue {
                                if let Some(entity) = &mut pending {
                                    entity.end = token.end;
                                }
                            } else {
                                flush_entity(&mut pending, text, &mut found);
                            }
                            continue;
                        }

                        let glued = pending
                            .as_ref()
                            .is_some_and(|entity| token.start == entity.end);
                        let continuation = glued
                            && token.start > 0
                            && text[..token.start]
                                .chars()
                                .next_back()
                                .is_some_and(char::is_alphanumeric);
                        if matches!(best, 1 | 2) || continuation {
                            if best == 1 && !glued {
                                flush_entity(&mut pending, text, &mut found);
                                pending = Some(PendingEntity::new(token.start));
                            } else if pending.is_none() {
                                pending = Some(PendingEntity::new(token.start));
                            }
                            if let Some(entity) = &mut pending {
                                if matches!(best, 1 | 2) {
                                    entity.confidence += score;
                                    entity.tokens += 1;
                                }
                                entity.end = token.end;
                            }
                        } else {
                            flush_entity(&mut pending, text, &mut found);
                        }
                    }
                    flush_entity(&mut pending, text, &mut found);
                }
            }

            let output = deduplicate_and_repair(found, text);
            check_cancelled(cancelled)?;
            if let Some(cache_key) = cache_key {
                self.cache
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .insert(cache_key, output.clone());
            }
            Ok(output)
        }

        fn run_batch(
            &self,
            ids: Array2<i64>,
            mask: Array2<i64>,
            cancelled: &AtomicBool,
        ) -> Result<Array3<f32>, NameError> {
            check_cancelled(cancelled)?;
            let ids = TensorRef::from_array_view(&ids)
                .map_err(|error| NameError::Inference(error.to_string()))?;
            let mask = TensorRef::from_array_view(&mask)
                .map_err(|error| NameError::Inference(error.to_string()))?;
            let options =
                RunOptions::new().map_err(|error| NameError::Inference(error.to_string()))?;
            let done = AtomicBool::new(false);
            let mut session = self
                .session
                .lock()
                .map_err(|_| NameError::SessionPoisoned)?;
            check_cancelled(cancelled)?;

            // AtomicBool has no callback registration. A short-lived watcher supplies the same
            // per-run termination behavior as CancellationToken.Register without sharing state.
            let result = std::thread::scope(|scope| {
                // Dropping this guard during unwinding releases the watcher before `scope`
                // waits for its threads, even if an ort internal unexpectedly panics.
                let _completion = RunCompletion(&done);
                let watcher = std::thread::Builder::new()
                    .name("pii-name-cancel".to_owned())
                    .spawn_scoped(scope, || {
                        while !done.load(Ordering::Acquire) {
                            if cancelled.load(Ordering::Acquire) {
                                let _ = options.terminate();
                                break;
                            }
                            std::thread::sleep(Duration::from_millis(2));
                        }
                    });
                let result = session.run_with_options(ort::inputs![ids, mask], &options);
                done.store(true, Ordering::Release);
                if let Ok(watcher) = watcher {
                    let _ = watcher.join();
                }
                result
            });
            let outputs = match result {
                Ok(outputs) => outputs,
                Err(_error) if cancelled.load(Ordering::Acquire) => {
                    return Err(NameError::Cancelled);
                }
                Err(error) => return Err(NameError::Inference(error.to_string())),
            };
            check_cancelled(cancelled)?;
            if outputs.len() == 0 {
                return Err(NameError::InvalidModelOutput(
                    "model returned no tensors".to_owned(),
                ));
            }
            let view = outputs[0]
                .try_extract_array::<f32>()
                .map_err(|error| NameError::InvalidModelOutput(error.to_string()))?;
            let logits = view
                .into_dimensionality::<Ix3>()
                .map_err(|error| NameError::InvalidModelOutput(error.to_string()))?
                .to_owned();
            if logits.dim().2 != LABEL_COUNT {
                return Err(NameError::InvalidModelOutput(format!(
                    "expected {LABEL_COUNT} labels, got {}",
                    logits.dim().2
                )));
            }
            Ok(logits)
        }
    }

    struct RunCompletion<'a>(&'a AtomicBool);

    impl Drop for RunCompletion<'_> {
        fn drop(&mut self) {
            self.0.store(true, Ordering::Release);
        }
    }

    #[derive(Debug)]
    struct PendingEntity {
        start: usize,
        end: usize,
        tokens: usize,
        confidence: f64,
    }

    impl PendingEntity {
        fn new(start: usize) -> Self {
            Self {
                start,
                end: start,
                tokens: 0,
                confidence: 0.0,
            }
        }
    }

    fn best_label(
        logits: &Array3<f32>,
        row: usize,
        position: usize,
    ) -> Result<(usize, f64), NameError> {
        if row >= logits.dim().0 || position >= logits.dim().1 {
            return Err(NameError::InvalidModelOutput(format!(
                "logit position ({row}, {position}) exceeds shape {:?}",
                logits.dim()
            )));
        }
        let mut best = 0;
        let mut maximum = logits[[row, position, 0]];
        for label in 1..LABEL_COUNT {
            let value = logits[[row, position, label]];
            if value > maximum {
                maximum = value;
                best = label;
            }
        }
        let total: f64 = (0..LABEL_COUNT)
            .map(|label| f64::from(logits[[row, position, label]] - maximum).exp())
            .sum();
        Ok((best, 1.0 / total))
    }

    fn packet_starts(tokens: &[NameToken], cased: &str) -> Vec<usize> {
        let mut starts = Vec::new();
        let mut start = 0;
        while start < tokens.len() {
            let count = PACKET.min(tokens.len() - start);
            if tokens[start..start + count].iter().any(|token| {
                cased[token.start..]
                    .chars()
                    .next()
                    .is_some_and(model_candidate_start)
            }) {
                starts.push(start);
            }
            if start + PACKET >= tokens.len() {
                break;
            }
            start += PACKET - OVERLAP;
        }
        starts
    }

    fn masked_between(truecased: &str, cased: &str, from: usize, to: usize) -> bool {
        truecased.as_bytes()[from.min(cased.len())..to.min(cased.len())]
            != cased.as_bytes()[from.min(cased.len())..to.min(cased.len())]
    }

    fn flush_entity(pending: &mut Option<PendingEntity>, text: &str, found: &mut Vec<EntitySpan>) {
        let Some(mut entity) = pending.take() else {
            return;
        };
        trim_lowercase_tail(text, entity.start, &mut entity.end);
        while entity.end > entity.start {
            let character = text[..entity.end].chars().next_back().unwrap_or('\0');
            if character.is_alphanumeric() {
                break;
            }
            entity.end -= character.len_utf8();
        }
        if entity.end <= entity.start
            || text[entity.start..entity.end].encode_utf16().count() < 2
            || entity.tokens == 0
        {
            return;
        }
        let confidence = entity.confidence / entity.tokens as f64;
        let start_boundary = entity.start == 0
            || text[..entity.start]
                .chars()
                .next_back()
                .is_some_and(|character| !character.is_alphanumeric());
        let end_boundary = entity.end == text.len()
            || text[entity.end..]
                .chars()
                .next()
                .is_some_and(|character| !character.is_alphanumeric());
        let value = &text[entity.start..entity.end];
        if confidence >= CONFIDENCE_THRESHOLD
            && start_boundary
            && end_boundary
            && !is_not_name(value)
        {
            found.push(EntitySpan::new(
                EntityType::Person,
                entity.start,
                entity.end - entity.start,
                ((confidence * 10_000.0).round() / 10_000.0) as f32,
                "Local model",
            ));
        }
    }

    fn trim_lowercase_tail(text: &str, start: usize, end: &mut usize) {
        while *end > start {
            let mut word_end = *end;
            while word_end > start {
                let character = text[..word_end].chars().next_back().unwrap_or('\0');
                if character.is_alphanumeric() {
                    break;
                }
                word_end -= character.len_utf8();
            }
            let mut word_start = word_end;
            while word_start > start {
                let character = text[..word_start].chars().next_back().unwrap_or('\0');
                if !(character.is_alphanumeric() || matches!(character, '.' | '\'' | '’' | '-')) {
                    break;
                }
                word_start -= character.len_utf8();
            }
            let word = &text[word_start..word_end];
            let lower = word.chars().any(char::is_lowercase);
            let upper = word.chars().any(char::is_uppercase);
            if (lower && !upper)
                || (word_start > start && (KEEP_UPPERCASE.contains(word) || is_not_name(word)))
            {
                *end = word_start;
            } else {
                return;
            }
        }
    }

    fn deduplicate_and_repair(mut found: Vec<EntitySpan>, text: &str) -> Vec<EntitySpan> {
        found.sort_by(|left, right| {
            left.start
                .cmp(&right.start)
                .then_with(|| right.length.cmp(&left.length))
                .then_with(|| right.confidence.total_cmp(&left.confidence))
        });
        let mut kept: Vec<EntitySpan> = Vec::new();
        let mut furthest_end = 0;
        for span in found {
            let end = span.start + span.length;
            if !kept.is_empty() && end <= furthest_end {
                continue;
            }
            let punctuation_join = kept.last().is_some_and(|previous| {
                text.get(furthest_end..span.start)
                    .is_some_and(|between| matches!(between, "'" | "’" | "-"))
                    && previous.start + previous.length == furthest_end
            });
            if punctuation_join {
                if let Some(previous) = kept.last_mut() {
                    previous.length = end - previous.start;
                    previous.confidence = previous.confidence.min(span.confidence);
                }
            } else {
                kept.push(span);
            }
            furthest_end = end;
        }
        kept.sort_by(|left, right| {
            right
                .length
                .cmp(&left.length)
                .then_with(|| right.confidence.total_cmp(&left.confidence))
                .then_with(|| left.start.cmp(&right.start))
        });
        kept
    }
}

#[cfg(feature = "ner")]
pub use implementation::NameDetector;

/// Feature-disabled detector. Construction and detection both report the missing capability.
#[cfg(not(feature = "ner"))]
#[derive(Debug)]
pub struct NameDetector;

#[cfg(not(feature = "ner"))]
impl NameDetector {
    pub fn new(
        _model_path: impl AsRef<Path>,
        _vocab_path: impl AsRef<Path>,
        _threads: usize,
    ) -> Result<Self, NameError> {
        Err(NameError::Unavailable)
    }

    pub fn detect(
        &self,
        _text: &str,
        _location: &str,
        _phone_regions: &BTreeSet<String>,
        _cancelled: &AtomicBool,
    ) -> Result<Vec<EntitySpan>, NameError> {
        Err(NameError::Unavailable)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truecasing_preserves_offsets_acronyms_and_labels() {
        assert_eq!(truecase("JOHN SMITH AND DOB"), "John Smith AND DOB");
        assert_eq!(truecase("Sent EDT via PDF"), "Sent EDT via PDF");
        assert_eq!(truecase("O'BRIEN"), "O'Brien");
        assert_eq!(
            truecase("NAME: MARIA HERNANDEZ DOB: 1984-03-11"),
            "NAME: Maria Hernandez DOB: 1984-03-11"
        );
        for text in [
            "Ärzte OHNE GRENZEN e.V.",
            "MARIA HERNANDEZ",
            "Nguyễn Văn An",
            "",
        ] {
            assert_eq!(truecase(text).len(), text.len());
        }
    }

    #[test]
    fn caseless_letters_are_candidates_but_numeric_cells_are_not() {
        assert!(model_candidate_start('李'));
        assert!(model_candidate_start('م'));
        assert!(model_candidate_start('M'));
        assert!(!model_candidate_start('m'));
        assert!(!model_candidate_start('4'));
    }

    #[test]
    fn metadata_gate_preserves_person_keys() {
        assert!(!names_plausible("metadata:color-space"));
        assert!(names_plausible("metadata:author"));
        assert!(names_plausible("body"));
    }

    #[test]
    fn noise_masking_is_byte_preserving() {
        let text = "Maria Hernandez key=AbCdEfGh1234567890";
        let masked = mask_noise(text, &AtomicBool::new(false)).unwrap_or_default();
        assert_eq!(masked.len(), text.len());
        assert!(masked.starts_with("Maria Hernandez"));
        assert!(masked.contains("Maria Hernandez"));
    }

    #[cfg(not(feature = "ner"))]
    #[test]
    fn feature_disabled_constructor_reports_unavailable() {
        let result = NameDetector::new("model.onnx", "vocab.txt", 1);
        let Err(error) = result else {
            panic!("feature-disabled detector unexpectedly loaded");
        };
        assert!(matches!(error, NameError::Unavailable));
        assert!(error.to_string().contains("ner"));
    }

    #[cfg(feature = "ner")]
    mod model {
        use super::*;

        fn detector() -> &'static NameDetector {
            static DETECTOR: LazyLock<NameDetector> = LazyLock::new(|| {
                let assets = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../assets/models");
                NameDetector::new(
                    assets.join("model_quantized.onnx"),
                    assets.join("vocab.txt"),
                    1,
                )
                .unwrap_or_else(|error| panic!("load pinned NER assets: {error}"))
            });
            &DETECTOR
        }

        fn regions() -> BTreeSet<String> {
            ["GB".to_owned(), "US".to_owned()].into_iter().collect()
        }

        fn names(text: &str) -> Vec<String> {
            detector()
                .detect(text, "body", &regions(), &AtomicBool::new(false))
                .unwrap_or_else(|error| panic!("detect names in {text:?}: {error}"))
                .into_iter()
                .map(|span| text[span.start..span.start + span.length].to_owned())
                .collect()
        }

        #[test]
        fn failed_wordpieces_roll_back_and_overlong_words_are_unknown() {
            let word = format!("{}\u{08a0}", "a".repeat(99));
            let text = format!("Maria {word} David");
            let tokens = detector().tokenize(&text);
            let unknown: Vec<_> = tokens
                .iter()
                .filter(|token| token.start >= 6 && token.start < 6 + word.len())
                .collect();
            assert_eq!(unknown.len(), 1);
            assert_eq!(unknown[0].id, UNKNOWN_ID);
            assert_eq!(unknown[0].start, 6);
            assert_eq!(unknown[0].end, 6 + word.len());
            assert!(
                tokens
                    .iter()
                    .any(|token| token.start == text.find("David").unwrap_or(0))
            );

            let long = "a".repeat(100_000);
            let tokens = detector().tokenize(&long);
            assert_eq!(tokens.len(), 1);
            assert_eq!(tokens[0].id, UNKNOWN_ID);
            assert_eq!(tokens[0].end, long.len());
        }

        #[test]
        fn representative_names_keep_exact_utf8_spans() {
            for (text, expected) in [
                ("From: Priya Raghunathan", "Priya Raghunathan"),
                ("Customer Olusegun Adebayo called.", "Olusegun Adebayo"),
                ("Customer Yuki Tanaka called.", "Yuki Tanaka"),
                ("Nguyễn Văn An attended the meeting.", "Nguyễn Văn An"),
                ("Contact: J. Robert Oppenheimer", "J. Robert Oppenheimer"),
                ("O'Brien, Patrick attended.", "O'Brien"),
                ("Jean-Luc Picard attended.", "Jean-Luc Picard"),
                ("JOHN SMITH attended the meeting.", "JOHN SMITH"),
                ("NAME: MARIA HERNANDEZ DOB: 1984-03-11", "MARIA HERNANDEZ"),
            ] {
                let spans = detector()
                    .detect(text, "body", &regions(), &AtomicBool::new(false))
                    .unwrap_or_default();
                assert!(
                    spans.iter().any(|span| {
                        text.get(span.start..span.start + span.length) == Some(expected)
                    }),
                    "missing {expected:?} in {text:?}; got {spans:?}"
                );
            }
        }

        #[test]
        fn closings_acronyms_and_organizations_are_not_people() {
            for text in [
                "Best regards,",
                "Send the PDF to IBM and NASA today.",
                "The FBI and CIA met with ACME CORP.",
                "Modified Tue Aug 25 18:21:14 EDT 2026",
                "Microsoft Excel crashed again.",
                "Bank of America statement.",
            ] {
                assert!(names(text).is_empty(), "unexpected names in {text:?}");
            }
        }

        #[test]
        fn table_masking_preserves_notes_and_original_offsets() {
            let structured = "[Table] E000001 | Full name: Maria Hernandez | maria@example.com | 415-555-0142 | 123-45-6789 | DOB: 1984-03-11 | 911 Kingsway Lane, Portland OR 97205 | Passport number: AB1234567 |";
            assert!(names(structured).is_empty());
            let text = "[Table] Full name: Maria Hernandez | notes: David Okonkwo called.";
            let spans = detector()
                .detect(text, "body", &regions(), &AtomicBool::new(false))
                .unwrap_or_default();
            assert!(spans.iter().any(|span| {
                span.start == text.find("David").unwrap_or(usize::MAX)
                    && text[span.start..span.start + span.length] == *"David Okonkwo"
            }));
            assert!(
                !spans.iter().any(|span| {
                    text[span.start..span.start + span.length] == *"Maria Hernandez"
                })
            );
        }

        #[test]
        fn inspection_exposes_person_label_and_score() {
            let tokens = detector()
                .inspect("Maria Hernandez called.")
                .unwrap_or_default();
            assert!(!tokens.is_empty());
            assert_eq!(tokens[0].label, 1);
            assert_eq!(tokens[0].piece, "Maria");
            assert!(tokens[0].score > 0.9);
        }

        #[test]
        fn cancellation_precedes_fast_paths_and_does_not_poison_shared_state() {
            for text in ["", "   ", "12345", "[Table] Full name: Maria Hernandez |"] {
                let result = detector().detect(text, "body", &regions(), &AtomicBool::new(true));
                let Err(error) = result else {
                    panic!("cancelled detection unexpectedly succeeded");
                };
                assert!(matches!(error, NameError::Cancelled));
            }
            assert!(!names("Maria Hernandez spoke with David Okonkwo.").is_empty());
        }

        #[test]
        fn cancelling_one_worker_does_not_cancel_another() {
            let shared = detector();
            let cancelled = std::sync::Arc::new(AtomicBool::new(false));
            let long_text =
                "Maria Hernandez spoke with David Okonkwo about the delivery. ".repeat(400);
            std::thread::scope(|scope| {
                let cancelled_flag = std::sync::Arc::clone(&cancelled);
                let long_text = &long_text;
                let cancelled_worker = scope
                    .spawn(move || shared.detect(long_text, "body", &regions(), &cancelled_flag));
                let normal_worker = scope.spawn(|| {
                    shared.detect(
                        "Cancellation isolation check: Yuki Tanaka remained available.",
                        "body",
                        &regions(),
                        &AtomicBool::new(false),
                    )
                });
                std::thread::sleep(std::time::Duration::from_millis(10));
                cancelled.store(true, Ordering::Release);
                let cancelled_result = cancelled_worker
                    .join()
                    .unwrap_or_else(|_| panic!("cancelled worker panicked"));
                assert!(matches!(cancelled_result, Err(NameError::Cancelled)));
                let normal = normal_worker
                    .join()
                    .unwrap_or_else(|_| panic!("normal worker panicked"))
                    .unwrap_or_else(|error| panic!("normal worker was cancelled: {error}"));
                assert!(normal.iter().any(|span| {
                    span.length == "Yuki Tanaka".len()
                        && span.start > 0
                        && span.start < "Cancellation isolation check: ".len() + 1
                }));
            });
        }

        #[test]
        fn cache_enforces_entry_and_character_bounds() {
            let mut cache = DetectionCache::default();
            for i in 0..=MAX_CACHE_ENTRIES {
                cache.insert(
                    CacheKey {
                        text: i.to_string(),
                        phone_regions: Vec::new(),
                    },
                    Vec::new(),
                );
            }
            assert_eq!(cache.entries.len(), MAX_CACHE_ENTRIES);
            assert!(cache.characters <= MAX_CACHE_CHARACTERS);

            let mut cache = DetectionCache::default();
            for i in 0..100 {
                cache.insert(
                    CacheKey {
                        text: format!("{}{i:04}", "x".repeat(MAX_CACHED_TEXT_BYTES - 4)),
                        phone_regions: Vec::new(),
                    },
                    Vec::new(),
                );
            }
            assert_eq!(
                cache.entries.len(),
                MAX_CACHE_CHARACTERS / MAX_CACHED_TEXT_BYTES
            );
            assert!(cache.characters <= MAX_CACHE_CHARACTERS);
        }

        #[test]
        fn cached_detections_cannot_be_mutated_by_callers() {
            let text = "Maria Hernandez spoke with David Okonkwo about the delivery.";
            let mut first = detector()
                .detect(text, "body", &regions(), &AtomicBool::new(false))
                .unwrap_or_default();
            assert!(!first.is_empty());
            let expected = first.clone();
            first[0].start = 0;
            first[0].length = 1;
            first[0].method = "Changed by caller".to_owned();
            let second = detector()
                .detect(text, "body", &regions(), &AtomicBool::new(false))
                .unwrap_or_default();
            assert_eq!(second, expected);
        }

        #[test]
        fn shared_detector_supports_concurrent_workers() {
            let shared = detector();
            std::thread::scope(|scope| {
                for (text, expected) in [
                    (
                        "Concurrent worker A: Maria Hernandez called about the first delivery.",
                        "Maria Hernandez",
                    ),
                    (
                        "Concurrent worker B: David Okonkwo called about the second delivery.",
                        "David Okonkwo",
                    ),
                ] {
                    scope.spawn(move || {
                        let spans = shared
                            .detect(text, "body", &regions(), &AtomicBool::new(false))
                            .unwrap_or_default();
                        assert!(spans.iter().any(|span| {
                            text.get(span.start..span.start + span.length) == Some(expected)
                        }));
                    });
                }
            });
        }

        #[test]
        fn overlapping_packets_keep_repeated_names_at_distinct_offsets() {
            let sentence = "Maria Hernandez spoke with David Okonkwo about the delivery. ";
            let text = sentence.repeat(60);
            let spans = detector()
                .detect(&text, "body", &regions(), &AtomicBool::new(false))
                .unwrap_or_default();
            let mut positions: Vec<_> =
                spans.iter().map(|span| (span.start, span.length)).collect();
            positions.sort_unstable();
            positions.dedup();
            assert_eq!(positions.len(), spans.len());
            for i in 0..60 {
                let offset = i * sentence.len();
                assert!(spans.iter().any(|span| {
                    span.start == offset
                        && text[span.start..span.start + span.length] == *"Maria Hernandez"
                }));
                assert!(spans.iter().any(|span| {
                    span.start == offset + sentence.find("David").unwrap_or(0)
                        && text[span.start..span.start + span.length] == *"David Okonkwo"
                }));
            }
        }
    }
}
