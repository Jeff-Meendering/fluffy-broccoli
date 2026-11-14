use std::collections::BTreeSet;
use std::path::PathBuf;
use std::time::Duration;

use serde::{Deserialize, Serialize};

pub const DEFAULT_MAX_FILE_BYTES: u64 = 100 * 1024 * 1024;
pub const DEFAULT_MAX_FINDINGS: usize = 500_000;
pub const DEFAULT_MAX_ATTENTION: usize = 10_000;
pub const DEFAULT_MAX_ARCHIVE_BYTES: u64 = 400 * 1024 * 1024;
pub const DEFAULT_MAX_ARCHIVE_MEMBERS: usize = 2_000;
pub const DEFAULT_MAX_EXTRACTED_UTF16: usize = 16_000_000;
pub const DEFAULT_CHUNK_UTF16: usize = 24_000;
pub const DEFAULT_CHUNK_OVERLAP_UTF16: usize = 512;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum EntityType {
    Person,
    Email,
    Phone,
    #[serde(rename = "Social Security number")]
    SocialSecurityNumber,
    #[serde(rename = "Payment card")]
    PaymentCard,
    #[serde(rename = "Street address")]
    StreetAddress,
    #[serde(rename = "Date of birth")]
    DateOfBirth,
    #[serde(rename = "IP address")]
    IpAddress,
    #[serde(rename = "MAC address")]
    MacAddress,
    #[serde(rename = "UK National Insurance")]
    UkNationalInsurance,
    #[serde(rename = "IBAN")]
    Iban,
    #[serde(rename = "National ID")]
    NationalId,
    #[serde(rename = "Labelled identifier")]
    LabelledIdentifier,
    Credential,
    #[serde(rename = "Crypto wallet")]
    CryptoWallet,
}

impl EntityType {
    pub const ALL: [Self; 15] = [
        Self::Person,
        Self::Email,
        Self::Phone,
        Self::SocialSecurityNumber,
        Self::PaymentCard,
        Self::StreetAddress,
        Self::DateOfBirth,
        Self::IpAddress,
        Self::MacAddress,
        Self::UkNationalInsurance,
        Self::Iban,
        Self::NationalId,
        Self::LabelledIdentifier,
        Self::Credential,
        Self::CryptoWallet,
    ];

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Person => "Person",
            Self::Email => "Email",
            Self::Phone => "Phone",
            Self::SocialSecurityNumber => "Social Security number",
            Self::PaymentCard => "Payment card",
            Self::StreetAddress => "Street address",
            Self::DateOfBirth => "Date of birth",
            Self::IpAddress => "IP address",
            Self::MacAddress => "MAC address",
            Self::UkNationalInsurance => "UK National Insurance",
            Self::Iban => "IBAN",
            Self::NationalId => "National ID",
            Self::LabelledIdentifier => "Labelled identifier",
            Self::Credential => "Credential",
            Self::CryptoWallet => "Crypto wallet",
        }
    }

    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|kind| kind.as_str() == value)
    }
}

impl std::fmt::Display for EntityType {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum EvidenceKind {
    Body,
    Filename,
    ArchiveMemberName,
    Metadata,
    Ocr,
    BinaryStrings,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum CoordinateUnit {
    #[serde(rename = "utf16")]
    Utf16CodeUnits,
    #[serde(rename = "bytes")]
    Bytes,
}

/// Stable identity for one representation of a resource.
///
/// Resource and stream IDs are logical identifiers, not host filesystem paths. Archive
/// ordinals distinguish duplicate member names. `chunk_start` identifies the extraction
/// chunk; finding offsets are always absolute within the selected representation.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct EvidenceOrigin {
    pub resource_id: String,
    pub stream_id: String,
    pub kind: EvidenceKind,
    pub representation: String,
    pub chunk_start: u64,
    pub coordinate_unit: CoordinateUnit,
    #[serde(default = "default_stride")]
    pub stride: u32,
}

const fn default_stride() -> u32 {
    1
}

impl EvidenceOrigin {
    #[must_use]
    pub fn text(
        resource_id: impl Into<String>,
        stream_id: impl Into<String>,
        representation: impl Into<String>,
    ) -> Self {
        Self {
            resource_id: resource_id.into(),
            stream_id: stream_id.into(),
            kind: EvidenceKind::Body,
            representation: representation.into(),
            chunk_start: 0,
            coordinate_unit: CoordinateUnit::Utf16CodeUnits,
            stride: 1,
        }
    }

    #[must_use]
    pub fn occurrence_key(&self) -> (&str, &str) {
        (&self.resource_id, &self.stream_id)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Finding {
    #[serde(rename = "type")]
    pub entity_type: EntityType,
    pub value: String,
    pub start: u64,
    pub length: u64,
    pub context: String,
    pub context_start: u64,
    pub detector_start: u64,
    pub detector_length: u64,
    pub confidence: f32,
    pub method: String,
    pub origin: EvidenceOrigin,
}

impl Finding {
    /// Identity deliberately excludes value, confidence, detector method, and chunk start.
    /// This collapses overlapping chunk/model duplicates without merging distinct occurrences.
    #[must_use]
    pub fn occurrence_key(&self) -> (&str, &str, EntityType, u64, u64) {
        (
            &self.origin.resource_id,
            &self.origin.stream_id,
            self.entity_type,
            self.start,
            self.length,
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttentionItem {
    pub resource_id: String,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtractedPart {
    pub text: String,
    pub location: Option<String>,
    pub origin: EvidenceOrigin,
    /// Artificial segmentation must not turn a clipped identifier into a new occurrence.
    pub continues_before: bool,
    pub continues_after: bool,
}

impl ExtractedPart {
    #[must_use]
    pub fn new(text: impl Into<String>, origin: EvidenceOrigin) -> Self {
        Self {
            text: text.into(),
            location: None,
            origin,
            continues_before: false,
            continues_after: false,
        }
    }

    #[must_use]
    pub fn at(mut self, location: impl Into<String>) -> Self {
        self.location = Some(location.into());
        self
    }

    #[must_use]
    pub fn with_continuations(mut self, before: bool, after: bool) -> Self {
        self.continues_before = before;
        self.continues_after = after;
        self
    }
}

#[derive(Debug, Clone, Default)]
pub struct Extraction {
    pub parts: Vec<ExtractedPart>,
    pub attention: Vec<AttentionItem>,
    /// True when a parser intentionally provides metadata only or only a strings view.
    pub partial: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceRecord {
    pub resource_id: String,
    pub size: u64,
    pub sha256: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ScanOptions {
    pub detect_names: bool,
    #[serde(skip)]
    pub model_path: Option<PathBuf>,
    #[serde(skip)]
    pub vocab_path: Option<PathBuf>,
    pub ocr: bool,
    #[serde(skip)]
    pub tesseract_path: Option<PathBuf>,
    #[serde(skip)]
    pub tessdata_path: Option<PathBuf>,
    pub max_file_bytes: u64,
    pub max_findings: usize,
    pub max_attention: usize,
    pub max_archive_bytes: u64,
    pub max_archive_members: usize,
    pub max_archive_depth: usize,
    pub max_extracted_utf16: usize,
    pub file_timeout: Duration,
    pub ocr_timeout: Duration,
    pub workers: usize,
    pub phone_regions: BTreeSet<String>,
    pub include_context: bool,
    pub excluded_directories: BTreeSet<String>,
    pub custom_rules: Vec<crate::custom::CustomRule>,
}

impl Default for ScanOptions {
    fn default() -> Self {
        let workers =
            std::thread::available_parallelism().map_or(2, |count| (count.get() / 4).clamp(2, 4));
        Self {
            detect_names: true,
            model_path: None,
            vocab_path: None,
            ocr: true,
            tesseract_path: None,
            tessdata_path: None,
            max_file_bytes: DEFAULT_MAX_FILE_BYTES,
            max_findings: DEFAULT_MAX_FINDINGS,
            max_attention: DEFAULT_MAX_ATTENTION,
            max_archive_bytes: DEFAULT_MAX_ARCHIVE_BYTES,
            max_archive_members: DEFAULT_MAX_ARCHIVE_MEMBERS,
            max_archive_depth: 4,
            max_extracted_utf16: DEFAULT_MAX_EXTRACTED_UTF16,
            file_timeout: Duration::from_secs(180),
            ocr_timeout: Duration::from_secs(60),
            workers,
            phone_regions: ["GB".to_owned(), "US".to_owned()].into_iter().collect(),
            include_context: true,
            excluded_directories: [
                ".git",
                ".svn",
                ".hg",
                "node_modules",
                "__pycache__",
                ".venv",
                "venv",
                "$RECYCLE.BIN",
                "System Volume Information",
            ]
            .into_iter()
            .map(str::to_owned)
            .collect(),
            custom_rules: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanProgress {
    pub discovered: u64,
    pub completed: u64,
    pub findings: usize,
    pub attention: usize,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanSummary {
    pub discovered: u64,
    pub completed: u64,
    pub findings: usize,
    pub attention: usize,
    pub cancelled: bool,
    pub limit_reached: Option<String>,
    pub elapsed_ms: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ScanResult {
    #[serde(default)]
    pub settings: ScanOptions,
    pub findings: Vec<Finding>,
    pub attention: Vec<AttentionItem>,
    pub sources: Vec<SourceRecord>,
    pub summary: ScanSummary,
}

impl ScanResult {
    /// Sorting after parallel extraction makes output independent of worker timing.
    pub fn sort_deterministically(&mut self) {
        self.findings.sort_by(|left, right| {
            left.origin
                .resource_id
                .cmp(&right.origin.resource_id)
                .then_with(|| left.origin.stream_id.cmp(&right.origin.stream_id))
                .then_with(|| left.start.cmp(&right.start))
                .then_with(|| left.length.cmp(&right.length))
                .then_with(|| left.entity_type.cmp(&right.entity_type))
                .then_with(|| left.method.cmp(&right.method))
        });
        self.attention.sort_by(|left, right| {
            left.resource_id
                .cmp(&right.resource_id)
                .then_with(|| left.message.cmp(&right.message))
        });
        self.sources
            .sort_by(|left, right| left.resource_id.cmp(&right.resource_id));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entity_names_match_the_existing_json_contract() {
        for kind in EntityType::ALL {
            assert_eq!(EntityType::parse(kind.as_str()), Some(kind));
            let json = serde_json::to_string(&kind).expect("serialize entity");
            assert_eq!(
                serde_json::from_str::<EntityType>(&json).expect("deserialize entity"),
                kind
            );
        }
    }

    #[test]
    fn occurrence_identity_excludes_display_and_detector_details() {
        let origin = EvidenceOrigin::text("root:0", "body", "parsed-text");
        let finding = Finding {
            entity_type: EntityType::Email,
            value: "alice@example.com".into(),
            start: 4,
            length: 17,
            context: "... alice@example.com ...".into(),
            context_start: 0,
            detector_start: 4,
            detector_length: 17,
            confidence: 0.9,
            method: "regex".into(),
            origin,
        };
        let mut duplicate = finding.clone();
        duplicate.value = "normalized".into();
        duplicate.method = "model".into();
        duplicate.origin.chunk_start = 24_000;
        assert_eq!(finding.occurrence_key(), duplicate.occurrence_key());
    }
}
