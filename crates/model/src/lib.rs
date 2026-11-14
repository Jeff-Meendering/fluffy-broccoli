//! Domain types shared by every stage of the pipeline.
//!
//! The unit of work is a person, not a matched string. Extraction produces [`Table`]s,
//! detection assigns columns to [`ElementKind`]s, and linking turns each row into a
//! [`PersonRecord`] made of [`Observation`]s. Anything that could not be read is a
//! [`CoverageGap`], never a silent skip.

pub mod date;

use serde::{Deserialize, Serialize};

/// A category of personal data that can be exposed for one person.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ElementKind {
    Name,
    Ssn,
    DateOfBirth,
    Email,
    Phone,
    Address,
    City,
    State,
    PostalCode,
    Country,
    PaymentCard,
    BankAccount,
    RoutingNumber,
    DriversLicence,
    Passport,
    MedicalRecordNumber,
    HealthInsuranceId,
}

impl ElementKind {
    pub const ALL: [Self; 17] = [
        Self::Name,
        Self::Ssn,
        Self::DateOfBirth,
        Self::Email,
        Self::Phone,
        Self::Address,
        Self::City,
        Self::State,
        Self::PostalCode,
        Self::Country,
        Self::PaymentCard,
        Self::BankAccount,
        Self::RoutingNumber,
        Self::DriversLicence,
        Self::Passport,
        Self::MedicalRecordNumber,
        Self::HealthInsuranceId,
    ];

    /// Stable identifier used in the case database and export column names.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Name => "name",
            Self::Ssn => "ssn",
            Self::DateOfBirth => "date_of_birth",
            Self::Email => "email",
            Self::Phone => "phone",
            Self::Address => "address",
            Self::City => "city",
            Self::State => "state",
            Self::PostalCode => "postal_code",
            Self::Country => "country",
            Self::PaymentCard => "payment_card",
            Self::BankAccount => "bank_account",
            Self::RoutingNumber => "routing_number",
            Self::DriversLicence => "drivers_licence",
            Self::Passport => "passport",
            Self::MedicalRecordNumber => "medical_record_number",
            Self::HealthInsuranceId => "health_insurance_id",
        }
    }

    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|kind| kind.as_str() == value)
    }

    /// The element as named in a sentence: "same SSN", "same email address".
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Name => "name",
            Self::Ssn => "SSN",
            Self::DateOfBirth => "date of birth",
            Self::Email => "email address",
            Self::Phone => "phone number",
            Self::Address => "address",
            Self::City => "city",
            Self::State => "state",
            Self::PostalCode => "postal code",
            Self::Country => "country",
            Self::PaymentCard => "payment card number",
            Self::BankAccount => "bank account number",
            Self::RoutingNumber => "routing number",
            Self::DriversLicence => "driver's licence number",
            Self::Passport => "passport number",
            Self::MedicalRecordNumber => "medical record number",
            Self::HealthInsuranceId => "health insurance ID",
        }
    }

    /// True when a value of this kind, on its own, points at a specific person.
    ///
    /// A row needs at least one such element to become a person record: a date of birth
    /// and a state alone do not say who was affected.
    #[must_use]
    pub const fn identifies_person(self) -> bool {
        !matches!(
            self,
            Self::DateOfBirth
                | Self::Address
                | Self::City
                | Self::State
                | Self::PostalCode
                | Self::Country
                | Self::RoutingNumber
        )
    }

    /// True for identifiers that exports mask unless full values are requested.
    #[must_use]
    pub const fn is_secret(self) -> bool {
        matches!(
            self,
            Self::Ssn
                | Self::PaymentCard
                | Self::BankAccount
                | Self::DriversLicence
                | Self::Passport
                | Self::MedicalRecordNumber
                | Self::HealthInsuranceId
        )
    }
}

impl std::fmt::Display for ElementKind {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// One sheet or delimited file, kept as rows and cells.
///
/// `rows[r][c]` is the cell at zero-based sheet row `first_row + r` and column
/// `first_column + c`. Blank rows are kept so coordinates match the source.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Table {
    /// Sheet name for workbooks; `None` for single-table files.
    pub scope: Option<String>,
    pub first_row: u32,
    pub first_column: u32,
    pub rows: Vec<Vec<String>>,
}

/// How a column came to be treated as a given element.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Method {
    /// The column header named the element.
    Header,
    /// No usable header; the cell values themselves matched a strict format.
    Content,
}

impl Method {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Header => "header",
            Self::Content => "content",
        }
    }

    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "header" => Some(Self::Header),
            "content" => Some(Self::Content),
            _ => None,
        }
    }
}

/// One data element seen for one person at one place in the evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Observation {
    pub kind: ElementKind,
    /// The cell text exactly as extracted.
    pub raw: String,
    /// Canonical form used for comparison and export.
    pub normalized: String,
    /// False when the value failed the format or checksum rules for its kind.
    pub valid: bool,
    /// Zero-based column in the source sheet.
    pub column: u32,
    pub header: Option<String>,
    pub method: Method,
}

/// The data elements one table row holds about one person.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersonRecord {
    pub scope: Option<String>,
    /// Zero-based row in the source sheet.
    pub row: u32,
    /// `None` for the row's main subject; otherwise the related person the columns
    /// describe, such as `spouse` or `emergency contact`.
    pub relation: Option<String>,
    pub observations: Vec<Observation>,
}

/// Why part of the evidence did not contribute person records.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GapKind {
    /// The file type is not read by this version.
    Unsupported,
    /// The file or sheet could not be opened or parsed.
    Unreadable,
    /// Reading stopped at a size or row limit.
    Truncated,
    /// A table was read but none of its columns were recognised as personal data.
    Unrecognised,
    /// A file ingested earlier is no longer in the evidence folder.
    Missing,
}

impl GapKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unsupported => "unsupported",
            Self::Unreadable => "unreadable",
            Self::Truncated => "truncated",
            Self::Unrecognised => "unrecognised",
            Self::Missing => "missing",
        }
    }

    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        [
            Self::Unsupported,
            Self::Unreadable,
            Self::Truncated,
            Self::Unrecognised,
            Self::Missing,
        ]
        .into_iter()
        .find(|kind| kind.as_str() == value)
    }
}

/// Evidence that was not, or not fully, turned into person records.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoverageGap {
    pub scope: Option<String>,
    pub kind: GapKind,
    pub detail: String,
}

impl CoverageGap {
    #[must_use]
    pub fn new(scope: Option<String>, kind: GapKind, detail: impl Into<String>) -> Self {
        Self {
            scope,
            kind,
            detail: detail.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn element_identifiers_round_trip() {
        for kind in ElementKind::ALL {
            assert_eq!(ElementKind::parse(kind.as_str()), Some(kind));
        }
        assert_eq!(ElementKind::parse("wallet"), None);
    }

    #[test]
    fn contact_details_alone_do_not_identify_a_person() {
        assert!(ElementKind::Ssn.identifies_person());
        assert!(ElementKind::Name.identifies_person());
        assert!(!ElementKind::State.identifies_person());
        assert!(!ElementKind::DateOfBirth.identifies_person());
    }
}
