//! The case: a single SQLite file holding everything learned about a breach dataset.
//!
//! A case records every evidence file by content hash, the person records found in it,
//! the persons those records resolve to, a reviewer's rulings, every gap in coverage
//! and an audit log. Ingest can be repeated: unchanged files are not read again,
//! changed files replace their earlier records, and rulings carry over.

mod export;
mod ingest;
mod persons;
mod store;

pub use export::{
    HashingWriter, PersonSummary, Values, export_people_csv, export_records_csv, mask, summarise,
    summarise_person,
};
pub use ingest::{IngestOptions, IngestSummary, ingest};
pub use persons::{
    AuditCheck, AuditEntry, ResolveSummary, StoredDecision, StoredLink, StoredSuggestion,
};
pub use store::{Case, Counts, StoredDocument, StoredGap, StoredPerson, StoredRecord};
