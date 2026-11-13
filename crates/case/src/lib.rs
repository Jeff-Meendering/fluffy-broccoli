//! The case: a single SQLite file holding everything learned about a breach dataset.
//!
//! A case records every evidence file by content hash, the person records found in it,
//! and every gap in coverage. Ingest can be repeated: unchanged files are not read
//! again, changed files replace their earlier records.

mod export;
mod ingest;
mod store;

pub use export::{PersonSummary, Values, export_csv, summarise};
pub use ingest::{IngestOptions, IngestSummary, ingest};
pub use store::{Case, Counts, StoredDocument, StoredGap, StoredRecord};
