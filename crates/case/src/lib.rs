#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used))]
//! Durable case storage and incremental local evidence scanning.

mod scan;
mod store;

pub use scan::{CaseScanOptions, scan_case};
pub use store::{CaseStore, CaseSummary, FindingPage, ReviewStatus};
