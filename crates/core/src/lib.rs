#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used))]
//! PII Explorer's local detection, extraction, scanning, and reporting engine.

pub mod custom;
pub mod detectors;
pub mod evaluation;
pub mod extract;
pub mod hash;
pub mod model;
#[cfg(feature = "report")]
pub mod report;
pub mod scanner;
pub mod storage;
pub mod text;
pub mod verify;

pub use model::*;
pub use scanner::{ScanError, ScanEvent, Scanner};
pub use text::Utf16Index;

pub const ENGINE_VERSION: &str = env!("CARGO_PKG_VERSION");
