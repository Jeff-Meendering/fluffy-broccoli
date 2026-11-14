//! Bounded, local extraction from documents, archives, images, and binary strings.

#[cfg(feature = "archives")]
pub mod archive;
#[cfg(not(feature = "archives"))]
pub mod archive {
    use super::ExtractionContext;
    use crate::{AttentionItem, Extraction};

    pub fn extract(
        name: &str,
        _data: &[u8],
        _depth: usize,
        _context: &ExtractionContext,
    ) -> Extraction {
        Extraction {
            partial: true,
            attention: vec![AttentionItem {
                resource_id: name.into(),
                message: "Archive support was not compiled in; archive content was not checked."
                    .into(),
            }],
            ..Extraction::default()
        }
    }
}
pub mod binary;
pub mod document;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::time::Instant;

use crate::{Extraction, ScanOptions};

/// Extraction can run in a separate process without moving detection or evidence storage
/// into the parser's address space. Implementations must report incomplete work explicitly.
pub trait Extractor: Send + Sync {
    fn extract(&self, name: &str, data: &[u8], context: &ExtractionContext) -> Extraction;
}

pub struct NativeExtractor;

impl Extractor for NativeExtractor {
    fn extract(&self, name: &str, data: &[u8], context: &ExtractionContext) -> Extraction {
        extract_bytes(name, data, context)
    }
}

#[derive(Debug, Clone)]
pub struct ExtractionContext {
    pub options: Arc<ScanOptions>,
    cancelled: Arc<AtomicBool>,
    deadline: Option<Instant>,
    archive_bytes: Arc<AtomicU64>,
    archive_members: Arc<AtomicUsize>,
    extracted_utf16: Arc<AtomicUsize>,
}

impl ExtractionContext {
    #[must_use]
    pub fn for_root(options: Arc<ScanOptions>, cancelled: Arc<AtomicBool>) -> Self {
        let deadline = Instant::now().checked_add(options.file_timeout);
        Self {
            options,
            cancelled,
            deadline,
            archive_bytes: Arc::new(AtomicU64::new(0)),
            archive_members: Arc::new(AtomicUsize::new(0)),
            extracted_utf16: Arc::new(AtomicUsize::new(0)),
        }
    }

    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Relaxed)
            || self
                .deadline
                .is_some_and(|deadline| Instant::now() >= deadline)
    }

    #[must_use]
    pub const fn deadline(&self) -> Option<Instant> {
        self.deadline
    }

    #[must_use]
    pub fn remaining_time(&self) -> Option<std::time::Duration> {
        self.deadline
            .map(|deadline| deadline.saturating_duration_since(Instant::now()))
    }

    pub fn reserve_archive_member(&self) -> bool {
        reserve_atomic(
            &self.archive_members,
            1,
            self.options.max_archive_members,
            Ordering::Relaxed,
        )
    }

    pub fn reserve_archive_bytes(&self, bytes: u64) -> bool {
        let Ok(bytes) = usize::try_from(bytes) else {
            return false;
        };
        let previous = self
            .archive_bytes
            .fetch_add(bytes as u64, Ordering::Relaxed);
        if previous.saturating_add(bytes as u64) > self.options.max_archive_bytes {
            self.archive_bytes
                .fetch_sub(bytes as u64, Ordering::Relaxed);
            false
        } else {
            true
        }
    }

    pub fn reserve_extracted_utf16(&self, units: usize) -> bool {
        reserve_atomic(
            &self.extracted_utf16,
            units,
            self.options.max_extracted_utf16,
            Ordering::Relaxed,
        )
    }
}

fn reserve_atomic(counter: &AtomicUsize, amount: usize, limit: usize, ordering: Ordering) -> bool {
    let mut previous = counter.load(ordering);
    loop {
        let Some(next) = previous.checked_add(amount).filter(|next| *next <= limit) else {
            return false;
        };
        match counter.compare_exchange_weak(previous, next, ordering, ordering) {
            Ok(_) => return true,
            Err(actual) => previous = actual,
        }
    }
}

/// Extract one in-memory resource. Archive members recurse through this same entry point
/// and share the root resource's budgets and cancellation state.
pub fn extract_bytes(name: &str, data: &[u8], context: &ExtractionContext) -> Extraction {
    extract_bytes_at(name, data, 0, context)
}

pub fn extract_bytes_at(
    name: &str,
    data: &[u8],
    archive_depth: usize,
    context: &ExtractionContext,
) -> Extraction {
    if context.is_cancelled() {
        return Extraction {
            attention: vec![crate::AttentionItem {
                resource_id: name.to_owned(),
                message: "Extraction cancelled or timed out; content was not fully checked.".into(),
            }],
            ..Extraction::default()
        };
    }
    document::extract_at(name, data, archive_depth, context)
}
