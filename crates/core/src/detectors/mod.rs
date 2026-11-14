//! PII detectors return UTF-8 byte spans; the scanner maps them to public UTF-16 offsets.

mod crypto;
pub mod names;
mod national_ids;
mod normalize;
mod pattern;

pub use pattern::PatternDetector;

use serde::{Deserialize, Serialize};

use crate::EntityType;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EntitySpan {
    #[serde(rename = "type")]
    pub entity_type: EntityType,
    pub start: usize,
    pub length: usize,
    pub confidence: f32,
    pub method: String,
}

impl EntitySpan {
    #[must_use]
    pub fn new(
        entity_type: EntityType,
        start: usize,
        length: usize,
        confidence: f32,
        method: impl Into<String>,
    ) -> Self {
        Self {
            entity_type,
            start,
            length,
            confidence,
            method: method.into(),
        }
    }
}
