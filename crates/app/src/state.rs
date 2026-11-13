use std::collections::HashMap;

use pii_explorer_core::scanner::ScanEvent;
use pii_explorer_core::{ScanProgress, ScanResult, SourceRecord};

use crate::filter::{FindingFilter, attention_indices, finding_indices};

/// In-memory review state. Nothing here is persisted by the application.
#[derive(Debug, Default)]
pub struct ReviewState {
    pub result: ScanResult,
    pub progress: ScanProgress,
    pub visible_findings: Vec<usize>,
    pub visible_attention: Vec<usize>,
    source_indices: HashMap<String, usize>,
}

impl ReviewState {
    pub fn reset(&mut self) {
        self.result = ScanResult::default();
        self.progress = ScanProgress::default();
        self.visible_findings.clear();
        self.visible_attention.clear();
        self.source_indices.clear();
    }

    pub fn apply_event(&mut self, event: ScanEvent, filter: &FindingFilter) {
        match event {
            ScanEvent::Findings(batch) => {
                let first = self.result.findings.len();
                self.visible_findings
                    .extend(batch.iter().enumerate().filter_map(|(offset, finding)| {
                        filter.matches_finding(finding).then_some(first + offset)
                    }));
                self.result.findings.extend(batch);
            }
            ScanEvent::Attention(batch) => {
                let first = self.result.attention.len();
                self.visible_attention
                    .extend(batch.iter().enumerate().filter_map(|(offset, item)| {
                        filter.matches_attention(item).then_some(first + offset)
                    }));
                self.result.attention.extend(batch);
            }
            ScanEvent::Progress(progress) => self.progress = progress,
            ScanEvent::Sources(sources) => {
                for source in sources {
                    self.source_indices
                        .insert(source.resource_id.clone(), self.result.sources.len());
                    self.result.sources.push(source);
                }
            }
        }
    }

    pub fn finish(&mut self, result: ScanResult, filter: &FindingFilter) {
        self.progress = ScanProgress {
            discovered: result.summary.discovered,
            completed: result.summary.completed,
            findings: result.summary.findings,
            attention: result.summary.attention,
        };
        self.result = result;
        self.rebuild_source_index();
        self.refilter(filter);
    }

    pub fn refilter(&mut self, filter: &FindingFilter) {
        self.visible_findings = finding_indices(&self.result.findings, filter);
        self.visible_attention = attention_indices(&self.result.attention, filter);
    }

    #[must_use]
    pub fn source(&self, resource_id: &str) -> Option<&SourceRecord> {
        self.source_indices
            .get(resource_id)
            .and_then(|index| self.result.sources.get(*index))
    }

    fn rebuild_source_index(&mut self) {
        self.source_indices.clear();
        self.source_indices.reserve(self.result.sources.len());
        for (index, source) in self.result.sources.iter().enumerate() {
            self.source_indices
                .entry(source.resource_id.clone())
                .or_insert(index);
        }
    }
}

#[cfg(test)]
mod tests {
    use pii_explorer_core::{
        AttentionItem, CoordinateUnit, EntityType, EvidenceOrigin, Finding, ScanOptions,
        ScanSummary,
    };

    use super::*;

    fn finding(value: &str) -> Finding {
        Finding {
            entity_type: EntityType::Email,
            value: value.into(),
            start: 0,
            length: value.len() as u64,
            context: value.into(),
            context_start: 0,
            detector_start: 0,
            detector_length: value.len() as u64,
            confidence: 1.0,
            method: "pattern".into(),
            origin: EvidenceOrigin {
                resource_id: "file.txt".into(),
                stream_id: "body".into(),
                kind: pii_explorer_core::EvidenceKind::Body,
                representation: "decoded-text".into(),
                chunk_start: 0,
                coordinate_unit: CoordinateUnit::Utf16CodeUnits,
                stride: 1,
            },
        }
    }

    #[test]
    fn live_batches_update_all_and_filtered_views() {
        let mut state = ReviewState::default();
        let filter = FindingFilter::new("alice", None);
        state.apply_event(
            ScanEvent::Findings(vec![
                finding("alice@example.com"),
                finding("bob@example.com"),
            ]),
            &filter,
        );
        state.apply_event(
            ScanEvent::Findings(vec![finding("ALICE@example.org")]),
            &filter,
        );
        assert_eq!(state.result.findings.len(), 3);
        assert_eq!(state.visible_findings, [0, 2]);

        state.apply_event(
            ScanEvent::Attention(vec![AttentionItem {
                resource_id: "alice.txt".into(),
                message: "Unreadable".into(),
            }]),
            &filter,
        );
        assert_eq!(state.visible_attention, [0]);
    }

    #[test]
    fn final_result_replaces_streamed_copies_and_indexes_hashes() {
        let mut state = ReviewState::default();
        state.apply_event(
            ScanEvent::Findings(vec![finding("old@example.com")]),
            &FindingFilter::default(),
        );
        let result = ScanResult {
            findings: vec![finding("new@example.com")],
            attention: Vec::new(),
            sources: vec![SourceRecord {
                resource_id: "file.txt".into(),
                size: 42,
                sha256: Some("abc123".into()),
            }],
            settings: ScanOptions::default(),
            summary: ScanSummary {
                discovered: 1,
                completed: 1,
                findings: 1,
                attention: 0,
                cancelled: false,
                limit_reached: None,
                elapsed_ms: 5,
            },
        };
        state.finish(result, &FindingFilter::default());
        assert_eq!(state.result.findings[0].value, "new@example.com");
        assert_eq!(state.visible_findings, [0]);
        assert_eq!(state.progress.completed, 1);
        assert_eq!(
            state
                .source("file.txt")
                .and_then(|source| source.sha256.as_deref()),
            Some("abc123")
        );
    }

    #[test]
    fn refilter_and_reset_do_not_mix_generations() {
        let mut state = ReviewState::default();
        state.apply_event(
            ScanEvent::Findings(vec![
                finding("alice@example.com"),
                finding("bob@example.com"),
            ]),
            &FindingFilter::default(),
        );
        state.refilter(&FindingFilter::new("bob", None));
        assert_eq!(state.visible_findings, [1]);
        state.reset();
        assert!(state.result.findings.is_empty());
        assert!(state.visible_findings.is_empty());
        assert!(state.source("file.txt").is_none());
    }
}
