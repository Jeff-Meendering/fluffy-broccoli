use pii_explorer_core::{AttentionItem, EntityType, Finding};

/// A prepared, case-insensitive filter shared by the findings and attention tabs.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FindingFilter {
    query: String,
    entity_type: Option<EntityType>,
}

impl FindingFilter {
    #[must_use]
    pub fn new(query: &str, entity_type: Option<EntityType>) -> Self {
        Self {
            query: query.trim().to_lowercase(),
            entity_type,
        }
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.query.is_empty() && self.entity_type.is_none()
    }

    #[must_use]
    pub fn matches_finding(&self, finding: &Finding) -> bool {
        if self
            .entity_type
            .is_some_and(|kind| kind != finding.entity_type)
        {
            return false;
        }
        self.query.is_empty()
            || [
                finding.value.as_str(),
                finding.context.as_str(),
                finding.method.as_str(),
                finding.origin.resource_id.as_str(),
                finding.origin.stream_id.as_str(),
                finding.origin.representation.as_str(),
            ]
            .into_iter()
            .any(|text| contains_case_insensitive(text, &self.query))
    }

    #[must_use]
    pub fn matches_attention(&self, item: &AttentionItem) -> bool {
        self.query.is_empty()
            || contains_case_insensitive(&item.resource_id, &self.query)
            || contains_case_insensitive(&item.message, &self.query)
    }
}

#[must_use]
pub fn finding_indices(findings: &[Finding], filter: &FindingFilter) -> Vec<usize> {
    findings
        .iter()
        .enumerate()
        .filter_map(|(index, finding)| filter.matches_finding(finding).then_some(index))
        .collect()
}

#[must_use]
pub fn attention_indices(items: &[AttentionItem], filter: &FindingFilter) -> Vec<usize> {
    items
        .iter()
        .enumerate()
        .filter_map(|(index, item)| filter.matches_attention(item).then_some(index))
        .collect()
}

fn contains_case_insensitive(text: &str, folded_query: &str) -> bool {
    text.to_lowercase().contains(folded_query)
}

#[cfg(test)]
mod tests {
    use pii_explorer_core::{EvidenceKind, EvidenceOrigin};

    use super::*;

    fn finding(entity_type: EntityType, value: &str) -> Finding {
        Finding {
            entity_type,
            value: value.into(),
            start: 3,
            length: value.len() as u64,
            context: "Surrounding EVIDENCE text".into(),
            context_start: 0,
            detector_start: 3,
            detector_length: value.len() as u64,
            confidence: 0.75,
            method: "Pattern / context match".into(),
            origin: EvidenceOrigin {
                resource_id: "Records/Report.TXT".into(),
                stream_id: "archive:member.txt".into(),
                kind: EvidenceKind::Body,
                representation: "parsed-text".into(),
                chunk_start: 0,
                coordinate_unit: pii_explorer_core::CoordinateUnit::Utf16CodeUnits,
                stride: 1,
            },
        }
    }

    #[test]
    fn empty_filter_matches_everything() {
        let filter = FindingFilter::default();
        assert!(filter.matches_finding(&finding(EntityType::Email, "a@example.com")));
        assert!(filter.matches_attention(&AttentionItem {
            resource_id: "file.txt".into(),
            message: "Unreadable".into(),
        }));
        assert!(filter.is_empty());
    }

    #[test]
    fn finding_filter_searches_all_evidence_text_without_case_sensitivity() {
        let finding = finding(EntityType::Email, "Alice@Example.COM");
        for query in [
            "alice@example.com",
            "evidence",
            "records/report",
            "ARCHIVE:MEMBER",
            "CONTEXT MATCH",
        ] {
            assert!(
                FindingFilter::new(query, None).matches_finding(&finding),
                "query: {query}"
            );
        }
        assert!(!FindingFilter::new("missing", None).matches_finding(&finding));
    }

    #[test]
    fn entity_and_text_filters_are_combined() {
        let finding = finding(EntityType::Email, "alice@example.com");
        assert!(FindingFilter::new("alice", Some(EntityType::Email)).matches_finding(&finding));
        assert!(!FindingFilter::new("alice", Some(EntityType::Person)).matches_finding(&finding));
        assert!(!FindingFilter::new("", Some(EntityType::Person)).matches_finding(&finding));
    }

    #[test]
    fn attention_filter_checks_source_and_message() {
        let item = AttentionItem {
            resource_id: "Docs/Scanned.PDF".into(),
            message: "OCR timed OUT".into(),
        };
        assert!(FindingFilter::new("scanned.pdf", None).matches_attention(&item));
        assert!(FindingFilter::new("timed out", None).matches_attention(&item));
        assert!(!FindingFilter::new("missing", Some(EntityType::Email)).matches_attention(&item));
    }

    #[test]
    fn filtered_indices_refer_to_unfiltered_source_vectors() {
        let findings = vec![
            finding(EntityType::Email, "alice@example.com"),
            finding(EntityType::Phone, "+1 202 555 0100"),
            finding(EntityType::Email, "bob@example.com"),
        ];
        let indices = finding_indices(
            &findings,
            &FindingFilter::new("example", Some(EntityType::Email)),
        );
        assert_eq!(indices, [0, 2]);
    }
}
