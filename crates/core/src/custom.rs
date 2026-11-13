//! Declarative organization-specific detection rules.
//!
//! Rules are data, not executable plugins. They use linear-time Rust regular expressions
//! and cannot perform network requests, filesystem access, or credential validation.

use regex::{Regex, RegexBuilder};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::EntityType;
use crate::detectors::EntitySpan;

const MAX_RULES: usize = 128;
const MAX_PATTERN_BYTES: usize = 4_096;
const MAX_NAME_BYTES: usize = 80;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CustomRule {
    pub name: String,
    pub pattern: String,
    #[serde(rename = "type")]
    pub entity_type: EntityType,
    #[serde(default = "default_confidence")]
    pub confidence: f32,
    #[serde(default)]
    pub case_insensitive: bool,
    #[serde(default = "default_true")]
    pub whole_word: bool,
    /// Zero selects the whole match; a positive value selects that capture group.
    #[serde(default)]
    pub capture_group: usize,
}

const fn default_confidence() -> f32 {
    0.75
}

const fn default_true() -> bool {
    true
}

#[derive(Debug, Error)]
pub enum CustomRuleError {
    #[error("At most {MAX_RULES} custom rules are supported.")]
    TooMany,
    #[error("Custom rule {index} has an empty or oversized name/pattern.")]
    InvalidText { index: usize },
    #[error("Custom rule '{name}' has a confidence outside 0..=1.")]
    InvalidConfidence { name: String },
    #[error("Custom rule '{name}' contains unsupported or oversized regex syntax: {reason}")]
    InvalidRegex { name: String, reason: String },
    #[error("Custom rule names must be unique.")]
    DuplicateName,
}

#[derive(Debug, Default)]
pub struct CustomDetector {
    rules: Vec<CompiledRule>,
}

#[derive(Debug)]
struct CompiledRule {
    name: String,
    regex: Regex,
    entity_type: EntityType,
    confidence: f32,
    whole_word: bool,
    capture_group: usize,
}

impl CustomDetector {
    pub fn new(rules: &[CustomRule]) -> Result<Self, CustomRuleError> {
        if rules.len() > MAX_RULES {
            return Err(CustomRuleError::TooMany);
        }
        let mut names = std::collections::HashSet::with_capacity(rules.len());
        let mut compiled = Vec::with_capacity(rules.len());
        for (index, rule) in rules.iter().enumerate() {
            if rule.name.trim().is_empty()
                || rule.name.len() > MAX_NAME_BYTES
                || rule.name.chars().any(char::is_control)
                || rule.pattern.is_empty()
                || rule.pattern.len() > MAX_PATTERN_BYTES
            {
                return Err(CustomRuleError::InvalidText { index });
            }
            if !names.insert(rule.name.as_str()) {
                return Err(CustomRuleError::DuplicateName);
            }
            if !rule.confidence.is_finite() || !(0.0..=1.0).contains(&rule.confidence) {
                return Err(CustomRuleError::InvalidConfidence {
                    name: rule.name.clone(),
                });
            }
            let regex = RegexBuilder::new(&rule.pattern)
                .case_insensitive(rule.case_insensitive)
                .unicode(true)
                .size_limit(1 << 20)
                .dfa_size_limit(2 << 20)
                .build()
                .map_err(|error| CustomRuleError::InvalidRegex {
                    name: rule.name.clone(),
                    reason: error.to_string(),
                })?;
            if rule.capture_group > regex.captures_len().saturating_sub(1) {
                return Err(CustomRuleError::InvalidRegex {
                    name: rule.name.clone(),
                    reason: format!("capture group {} does not exist", rule.capture_group),
                });
            }
            compiled.push(CompiledRule {
                name: rule.name.clone(),
                regex,
                entity_type: rule.entity_type,
                confidence: rule.confidence,
                whole_word: rule.whole_word,
                capture_group: rule.capture_group,
            });
        }
        Ok(Self { rules: compiled })
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    #[must_use]
    pub fn detect(&self, text: &str) -> Vec<EntitySpan> {
        let mut spans = Vec::new();
        for rule in &self.rules {
            for captures in rule.regex.captures_iter(text) {
                let Some(matched) = captures.get(rule.capture_group) else {
                    continue;
                };
                if matched.is_empty()
                    || (rule.whole_word
                        && !has_word_boundaries(text, matched.start(), matched.end()))
                {
                    continue;
                }
                spans.push(EntitySpan::new(
                    rule.entity_type,
                    matched.start(),
                    matched.len(),
                    rule.confidence,
                    format!("custom:{}", rule.name),
                ));
            }
        }
        spans
    }
}

fn has_word_boundaries(text: &str, start: usize, end: usize) -> bool {
    let before = text[..start].chars().next_back();
    let after = text[end..].chars().next();
    !before.is_some_and(is_word_character) && !after.is_some_and(is_word_character)
}

fn is_word_character(character: char) -> bool {
    character.is_alphanumeric() || character == '_'
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(pattern: &str) -> CustomRule {
        CustomRule {
            name: "engagement-id".into(),
            pattern: pattern.into(),
            entity_type: EntityType::LabelledIdentifier,
            confidence: 0.8,
            case_insensitive: false,
            whole_word: true,
            capture_group: 0,
        }
    }

    #[test]
    fn detects_organization_identifiers_with_byte_offsets() {
        let detector = CustomDetector::new(&[rule(r"ENG-[0-9]{6}")]).expect("valid rule");
        let spans = detector.detect("Case: 😀 ENG-123456 and ENG-123456");
        assert_eq!(spans.len(), 2);
        assert_eq!(
            &"Case: 😀 ENG-123456 and ENG-123456"[spans[0].start..spans[0].start + spans[0].length],
            "ENG-123456"
        );
        assert_eq!(spans[0].method, "custom:engagement-id");
    }

    #[test]
    fn capture_group_and_word_boundaries_are_explicit() {
        let mut custom = rule(r"employee=([A-Z]{2}[0-9]{4})");
        custom.capture_group = 1;
        let detector = CustomDetector::new(&[custom]).expect("valid rule");
        let spans = detector.detect("employee=AB1234; XENG-123456");
        assert_eq!(spans.len(), 1);
        assert_eq!(spans[0].length, 6);
    }

    #[test]
    fn rejects_executable_or_pathological_configuration() {
        assert!(CustomDetector::new(&[rule(r"(?=a)b")]).is_err());
        assert!(CustomDetector::new(&[rule(r"(a)\1")]).is_err());
        let mut invalid = rule("abc");
        invalid.confidence = f32::NAN;
        assert!(CustomDetector::new(&[invalid]).is_err());
    }

    #[test]
    fn empty_rules_do_no_work() {
        let detector = CustomDetector::default();
        assert!(detector.is_empty());
        assert!(detector.detect("anything").is_empty());
    }
}
