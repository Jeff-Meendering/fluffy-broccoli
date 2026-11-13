//! The notification list: one row per person record, with the elements exposed.

use std::collections::BTreeMap;
use std::io::Write;

use anyhow::Result;
use rollcall_extract::delimited::write_row;
use rollcall_model::ElementKind;

use crate::store::{Case, StoredRecord};

/// Whether sensitive identifiers are written in full or reduced to their last digits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Values {
    Masked,
    Full,
}

/// What one person record exposes, ready for display.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersonSummary {
    /// Distinct valid values per element, in the order they were seen.
    pub values: BTreeMap<ElementKind, Vec<String>>,
    /// Elements with a value that failed validation and needs a person to look at it.
    pub needs_review: Vec<ElementKind>,
}

impl PersonSummary {
    #[must_use]
    pub fn name(&self) -> &str {
        self.values
            .get(&ElementKind::Name)
            .and_then(|names| names.first())
            .map_or("", String::as_str)
    }

    /// The kinds of element this record exposes with a valid value.
    #[must_use]
    pub fn exposed(&self) -> Vec<ElementKind> {
        self.values.keys().copied().collect()
    }
}

#[must_use]
pub fn summarise(record: &StoredRecord) -> PersonSummary {
    let mut summary = PersonSummary {
        values: BTreeMap::new(),
        needs_review: Vec::new(),
    };
    for observation in &record.observations {
        if observation.valid {
            let values = summary.values.entry(observation.kind).or_default();
            if !values.contains(&observation.normalized) {
                values.push(observation.normalized.clone());
            }
        } else if !summary.needs_review.contains(&observation.kind) {
            summary.needs_review.push(observation.kind);
        }
    }
    summary
}

/// Hides all but the last four characters of a sensitive identifier.
#[must_use]
pub fn mask(kind: ElementKind, value: &str, values: Values) -> String {
    if values == Values::Full || !kind.is_secret() {
        return value.to_owned();
    }
    let length = value.chars().count();
    // Too short to show part of without showing most of it.
    let visible_from = if length > 4 { length - 4 } else { length };
    value
        .chars()
        .enumerate()
        .map(|(index, character)| {
            if index >= visible_from || !character.is_alphanumeric() {
                character
            } else {
                '*'
            }
        })
        .collect()
}

/// Stops a spreadsheet from running a cell as a formula when the list is opened.
///
/// Evidence is hostile input: a "name" of `=HYPERLINK(...)` must stay text.
fn spreadsheet_safe(field: String) -> String {
    if field.starts_with(['=', '+', '-', '@', '\t', '\r']) {
        format!("'{field}")
    } else {
        field
    }
}

/// Writes the notification list as CSV and returns the number of person rows.
pub fn export_csv(case: &Case, output: &mut impl Write, values: Values) -> Result<u64> {
    let element_columns: Vec<ElementKind> = ElementKind::ALL
        .into_iter()
        .filter(|kind| *kind != ElementKind::Name)
        .collect();
    let mut header = vec!["record_id", "name", "relation", "exposed_elements"];
    header.extend(element_columns.iter().map(|kind| kind.as_str()));
    header.extend([
        "source_file",
        "source_sheet",
        "source_row",
        "source_sha256",
        "needs_review",
    ]);
    let mut line = String::new();
    write_row(&mut line, &header, ',');
    output.write_all(line.as_bytes())?;

    let mut rows = 0_u64;
    case.for_each_record(|record| {
        let summary = summarise(&record);
        let joined = |kinds: &[ElementKind]| {
            kinds
                .iter()
                .map(|kind| kind.as_str())
                .collect::<Vec<_>>()
                .join("; ")
        };
        let mut fields = vec![
            record.id.to_string(),
            summary.name().to_owned(),
            record.relation.clone().unwrap_or_default(),
            joined(&summary.exposed()),
        ];
        for kind in &element_columns {
            let shown: Vec<String> = summary
                .values
                .get(kind)
                .map(|found| {
                    found
                        .iter()
                        .map(|value| mask(*kind, value, values))
                        .collect()
                })
                .unwrap_or_default();
            fields.push(shown.join(" | "));
        }
        fields.extend([
            record.path.clone(),
            record.scope.clone().unwrap_or_default(),
            // Rows are stored zero-based; people count them from one.
            (u64::from(record.row) + 1).to_string(),
            record.sha256.clone().unwrap_or_default(),
            joined(&summary.needs_review),
        ]);
        let fields: Vec<String> = fields.into_iter().map(spreadsheet_safe).collect();
        line.clear();
        write_row(&mut line, &fields, ',');
        output.write_all(line.as_bytes())?;
        rows += 1;
        Ok(())
    })?;
    output.flush()?;
    Ok(rows)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn masks_sensitive_identifiers_but_not_contact_details() {
        assert_eq!(
            mask(ElementKind::Ssn, "219-09-9999", Values::Masked),
            "***-**-9999"
        );
        assert_eq!(
            mask(ElementKind::PaymentCard, "4111111111111111", Values::Masked),
            "************1111"
        );
        assert_eq!(mask(ElementKind::Passport, "X12", Values::Masked), "***");
        assert_eq!(
            mask(ElementKind::Email, "a@example.com", Values::Masked),
            "a@example.com"
        );
        assert_eq!(
            mask(ElementKind::Ssn, "219-09-9999", Values::Full),
            "219-09-9999"
        );
    }

    #[test]
    fn formula_like_cells_are_neutralised() {
        assert_eq!(
            spreadsheet_safe("=HYPERLINK(\"x\")".to_owned()),
            "'=HYPERLINK(\"x\")"
        );
        assert_eq!(spreadsheet_safe("+14155550134".to_owned()), "'+14155550134");
        assert_eq!(spreadsheet_safe("Jane Doe".to_owned()), "Jane Doe");
    }
}
