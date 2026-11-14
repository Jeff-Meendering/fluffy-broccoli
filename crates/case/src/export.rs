//! The notification list, by person or by source record.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::io::Write;

use anyhow::Result;
use rollcall_extract::delimited::write_row;
use rollcall_model::ElementKind;
use sha2::{Digest, Sha256};

use crate::store::{Case, StoredRecord};

/// Whether sensitive identifiers are written in full or reduced to their last digits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Values {
    Masked,
    Full,
}

/// What is exposed for one person, or in one record, ready for display.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersonSummary {
    /// Distinct valid values per element. Names are ordered most used first.
    pub values: BTreeMap<ElementKind, Vec<String>>,
    /// Elements with a value that failed validation and needs a person to look at it.
    pub needs_review: Vec<ElementKind>,
}

impl PersonSummary {
    /// The name the person is most often recorded under; empty when there is none.
    #[must_use]
    pub fn name(&self) -> &str {
        self.names().first().map_or("", String::as_str)
    }

    fn names(&self) -> &[String] {
        self.values
            .get(&ElementKind::Name)
            .map_or(&[], Vec::as_slice)
    }

    /// The kinds of element exposed with a valid value.
    #[must_use]
    pub fn exposed(&self) -> Vec<ElementKind> {
        self.values.keys().copied().collect()
    }
}

/// Summarises one record.
#[must_use]
pub fn summarise(record: &StoredRecord) -> PersonSummary {
    summarise_person(std::slice::from_ref(record))
}

/// Summarises everything recorded about one person across their records.
#[must_use]
pub fn summarise_person(records: &[StoredRecord]) -> PersonSummary {
    let mut summary = PersonSummary {
        values: BTreeMap::new(),
        needs_review: Vec::new(),
    };
    let mut name_uses: HashMap<String, usize> = HashMap::new();
    for observation in records.iter().flat_map(|record| &record.observations) {
        if observation.valid {
            if observation.kind == ElementKind::Name {
                *name_uses
                    .entry(observation.normalized.to_lowercase())
                    .or_default() += 1;
            }
            let values = summary.values.entry(observation.kind).or_default();
            let seen = values.iter().any(|value| {
                // A name written in another letter case is the same name.
                observation.kind == ElementKind::Name
                    && value.eq_ignore_ascii_case(&observation.normalized)
                    || *value == observation.normalized
            });
            if !seen {
                values.push(observation.normalized.clone());
            }
        } else if !summary.needs_review.contains(&observation.kind) {
            summary.needs_review.push(observation.kind);
        }
    }
    if let Some(names) = summary.values.get_mut(&ElementKind::Name) {
        // Most used first; among equals the fuller name, then the one seen first.
        names.sort_by_key(|name| {
            let uses = name_uses.get(&name.to_lowercase()).copied().unwrap_or(0);
            (
                std::cmp::Reverse(uses),
                std::cmp::Reverse(name.chars().count()),
            )
        });
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

fn element_columns() -> Vec<ElementKind> {
    ElementKind::ALL
        .into_iter()
        .filter(|kind| *kind != ElementKind::Name)
        .collect()
}

fn kind_list(kinds: &[ElementKind]) -> String {
    kinds
        .iter()
        .map(|kind| kind.as_str())
        .collect::<Vec<_>>()
        .join("; ")
}

fn element_fields(summary: &PersonSummary, values: Values) -> impl Iterator<Item = String> {
    element_columns().into_iter().map(move |kind| {
        summary
            .values
            .get(&kind)
            .map(|found| {
                found
                    .iter()
                    .map(|value| mask(kind, value, values))
                    .collect::<Vec<_>>()
                    .join(" | ")
            })
            .unwrap_or_default()
    })
}

fn write_fields(output: &mut impl Write, line: &mut String, fields: Vec<String>) -> Result<()> {
    let fields: Vec<String> = fields.into_iter().map(spreadsheet_safe).collect();
    line.clear();
    write_row(line, &fields, ',');
    output.write_all(line.as_bytes())?;
    Ok(())
}

/// The most sources listed for one person before the rest are counted instead.
const SOURCES_SHOWN: usize = 25;

/// Writes the notification list, one row per person, and returns the number of rows.
///
/// Each row carries the union of what the person's records expose, where each record
/// came from, and any other person who may be the same individual.
pub fn export_people_csv(case: &Case, output: &mut impl Write, values: Values) -> Result<u64> {
    let mut possible: HashMap<i64, BTreeSet<i64>> = HashMap::new();
    for suggestion in case.suggestions()? {
        possible
            .entry(suggestion.person_a)
            .or_default()
            .insert(suggestion.person_b);
        possible
            .entry(suggestion.person_b)
            .or_default()
            .insert(suggestion.person_a);
    }

    let mut header = vec!["person_id", "name", "other_names", "exposed_elements"];
    let columns = element_columns();
    header.extend(columns.iter().map(|kind| kind.as_str()));
    header.extend(["records", "sources", "needs_review", "possible_duplicates"]);
    let mut line = String::new();
    write_fields(
        output,
        &mut line,
        header.into_iter().map(str::to_owned).collect(),
    )?;

    let mut rows = 0_u64;
    case.for_each_person(|person| {
        let summary = summarise_person(&person.records);
        let mut sources: Vec<String> = person
            .records
            .iter()
            .take(SOURCES_SHOWN)
            .map(StoredRecord::source)
            .collect();
        if person.records.len() > SOURCES_SHOWN {
            sources.push(format!("and {} more", person.records.len() - SOURCES_SHOWN));
        }
        let duplicates = possible
            .get(&person.id)
            .map(|others| {
                others
                    .iter()
                    .map(i64::to_string)
                    .collect::<Vec<_>>()
                    .join("; ")
            })
            .unwrap_or_default();
        let mut fields = vec![
            person.id.to_string(),
            summary.name().to_owned(),
            summary
                .names()
                .iter()
                .skip(1)
                .cloned()
                .collect::<Vec<_>>()
                .join(" | "),
            kind_list(&summary.exposed()),
        ];
        fields.extend(element_fields(&summary, values));
        fields.extend([
            person.records.len().to_string(),
            sources.join(" | "),
            kind_list(&summary.needs_review),
            duplicates,
        ]);
        write_fields(output, &mut line, fields)?;
        rows += 1;
        Ok(())
    })?;
    output.flush()?;
    Ok(rows)
}

/// Writes one row per source record, the evidence behind the people list, and returns
/// the number of rows.
pub fn export_records_csv(case: &Case, output: &mut impl Write, values: Values) -> Result<u64> {
    let mut header = vec![
        "record_id",
        "person_id",
        "name",
        "relation",
        "exposed_elements",
    ];
    let columns = element_columns();
    header.extend(columns.iter().map(|kind| kind.as_str()));
    header.extend([
        "source_file",
        "source_sheet",
        "source_row",
        "source_sha256",
        "needs_review",
    ]);
    let mut line = String::new();
    write_fields(
        output,
        &mut line,
        header.into_iter().map(str::to_owned).collect(),
    )?;

    let mut rows = 0_u64;
    case.for_each_record(|record| {
        let summary = summarise(&record);
        let mut fields = vec![
            record.id.to_string(),
            record.person.to_string(),
            summary.name().to_owned(),
            record.relation.clone().unwrap_or_default(),
            kind_list(&summary.exposed()),
        ];
        fields.extend(element_fields(&summary, values));
        fields.extend([
            record.path.clone(),
            record.scope.clone().unwrap_or_default(),
            // Rows are stored zero-based; people count them from one.
            (u64::from(record.row) + 1).to_string(),
            record.sha256.clone().unwrap_or_default(),
            kind_list(&summary.needs_review),
        ]);
        write_fields(output, &mut line, fields)?;
        rows += 1;
        Ok(())
    })?;
    output.flush()?;
    Ok(rows)
}

/// Passes bytes through to a writer while hashing them, so the audit log can name
/// exactly the list that was written.
pub struct HashingWriter<W> {
    inner: W,
    hasher: Sha256,
}

impl<W: Write> HashingWriter<W> {
    pub fn new(inner: W) -> Self {
        Self {
            inner,
            hasher: Sha256::new(),
        }
    }

    /// Flushes the writer and returns the SHA-256 of everything written, in hex.
    pub fn finish(mut self) -> std::io::Result<String> {
        self.inner.flush()?;
        Ok(self
            .hasher
            .finalize()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect())
    }
}

impl<W: Write> Write for HashingWriter<W> {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        let written = self.inner.write(buffer)?;
        self.hasher.update(&buffer[..written]);
        Ok(written)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

#[cfg(test)]
mod tests {
    use rollcall_model::{Method, Observation};

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

    fn record(id: i64, values: &[(ElementKind, &str, bool)]) -> StoredRecord {
        StoredRecord {
            id,
            person: 1,
            fingerprint: String::new(),
            path: "staff.csv".to_owned(),
            sha256: None,
            scope: None,
            row: 1,
            relation: None,
            observations: values
                .iter()
                .map(|(kind, value, valid)| Observation {
                    kind: *kind,
                    raw: (*value).to_owned(),
                    normalized: (*value).to_owned(),
                    valid: *valid,
                    column: 0,
                    header: None,
                    method: Method::Header,
                })
                .collect(),
        }
    }

    #[test]
    fn a_person_is_the_union_of_their_records_under_their_usual_name() {
        use ElementKind::{Email, Name, Ssn};
        let records = [
            record(
                1,
                &[(Name, "Bob Smith", true), (Email, "bob@example.com", true)],
            ),
            record(
                2,
                &[(Name, "Robert Smith", true), (Ssn, "219-09-9999", true)],
            ),
            record(
                3,
                &[
                    (Name, "ROBERT SMITH", true),
                    (Email, "bob@example.com", true),
                    (Ssn, "000", false),
                ],
            ),
        ];
        let summary = summarise_person(&records);
        assert_eq!(summary.name(), "Robert Smith");
        assert_eq!(summary.values[&Name], ["Robert Smith", "Bob Smith"]);
        assert_eq!(summary.values[&Email], ["bob@example.com"]);
        assert_eq!(summary.exposed(), [Name, Ssn, Email]);
        assert_eq!(summary.needs_review, [Ssn]);
    }

    #[test]
    fn the_hashing_writer_reports_the_hash_of_what_it_wrote() {
        let mut writer = HashingWriter::new(Vec::new());
        writer.write_all(b"abc").unwrap();
        assert_eq!(
            writer.finish().unwrap(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
