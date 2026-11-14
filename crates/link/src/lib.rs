//! Links the data elements in one table row to the person they belong to.
//!
//! One row usually describes one person, but columns such as `Spouse SSN` or
//! `Emergency Contact Phone` describe someone else. Each such related person gets a
//! record of their own, so their data is never credited to the row's main subject.

mod text;

use rollcall_detect::{Column, Role, Schema, is_placeholder, normalize};

use rollcall_model::{ElementKind, Observation, PersonRecord, Table, Unit};
pub use text::link_text;

/// Builds the person records of one table from its recognised columns.
#[must_use]
pub fn link_table(table: &Table, schema: &Schema) -> Vec<PersonRecord> {
    // Columns grouped by the person they describe, main subject first.
    let mut groups: Vec<(Option<&str>, Vec<&Column>)> = Vec::new();
    for column in &schema.columns {
        let relation = column.relation.as_deref();
        match groups
            .iter_mut()
            .find(|(existing, _)| *existing == relation)
        {
            Some((_, columns)) => columns.push(column),
            None => groups.push((relation, vec![column])),
        }
    }
    groups.sort_by_key(|(relation, _)| relation.is_some());

    let mut records = Vec::new();
    for (offset, row) in table.rows.iter().enumerate().skip(schema.first_data_row()) {
        for (relation, columns) in &groups {
            let observations = observe(table, row, columns);
            if observations
                .iter()
                .any(|observation| observation.kind.identifies_person())
            {
                records.push(PersonRecord {
                    scope: table.scope.clone(),
                    row: table
                        .first_row
                        .saturating_add(u32::try_from(offset).unwrap_or(u32::MAX)),
                    unit: Unit::Row,
                    relation: relation.map(str::to_owned),
                    observations,
                });
            }
        }
    }
    records
}

fn observe(table: &Table, row: &[String], columns: &[&Column]) -> Vec<Observation> {
    let cell = |column: &Column| {
        row.get(column.index)
            .map(String::as_str)
            .filter(|text| !is_placeholder(text))
    };
    let observation = |kind: ElementKind, raw: String, column: &Column| {
        let normalized = normalize(kind, &raw);
        Observation {
            kind,
            raw,
            normalized: normalized.value,
            valid: normalized.valid,
            column: table
                .first_column
                .saturating_add(u32::try_from(column.index).unwrap_or(u32::MAX)),
            header: column.header.clone(),
            method: column.method,
        }
    };
    let with_role = |role: Role| {
        columns
            .iter()
            .filter(move |column| column.role == role)
            .filter_map(move |column| cell(column).map(|text| (*column, text.trim())))
    };

    let mut observations = Vec::new();

    // First, middle and last name columns make one name.
    let parts: Vec<(&Column, &str)> = [Role::FirstName, Role::MiddleName, Role::LastName]
        .into_iter()
        .filter_map(|role| with_role(role).next())
        .collect();
    if let Some((anchor, _)) = parts.first() {
        let joined = parts
            .iter()
            .map(|(_, text)| *text)
            .collect::<Vec<_>>()
            .join(" ");
        observations.push(observation(ElementKind::Name, joined, anchor));
    }

    // A second address line belongs to the first address in the row.
    let second_line = with_role(Role::AddressLine2)
        .map(|(_, text)| text)
        .collect::<Vec<_>>()
        .join(" ");
    let mut second_line = Some(second_line).filter(|line| !line.is_empty());

    for column in columns {
        let (Role::Element(kind), Some(text)) = (column.role, cell(column)) else {
            continue;
        };
        let mut raw = text.to_owned();
        if kind == ElementKind::Address
            && let Some(line) = second_line.take()
        {
            raw = format!("{} {line}", raw.trim());
        }
        observations.push(observation(kind, raw, column));
    }
    if let Some(line) = second_line
        && let Some((anchor, _)) = with_role(Role::AddressLine2).next()
    {
        observations.push(observation(ElementKind::Address, line, anchor));
    }
    observations
}

#[cfg(test)]
mod tests {
    use rollcall_detect::infer_schema;

    use super::*;

    fn link(first_row: u32, rows: &[&[&str]]) -> Vec<PersonRecord> {
        let table = Table {
            scope: Some("Sheet1".to_owned()),
            first_row,
            first_column: 0,
            rows: rows
                .iter()
                .map(|row| row.iter().map(|cell| (*cell).to_owned()).collect())
                .collect(),
        };
        link_table(&table, &infer_schema(&table))
    }

    fn values(record: &PersonRecord, kind: ElementKind) -> Vec<&str> {
        record
            .observations
            .iter()
            .filter(|observation| observation.kind == kind)
            .map(|observation| observation.normalized.as_str())
            .collect()
    }

    #[test]
    fn one_row_becomes_one_person_with_source_coordinates() {
        let records = link(
            4,
            &[
                &[
                    "First Name",
                    "MI",
                    "Last Name",
                    "SSN",
                    "Address",
                    "Apt",
                    "State",
                ],
                &[
                    "Jane",
                    "Q",
                    "Doe",
                    "219-09-9999",
                    "1 Main St",
                    "Unit 4",
                    "ny",
                ],
            ],
        );
        assert_eq!(records.len(), 1);
        let record = &records[0];
        assert_eq!((record.scope.as_deref(), record.row), (Some("Sheet1"), 5));
        assert_eq!(record.relation, None);
        assert_eq!(values(record, ElementKind::Name), vec!["Jane Q Doe"]);
        assert_eq!(values(record, ElementKind::Ssn), vec!["219-09-9999"]);
        assert_eq!(
            values(record, ElementKind::Address),
            vec!["1 Main St Unit 4"]
        );
        assert_eq!(values(record, ElementKind::State), vec!["NY"]);
        let ssn = record
            .observations
            .iter()
            .find(|found| found.kind == ElementKind::Ssn)
            .unwrap();
        assert_eq!((ssn.column, ssn.header.as_deref()), (3, Some("SSN")));
    }

    #[test]
    fn related_people_get_their_own_records() {
        let records = link(
            0,
            &[
                &[
                    "Name",
                    "SSN",
                    "Spouse Name",
                    "Spouse SSN",
                    "Emergency Contact Phone",
                ],
                &[
                    "Jane Doe",
                    "219-09-9999",
                    "John Doe",
                    "219-09-9998",
                    "415-555-0134",
                ],
                &["Ann Poe", "219-09-9997", "", "N/A", ""],
            ],
        );
        let summary: Vec<(u32, Option<&str>, Vec<&str>)> = records
            .iter()
            .map(|record| {
                (
                    record.row,
                    record.relation.as_deref(),
                    values(record, ElementKind::Ssn),
                )
            })
            .collect();
        assert_eq!(
            summary,
            vec![
                (1, None, vec!["219-09-9999"]),
                (1, Some("spouse"), vec!["219-09-9998"]),
                (1, Some("emergency contact"), vec![]),
                (2, None, vec!["219-09-9997"]),
            ]
        );
        assert_eq!(values(&records[1], ElementKind::Name), vec!["John Doe"]);
    }

    #[test]
    fn rows_without_an_identifying_element_are_not_people() {
        let records = link(
            0,
            &[
                &["Name", "State", "DOB"],
                &["", "NY", "1980-02-03"],
                &["", "", ""],
                &["Jane Doe", "", ""],
            ],
        );
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].row, 3);
    }

    #[test]
    fn values_that_fail_validation_are_kept_and_flagged() {
        let records = link(0, &[&["Name", "SSN"], &["Jane Doe", "000-00-0000"]]);
        let ssn = records[0]
            .observations
            .iter()
            .find(|found| found.kind == ElementKind::Ssn)
            .unwrap();
        assert!(!ssn.valid);
        assert_eq!(ssn.raw, "000-00-0000");
    }
}
