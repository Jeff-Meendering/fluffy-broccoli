//! Grouping what was found in running text into person records.
//!
//! Text gives far less to go on than a table row. Two rules keep one person's data
//! from being credited to another:
//!
//! - A run of labelled lines (`Name: ...`, `SSN: ...`) is one record. A blank line, or
//!   the same label appearing again, starts the next.
//! - Values found only by their format belong together when they sit on one line and
//!   no kind appears twice there. `cc: a@example.com, b@example.com` is two people.

use std::collections::BTreeMap;

use rollcall_detect::{Found, NamePart, normalize_header, scan_line};
use rollcall_model::{ElementKind, Method, Observation, PersonRecord, Text, Unit};

/// Builds the person records of one piece of running text.
#[must_use]
pub fn link_text(text: &Text) -> Vec<PersonRecord> {
    let mut records = Vec::new();
    let mut block: Option<Block> = None;
    let close = |block: &mut Option<Block>, records: &mut Vec<PersonRecord>| {
        records.extend(block.take().and_then(|block| block.finish(text)));
    };

    for (index, line) in text.lines.iter().enumerate() {
        if is_break(line) {
            close(&mut block, &mut records);
            continue;
        }
        let (labelled, loose): (Vec<Found>, Vec<Found>) = scan_line(line)
            .into_iter()
            .partition(|found| found.label.is_some());
        for found in labelled {
            let label = normalize_header(found.label.as_deref().unwrap_or_default());
            if block
                .as_ref()
                .is_some_and(|open| open.labels.contains(&label))
            {
                close(&mut block, &mut records);
            }
            let open = block.get_or_insert_with(|| Block::new(index));
            open.labels.push(label);
            open.found.push(found);
        }

        let mut per_kind: BTreeMap<ElementKind, usize> = BTreeMap::new();
        for found in &loose {
            *per_kind.entry(found.kind).or_default() += 1;
        }
        // Values whose kind appears once on the line go together; the rest stand alone.
        let mut together = Block::new(index);
        for found in loose {
            if per_kind[&found.kind] > 1 {
                records.extend(
                    Block {
                        found: vec![found],
                        ..Block::new(index)
                    }
                    .finish(text),
                );
            } else if let Some(open) = block.as_mut() {
                open.found.push(found);
            } else {
                together.found.push(found);
            }
        }
        records.extend(together.finish(text));
    }
    close(&mut block, &mut records);
    records.sort_by_key(|record| record.row);
    records
}

/// True for a line that separates one block of text from the next: a blank line, or
/// one holding only brackets and punctuation, as between records of a JSON list.
fn is_break(line: &str) -> bool {
    line.chars()
        .all(|character| character.is_whitespace() || "{}[](),;-=*_#".contains(character))
}

struct Block {
    line: usize,
    labels: Vec<String>,
    found: Vec<Found>,
}

impl Block {
    fn new(line: usize) -> Self {
        Self {
            line,
            labels: Vec::new(),
            found: Vec::new(),
        }
    }

    fn finish(self, text: &Text) -> Option<PersonRecord> {
        let observation =
            |kind: ElementKind, found: &Found, raw: String, normalized: String| Observation {
                kind,
                raw,
                normalized,
                valid: true,
                column: u32::try_from(found.start).unwrap_or(u32::MAX),
                header: found.label.clone(),
                method: if found.label.is_some() {
                    Method::Header
                } else {
                    Method::Content
                },
            };
        let mut observations = Vec::new();

        // First, middle and last name lines make one name.
        let parts: Vec<&Found> = [NamePart::First, NamePart::Middle, NamePart::Last]
            .into_iter()
            .filter_map(|part| {
                self.found
                    .iter()
                    .find(|found| found.kind == ElementKind::Name && found.part == part)
            })
            .collect();
        if let Some(anchor) = parts.first() {
            let joined = parts
                .iter()
                .map(|found| found.normalized.as_str())
                .collect::<Vec<_>>()
                .join(" ");
            observations.push(observation(
                ElementKind::Name,
                anchor,
                joined.clone(),
                joined,
            ));
        }
        for found in &self.found {
            let part_of_name = found.kind == ElementKind::Name && found.part != NamePart::Full;
            let repeated = observations.iter().any(|seen: &Observation| {
                seen.kind == found.kind && seen.normalized == found.normalized
            });
            if !part_of_name && !repeated {
                observations.push(observation(
                    found.kind,
                    found,
                    found.raw.clone(),
                    found.normalized.clone(),
                ));
            }
        }
        observations
            .iter()
            .any(|found| found.kind.identifies_person())
            .then(|| PersonRecord {
                scope: text.scope.clone(),
                row: text
                    .first_line
                    .saturating_add(u32::try_from(self.line).unwrap_or(u32::MAX)),
                unit: Unit::Line,
                relation: None,
                observations,
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn link(lines: &[&str]) -> Vec<(u32, Vec<(ElementKind, String)>)> {
        let text = Text {
            scope: None,
            first_line: 0,
            lines: lines.iter().map(|line| (*line).to_owned()).collect(),
        };
        link_text(&text)
            .into_iter()
            .map(|record| {
                assert_eq!(record.unit, Unit::Line);
                let values = record
                    .observations
                    .into_iter()
                    .map(|found| (found.kind, found.normalized))
                    .collect();
                (record.row, values)
            })
            .collect()
    }

    fn values(pairs: &[(ElementKind, &str)]) -> Vec<(ElementKind, String)> {
        pairs
            .iter()
            .map(|(kind, value)| (*kind, (*value).to_owned()))
            .collect()
    }

    use ElementKind::{DateOfBirth, Email, Name, Phone, Ssn};

    #[test]
    fn a_run_of_labelled_lines_is_one_person_and_a_blank_line_ends_it() {
        let records = link(&[
            "Employee file",
            "Name: Jane Doe",
            "SSN: 219-09-9999",
            "DOB: 02/03/1980",
            "",
            "First Name: John",
            "Last Name: Roe",
            "Email: john@example.com",
        ]);
        assert_eq!(
            records,
            vec![
                (
                    1,
                    values(&[
                        (Name, "Jane Doe"),
                        (Ssn, "219-09-9999"),
                        (DateOfBirth, "1980-02-03")
                    ])
                ),
                (
                    5,
                    values(&[(Name, "John Roe"), (Email, "john@example.com")])
                ),
            ]
        );
    }

    #[test]
    fn a_repeated_label_starts_the_next_person() {
        let records = link(&[
            "Name: Jane Doe",
            "SSN: 219-09-9999",
            "Name: John Roe",
            "SSN: 219-09-9998",
        ]);
        assert_eq!(records.len(), 2);
        assert_eq!(
            records[1],
            (2, values(&[(Name, "John Roe"), (Ssn, "219-09-9998")]))
        );
    }

    #[test]
    fn records_of_a_list_are_separated_by_their_brackets() {
        let records = link(&[
            "[",
            "  {",
            "    \"name\": \"Jane Doe\",",
            "    \"email\": \"jane@example.com\"",
            "  },",
            "  {",
            "    \"email\": \"john@example.com\",",
            "    \"phone\": \"415-555-0134\"",
            "  }",
            "]",
        ]);
        assert_eq!(
            records,
            vec![
                (
                    2,
                    values(&[(Name, "Jane Doe"), (Email, "jane@example.com")])
                ),
                (
                    6,
                    values(&[(Email, "john@example.com"), (Phone, "+14155550134")])
                ),
            ]
        );
    }

    #[test]
    fn values_on_one_line_go_together_unless_a_kind_repeats() {
        let records = link(&[
            "Call jane@example.com on 415-555-0134 about the reset.",
            "cc: a@example.com, b@example.com (415) 555-0199",
            "nothing personal on this line",
        ]);
        assert_eq!(
            records,
            vec![
                (
                    0,
                    values(&[(Email, "jane@example.com"), (Phone, "+14155550134")])
                ),
                (1, values(&[(Email, "a@example.com")])),
                (1, values(&[(Email, "b@example.com")])),
                (1, values(&[(Phone, "+14155550199")])),
            ]
        );
    }

    #[test]
    fn loose_values_inside_a_labelled_block_join_it() {
        let records = link(&[
            "Name: Jane Doe",
            "reach her at jane@example.com",
            "",
            "jane@example.com",
        ]);
        assert_eq!(
            records,
            vec![
                (
                    0,
                    values(&[(Name, "Jane Doe"), (Email, "jane@example.com")])
                ),
                (3, values(&[(Email, "jane@example.com")])),
            ]
        );
    }

    #[test]
    fn text_without_identifying_values_yields_nothing() {
        assert!(
            link(&[
                "DOB: 02/03/1980",
                "State: MA",
                "",
                "The quarterly report is attached."
            ])
            .is_empty()
        );
    }
}
