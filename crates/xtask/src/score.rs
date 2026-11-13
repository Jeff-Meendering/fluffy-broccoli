//! Scores a notification list against the ground truth of a synthetic dataset.
//!
//! The measure is the one that matters for breach notification: was every affected
//! person found, with the right data elements, and was anything credited to the wrong
//! person. String-level detection accuracy is not measured here.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt::Write as _;

use anyhow::{Context, Result, bail};
use rollcall_extract::delimited;
use rollcall_model::ElementKind;

use crate::synth::Truth;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Score {
    pub people: usize,
    pub people_found: usize,
    pub rows: usize,
    /// Rows that belong to a person in the ground truth.
    pub rows_matched: usize,
    /// Per element: how many of the exposed values were listed for the right person.
    pub elements: BTreeMap<String, (usize, usize)>,
    /// Values listed for a person that are not theirs.
    pub wrong_values: usize,
    pub missed_people: Vec<String>,
}

impl Score {
    /// True when the list is exactly right: nobody missed, nothing extra, nothing wrong.
    #[must_use]
    pub fn is_perfect(&self) -> bool {
        self.people_found == self.people
            && self.rows_matched == self.rows
            && self.wrong_values == 0
            && self
                .elements
                .values()
                .all(|(found, expected)| found == expected)
    }

    #[must_use]
    pub fn report(&self) -> String {
        let percent = |part: usize, whole: usize| {
            if whole == 0 {
                100.0
            } else {
                100.0 * part as f64 / whole as f64
            }
        };
        let mut text = String::new();
        let _ = writeln!(
            text,
            "People found:        {} of {} ({:.1}% recall)",
            self.people_found,
            self.people,
            percent(self.people_found, self.people)
        );
        let _ = writeln!(
            text,
            "Rows matching truth: {} of {} ({:.1}% precision)",
            self.rows_matched,
            self.rows,
            percent(self.rows_matched, self.rows)
        );
        let _ = writeln!(
            text,
            "Values credited to the wrong person: {}",
            self.wrong_values
        );
        let _ = writeln!(text, "Exposed elements listed for the right person:");
        for (kind, (found, expected)) in &self.elements {
            let _ = writeln!(
                text,
                "  {kind:<22} {found:>5} of {expected:<5} ({:.1}%)",
                percent(*found, *expected)
            );
        }
        for name in self.missed_people.iter().take(20) {
            let _ = writeln!(text, "Missed: {name}");
        }
        text
    }
}

/// Undoes the apostrophe the export puts before cells a spreadsheet could run.
fn cell_value(cell: &str) -> &str {
    match cell.strip_prefix('\'') {
        Some(rest) if rest.starts_with(['=', '+', '-', '@']) => rest,
        _ => cell,
    }
}

fn same_value(kind: &str, listed: &str, truth: &str) -> bool {
    if kind == ElementKind::Name.as_str() {
        listed.eq_ignore_ascii_case(truth)
    } else {
        listed == truth
    }
}

/// Scores the CSV text of a list exported with full values.
pub fn score(truth: &Truth, list: &str) -> Result<Score> {
    let parsed = delimited::parse(list, ',', usize::MAX, usize::MAX);
    let mut rows = parsed.rows.into_iter();
    let header = rows.next().context("the list is empty")?;
    let column = |name: &str| header.iter().position(|cell| cell == name);
    let element_columns: Vec<(&'static str, usize)> = ElementKind::ALL
        .into_iter()
        .filter_map(|kind| column(kind.as_str()).map(|index| (kind.as_str(), index)))
        .collect();
    if !element_columns.iter().any(|(kind, _)| *kind == "name") {
        bail!("the list has no name column; is it a rollcall export?");
    }

    // Ways to recognise whose row this is, most reliable first.
    let mut by_key: [HashMap<String, usize>; 3] = Default::default();
    for person in &truth.people {
        for (slot, kind) in ["ssn", "email", "name"].into_iter().enumerate() {
            if let Some(value) = person.exposed.get(kind) {
                by_key[slot].insert(value.to_lowercase(), person.id);
            }
        }
    }

    let mut result = Score {
        people: truth.people.len(),
        ..Score::default()
    };
    let mut listed: Vec<BTreeSet<(&str, String)>> = vec![BTreeSet::new(); truth.people.len()];
    for row in rows {
        result.rows += 1;
        let values: Vec<(&str, &str)> = element_columns
            .iter()
            .flat_map(|(kind, index)| {
                let cell = row.get(*index).map_or("", String::as_str);
                cell_value(cell)
                    .split(" | ")
                    .filter(|value| !value.is_empty())
                    .map(|value| (*kind, value))
            })
            .collect();
        if values
            .iter()
            .any(|(kind, value)| *kind == "ssn" && value.contains('*'))
        {
            bail!("identifiers in the list are masked; export it with `--values full` to score it");
        }
        let owner = ["ssn", "email", "name"]
            .into_iter()
            .enumerate()
            .find_map(|(slot, key)| {
                values
                    .iter()
                    .filter(|(kind, _)| *kind == key)
                    .find_map(|(_, value)| by_key[slot].get(&value.to_lowercase()).copied())
            });
        let Some(owner) = owner else {
            continue;
        };
        result.rows_matched += 1;
        let person = &truth.people[owner];
        for (kind, value) in values {
            if person
                .exposed
                .get(kind)
                .is_some_and(|expected| same_value(kind, value, expected))
            {
                listed[owner].insert((kind, value.to_owned()));
            } else {
                result.wrong_values += 1;
            }
        }
    }

    for person in &truth.people {
        let found = &listed[person.id];
        if found.is_empty() {
            result.missed_people.push(person.name.clone());
        } else {
            result.people_found += 1;
        }
        for kind in person.exposed.keys() {
            let tally = result.elements.entry(kind.clone()).or_default();
            tally.1 += 1;
            tally.0 += usize::from(found.iter().any(|(listed_kind, _)| listed_kind == kind));
        }
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use super::*;
    use crate::synth::TruthPerson;

    fn truth() -> Truth {
        let person = |id: usize, name: &str, exposed: &[(&str, &str)]| TruthPerson {
            id,
            name: name.to_owned(),
            files: BTreeSet::new(),
            exposed: exposed
                .iter()
                .map(|(kind, value)| ((*kind).to_owned(), (*value).to_owned()))
                .collect::<BTreeMap<_, _>>(),
        };
        Truth {
            seed: 0,
            people: vec![
                person(
                    0,
                    "Jane Doe",
                    &[
                        ("name", "Jane Doe"),
                        ("ssn", "219-09-9999"),
                        ("phone", "+14155550134"),
                    ],
                ),
                person(
                    1,
                    "John Roe",
                    &[("name", "John Roe"), ("email", "john@example.com")],
                ),
            ],
            files: Vec::new(),
        }
    }

    const HEADER: &str = "record_id,name,ssn,email,phone\n";

    #[test]
    fn a_complete_and_correct_list_is_perfect() {
        let list = format!(
            "{HEADER}1,JANE DOE,219-09-9999,,'+14155550134\n2,,219-09-9999,,\n3,John Roe,,john@example.com,\n"
        );
        let result = score(&truth(), &list).unwrap();
        assert!(result.is_perfect(), "{}", result.report());
        assert_eq!(
            (result.people_found, result.rows, result.rows_matched),
            (2, 3, 3)
        );
        assert_eq!(result.elements["phone"], (1, 1));
    }

    #[test]
    fn missing_people_extra_rows_and_wrong_values_are_all_counted() {
        let list = format!("{HEADER}1,Jane Doe,219-09-9999,john@example.com,\n2,Nobody Known,,,\n");
        let result = score(&truth(), &list).unwrap();
        assert!(!result.is_perfect());
        assert_eq!((result.people_found, result.rows_matched), (1, 1));
        assert_eq!(
            result.wrong_values, 1,
            "John's email was listed on Jane's row"
        );
        assert_eq!(result.missed_people, ["John Roe"]);
        assert_eq!(result.elements["phone"], (0, 1));
    }

    #[test]
    fn masked_lists_are_refused() {
        let list = format!("{HEADER}1,Jane Doe,***-**-9999,,\n");
        assert!(score(&truth(), &list).is_err());
    }
}
