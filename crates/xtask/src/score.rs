//! Scores a notification list against the ground truth of a synthetic dataset.
//!
//! The measure is the one that matters for breach notification: was every affected
//! person found, with the right data elements, was anything credited to the wrong
//! person, and is anyone listed more than once. String-level detection accuracy is
//! not measured here.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt::Write as _;

use anyhow::{Context, Result, bail};
use rollcall_extract::delimited;
use rollcall_model::ElementKind;

use crate::synth::{Truth, TruthPerson};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Score {
    pub people: usize,
    pub people_found: usize,
    pub rows: usize,
    /// Rows that belong to a person in the ground truth.
    pub rows_matched: usize,
    /// Rows beyond the first for a person: the same individual listed again.
    pub duplicate_rows: usize,
    /// Per element: how many of the exposed values were listed for the right person.
    pub elements: BTreeMap<String, (usize, usize)>,
    /// Values listed for a person that are not theirs. In a list of people, this is
    /// what a wrong merge looks like.
    pub wrong_values: usize,
    pub missed_people: Vec<String>,
    /// For each person listed more than once, their identifier in the ground truth and
    /// the number of rows beyond the first.
    pub repeated_people: Vec<(usize, usize)>,
}

impl Score {
    /// True when nobody is missed, no row is unexplained, no value is credited to the
    /// wrong person and every exposed element is listed. Duplicate rows are judged
    /// separately: a list of source records has one row per appearance by design.
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
        #[allow(clippy::cast_precision_loss)]
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
            "Rows repeating a person already listed: {}",
            self.duplicate_rows
        );
        let _ = writeln!(
            text,
            "Values credited to the wrong person:    {}",
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

/// True when a listed value is the person's value for that element.
fn is_theirs(person: &TruthPerson, kind: &str, listed: &str) -> bool {
    if kind == ElementKind::Name.as_str() {
        return person
            .exposed
            .get(kind)
            .is_some_and(|name| name.eq_ignore_ascii_case(listed))
            || person
                .aliases
                .iter()
                .any(|alias| alias.eq_ignore_ascii_case(listed));
    }
    person
        .exposed
        .get(kind)
        .is_some_and(|expected| expected == listed)
}

/// One row of a list: its identifier and every element value it carries.
struct ListRow<'a> {
    id: Option<i64>,
    values: Vec<(&'static str, &'a str)>,
}

fn list_rows(rows: &[Vec<String>]) -> Result<Vec<ListRow<'_>>> {
    let (header, body) = rows.split_first().context("the list is empty")?;
    let column = |name: &str| header.iter().position(|cell| cell == name);
    let mut columns: Vec<(&'static str, usize)> = ElementKind::ALL
        .into_iter()
        .filter_map(|kind| column(kind.as_str()).map(|index| (kind.as_str(), index)))
        .collect();
    if !columns.iter().any(|(kind, _)| *kind == "name") {
        bail!("the list has no name column; is it a rollcall export?");
    }
    // A list of people keeps the other ways a name was written in its own column.
    columns.extend(column("other_names").map(|index| ("name", index)));

    let mut listed = Vec::new();
    for row in body {
        let values: Vec<(&str, &str)> = columns
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
        listed.push(ListRow {
            id: row.first().and_then(|cell| cell.parse().ok()),
            values,
        });
    }
    Ok(listed)
}

/// Finds whose row a set of values is, from the values no two people share.
struct Owners<'a> {
    truth: &'a Truth,
    by_value: HashMap<(&'static str, String), Vec<usize>>,
}

/// Elements that belong to one person only, most reliable first.
const PERSONAL: [&str; 5] = [
    "ssn",
    "email",
    "health_insurance_id",
    "payment_card",
    "bank_account",
];
/// Elements that tell namesakes apart when a row has no personal identifier.
const TIE_BREAKERS: [&str; 3] = ["date_of_birth", "phone", "address"];

impl<'a> Owners<'a> {
    fn new(truth: &'a Truth) -> Self {
        let mut by_value: HashMap<(&'static str, String), Vec<usize>> = HashMap::new();
        for person in &truth.people {
            for kind in PERSONAL {
                if let Some(value) = person.exposed.get(kind) {
                    by_value
                        .entry((kind, value.to_lowercase()))
                        .or_default()
                        .push(person.id);
                }
            }
            let names = person
                .exposed
                .get("name")
                .into_iter()
                .chain(&person.aliases);
            for name in names {
                let owners = by_value.entry(("name", name.to_lowercase())).or_default();
                if !owners.contains(&person.id) {
                    owners.push(person.id);
                }
            }
        }
        Self { truth, by_value }
    }

    fn of(&self, row: &ListRow<'_>) -> Option<usize> {
        let owners_of = |kind: &'static str| {
            row.values
                .iter()
                .filter(move |(listed, _)| *listed == kind)
                .filter_map(move |(_, value)| self.by_value.get(&(kind, value.to_lowercase())))
        };
        for kind in PERSONAL {
            if let Some([only]) = owners_of(kind).map(Vec::as_slice).next() {
                return Some(*only);
            }
        }
        let namesakes: BTreeSet<usize> = owners_of("name").flatten().copied().collect();
        if namesakes.len() <= 1 {
            return namesakes.into_iter().next();
        }
        // Several people have this name: the row is the one whose other details fit.
        let mut fitting = namesakes.into_iter().filter(|candidate| {
            let person = &self.truth.people[*candidate];
            row.values
                .iter()
                .any(|(kind, value)| TIE_BREAKERS.contains(kind) && is_theirs(person, kind, value))
        });
        fitting.next().filter(|_| fitting.next().is_none())
    }
}

/// Says which person in the ground truth each row of a list belongs to, keyed by the
/// row's identifier. Rows that belong to nobody are left out.
pub fn owners(truth: &Truth, list: &str) -> Result<HashMap<i64, usize>> {
    let parsed = delimited::parse(list, ',', usize::MAX, usize::MAX);
    let rows = list_rows(&parsed.rows)?;
    let index = Owners::new(truth);
    Ok(rows
        .iter()
        .filter_map(|row| Some((row.id?, index.of(row)?)))
        .collect())
}

/// Scores the CSV text of a list exported with full values.
pub fn score(truth: &Truth, list: &str) -> Result<Score> {
    let parsed = delimited::parse(list, ',', usize::MAX, usize::MAX);
    let rows = list_rows(&parsed.rows)?;
    let index = Owners::new(truth);

    let mut result = Score {
        people: truth.people.len(),
        rows: rows.len(),
        ..Score::default()
    };
    let mut listed: Vec<BTreeSet<&str>> = vec![BTreeSet::new(); truth.people.len()];
    let mut row_count = vec![0_usize; truth.people.len()];
    for row in &rows {
        let Some(owner) = index.of(row) else {
            continue;
        };
        result.rows_matched += 1;
        row_count[owner] += 1;
        let person = &truth.people[owner];
        for (kind, value) in &row.values {
            if is_theirs(person, kind, value) {
                listed[owner].insert(kind);
            } else {
                result.wrong_values += 1;
            }
        }
    }

    for person in &truth.people {
        if row_count[person.id] == 0 {
            result.missed_people.push(person.name.clone());
        } else {
            result.people_found += 1;
            result.duplicate_rows += row_count[person.id] - 1;
            if row_count[person.id] > 1 {
                result
                    .repeated_people
                    .push((person.id, row_count[person.id] - 1));
            }
        }
        for kind in person.exposed.keys() {
            let tally = result.elements.entry(kind.clone()).or_default();
            tally.1 += 1;
            tally.0 += usize::from(listed[person.id].contains(kind.as_str()));
        }
    }
    Ok(result)
}

/// The fewest rows a perfect list of people could have beyond one per person.
///
/// Two appearances of a person can only be recognised as one individual if they share
/// some identifying value. Where a person's appearances fall into groups with nothing
/// in common (a benefits row with a name and date of birth, a dump row with an email
/// and SSN), no method can join them, and each extra group is an unavoidable extra row.
#[must_use]
pub fn unavoidable_duplicates(truth: &Truth) -> usize {
    truth.people.iter().map(unavoidable_duplicates_of).sum()
}

/// The unavoidable extra rows for one person; see [`unavoidable_duplicates`].
#[must_use]
pub fn unavoidable_duplicates_of(person: &TruthPerson) -> usize {
    const IDENTIFYING: [&str; 8] = [
        "name",
        "ssn",
        "email",
        "phone",
        "address",
        "payment_card",
        "bank_account",
        "health_insurance_id",
    ];
    {
        {
            let appearances: Vec<&BTreeMap<String, String>> = person.appearances.values().collect();
            let mut group: Vec<usize> = (0..appearances.len()).collect();
            for (left, first) in appearances.iter().enumerate() {
                for (right, second) in appearances.iter().enumerate().skip(left + 1) {
                    let share = IDENTIFYING.iter().any(|kind| {
                        matches!((first.get(*kind), second.get(*kind)), (Some(a), Some(b)) if a.eq_ignore_ascii_case(b))
                    });
                    if share {
                        let (from, to) = (group[right], group[left]);
                        for slot in &mut group {
                            if *slot == from {
                                *slot = to;
                            }
                        }
                    }
                }
            }
            group
                .iter()
                .collect::<BTreeSet<_>>()
                .len()
                .saturating_sub(1)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn person(id: usize, name: &str, exposed: &[(&str, &str)]) -> TruthPerson {
        TruthPerson {
            id,
            name: name.to_owned(),
            files: BTreeSet::new(),
            exposed: exposed
                .iter()
                .map(|(kind, value)| ((*kind).to_owned(), (*value).to_owned()))
                .collect(),
            aliases: BTreeSet::new(),
            appearances: BTreeMap::new(),
        }
    }

    fn truth() -> Truth {
        let mut jane = person(
            0,
            "Jane Doe",
            &[
                ("name", "Jane Doe"),
                ("ssn", "219-09-9999"),
                ("phone", "+14155550134"),
                ("date_of_birth", "1980-02-03"),
            ],
        );
        jane.aliases.insert("Janie Doe".to_owned());
        Truth {
            seed: 0,
            people: vec![
                jane,
                person(
                    1,
                    "John Roe",
                    &[("name", "John Roe"), ("email", "john@example.com")],
                ),
                person(
                    2,
                    "Jane Doe",
                    &[("name", "Jane Doe"), ("date_of_birth", "1991-07-08")],
                ),
            ],
            files: Vec::new(),
        }
    }

    const HEADER: &str = "record_id,name,other_names,ssn,email,phone,date_of_birth\n";

    #[test]
    fn a_complete_and_correct_list_is_perfect() {
        let list = format!(
            "{HEADER}1,JANE DOE,Janie Doe,219-09-9999,,'+14155550134,1980-02-03\n\
             2,John Roe,,,john@example.com,,\n\
             3,Jane Doe,,,,,1991-07-08\n"
        );
        let result = score(&truth(), &list).unwrap();
        assert!(result.is_perfect(), "{}", result.report());
        assert_eq!(
            (result.people_found, result.rows, result.rows_matched),
            (3, 3, 3)
        );
        assert_eq!(result.duplicate_rows, 0);
        assert_eq!(result.elements["phone"], (1, 1));
        assert_eq!(
            owners(&truth(), &list).unwrap(),
            HashMap::from([(1, 0), (2, 1), (3, 2)])
        );
    }

    #[test]
    fn namesakes_are_told_apart_by_their_other_details_or_not_at_all() {
        let list =
            format!("{HEADER}1,Jane Doe,,,,,1991-07-08\n2,Jane Doe,,,,,\n3,Janie Doe,,,,,\n");
        let found = owners(&truth(), &list).unwrap();
        assert_eq!(
            found,
            HashMap::from([(1, 2), (3, 0)]),
            "row 2 could be either Jane Doe"
        );
    }

    #[test]
    fn missing_people_extra_rows_wrong_values_and_repeats_are_all_counted() {
        let list = format!(
            "{HEADER}1,Jane Doe,,219-09-9999,john@example.com,,\n\
             2,Nobody Known,,,,,\n\
             3,Jane Doe,,219-09-9999,,,\n"
        );
        let result = score(&truth(), &list).unwrap();
        assert!(!result.is_perfect());
        assert_eq!((result.people_found, result.rows_matched), (1, 2));
        assert_eq!(
            result.wrong_values, 1,
            "John's email was listed on Jane's row"
        );
        assert_eq!(result.duplicate_rows, 1);
        assert_eq!(result.missed_people, ["John Roe", "Jane Doe"]);
        assert_eq!(result.elements["phone"], (0, 1));
    }

    #[test]
    fn masked_lists_are_refused() {
        let list = format!("{HEADER}1,Jane Doe,,***-**-9999,,,\n");
        assert!(score(&truth(), &list).is_err());
    }

    #[test]
    fn appearances_with_nothing_in_common_cannot_be_joined() {
        let mut truth = truth();
        let appearance = |values: &[(&str, &str)]| -> BTreeMap<String, String> {
            values
                .iter()
                .map(|(kind, value)| ((*kind).to_owned(), (*value).to_owned()))
                .collect()
        };
        let jane = &mut truth.people[0];
        jane.appearances.insert(
            "benefits".to_owned(),
            appearance(&[("name", "Jane Doe"), ("date_of_birth", "1980-02-03")]),
        );
        jane.appearances
            .insert("dump".to_owned(), appearance(&[("ssn", "219-09-9999")]));
        assert_eq!(unavoidable_duplicates(&truth), 1);
        // A third appearance that shares something with each of the others joins them.
        truth.people[0].appearances.insert(
            "payroll".to_owned(),
            appearance(&[("name", "JANE DOE"), ("ssn", "219-09-9999")]),
        );
        assert_eq!(unavoidable_duplicates(&truth), 0);
    }
}
