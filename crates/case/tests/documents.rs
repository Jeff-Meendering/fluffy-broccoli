//! Text files and Word documents become person records with line-level sources.

// Test helpers fail the test by panicking, like the tests themselves.
#![allow(clippy::unwrap_used)]

use std::fs;

use rollcall_case::{Case, IngestOptions, ingest, summarise_person};
use rollcall_model::ElementKind;

#[test]
fn people_in_notes_join_the_people_in_spreadsheets() {
    let evidence = tempfile::tempdir().unwrap();
    fs::write(
        evidence.path().join("hr.csv"),
        "Name,SSN,Email\nJane Doe,219-09-9999,jane@example.com\nJohn Roe,219-09-9998,john@example.com\n",
    )
    .unwrap();
    fs::write(
        evidence.path().join("notes.txt"),
        "Ticket 4411\n\nName: Jane Doe\nSSN: 219-09-9999\nDOB: 02/03/1980\n\n\
         Reset requested for john@example.com, callback 415-555-0134.\n\
         Unknown caller left 219-09-9990 on the voicemail.\n",
    )
    .unwrap();
    fs::write(
        evidence.path().join("readme.md"),
        "# Notes\nNothing personal here.\n",
    )
    .unwrap();
    let home = tempfile::tempdir().unwrap();
    let mut case = Case::create_or_open(&home.path().join("case.rollcall")).unwrap();
    let summary = ingest(&mut case, evidence.path(), &IngestOptions::default()).unwrap();

    assert_eq!(
        (summary.read, summary.total_records, summary.persons),
        (3, 5, 3)
    );
    assert_eq!(
        summary.total_gaps, 0,
        "prose without personal data is not a gap"
    );

    let mut people = Vec::new();
    case.for_each_person(|person| {
        let found = summarise_person(&person.records);
        let sources: Vec<String> = person
            .records
            .iter()
            .map(|record| record.source())
            .collect();
        people.push((found.name().to_owned(), found.exposed(), sources));
        Ok(())
    })
    .unwrap();
    use ElementKind::{DateOfBirth, Email, Name, Phone, Ssn};
    assert_eq!(
        people,
        vec![
            (
                "Jane Doe".to_owned(),
                vec![Name, Ssn, DateOfBirth, Email],
                vec!["hr.csv row 2".to_owned(), "notes.txt line 3".to_owned()]
            ),
            (
                "John Roe".to_owned(),
                vec![Name, Ssn, Email, Phone],
                vec!["hr.csv row 3".to_owned(), "notes.txt line 7".to_owned()]
            ),
            (
                String::new(),
                vec![Ssn],
                vec!["notes.txt line 8".to_owned()]
            ),
        ]
    );
}
