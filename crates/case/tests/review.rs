//! Persons, a reviewer's rulings and the audit log, end to end.

// Test helpers fail the test by panicking, like the tests themselves.
#![allow(clippy::unwrap_used)]

use std::fs;
use std::path::{Path, PathBuf};

use rollcall_case::{Case, IngestOptions, Values, export_people_csv, ingest};
use tempfile::TempDir;

const HR: &str = "Name,SSN,Email\n\
    Robert Smith,219-09-9999,bob@example.com\n\
    Uma Xu,219-09-9998,uma@example.com\n";
const CRM: &str = "Full Name,E-mail,Mobile\n\
    Bob Smith,bob@example.com,415-555-0134\n\
    Uma Xu,,415-555-0135\n";

/// The temporary folders are deleted when their fields are dropped, so tests bind them.
struct Fixture {
    evidence: TempDir,
    _home: TempDir,
    case_path: PathBuf,
    case: Case,
}

fn fixture() -> Fixture {
    let evidence = tempfile::tempdir().unwrap();
    fs::write(evidence.path().join("hr.csv"), HR).unwrap();
    fs::write(evidence.path().join("crm.csv"), CRM).unwrap();
    let home = tempfile::tempdir().unwrap();
    let case_path = home.path().join("case.rollcall");
    let mut case = Case::create_or_open(&case_path).unwrap();
    ingest(&mut case, evidence.path(), &IngestOptions::default()).unwrap();
    Fixture {
        evidence,
        _home: home,
        case_path,
        case,
    }
}

fn reingest(case: &mut Case, evidence: &Path) -> rollcall_case::IngestSummary {
    ingest(case, evidence, &IngestOptions::default()).unwrap()
}

fn people(case: &Case) -> Vec<Vec<i64>> {
    let mut persons = Vec::new();
    case.for_each_person(|person| {
        persons.push(person.records.iter().map(|record| record.id).collect());
        Ok(())
    })
    .unwrap();
    persons
}

fn list(case: &Case) -> String {
    let mut output = Vec::new();
    export_people_csv(case, &mut output, Values::Full).unwrap();
    String::from_utf8(output).unwrap()
}

#[test]
fn records_of_one_person_merge_and_weak_matches_become_questions() {
    let Fixture {
        case,
        _home,
        evidence: _evidence,
        ..
    } = fixture();
    // Records are numbered in ingest order: crm.csv rows are 1 and 2, hr.csv rows 3 and 4.
    assert_eq!(people(&case), vec![vec![1, 3], vec![2], vec![4]]);
    let counts = case.counts().unwrap();
    assert_eq!(
        (counts.records, counts.persons, counts.suggestions),
        (4, 3, 1)
    );

    let links = case.links_of(1).unwrap();
    assert_eq!(links.len(), 1);
    assert_eq!(
        links[0].reason,
        "Same email address; first names are forms of the same name"
    );

    let suggestions = case.suggestions().unwrap();
    assert_eq!(
        (
            suggestions[0].person_a,
            suggestions[0].person_b,
            suggestions[0].score
        ),
        (2, 4, 40)
    );
    assert_eq!(
        suggestions[0].reason,
        "Same name and nothing else in common"
    );

    let list = list(&case);
    let bob = list.lines().find(|line| line.starts_with("1,")).unwrap();
    assert!(
        bob.starts_with("1,Robert Smith,Bob Smith,name; ssn; email; phone,219-09-9999,"),
        "{bob}"
    );
    assert!(bob.contains(",2,crm.csv row 2 | hr.csv row 2,,"), "{bob}");
    let uma = list.lines().find(|line| line.starts_with("2,")).unwrap();
    assert!(
        uma.ends_with(",4"),
        "the list points at the possible duplicate: {uma}"
    );
}

#[test]
fn accepting_a_suggestion_merges_and_rejecting_it_stops_the_question() {
    let Fixture {
        mut case,
        _home,
        evidence: _evidence,
        ..
    } = fixture();
    let suggestion = case.suggestions().unwrap()[0].id;
    let summary = case
        .decide_suggestion(suggestion, true, "analyst", "same phone on file")
        .unwrap();
    assert_eq!((summary.persons, summary.suggestions), (2, 0));
    assert_eq!(people(&case), vec![vec![1, 3], vec![2, 4]]);
    assert_eq!(
        case.links_of(2).unwrap()[0].reason,
        "Confirmed by a reviewer"
    );

    // The same pair ruled the other way replaces the earlier ruling.
    let summary = case.decide(2, 4, false, "analyst", "").unwrap();
    assert_eq!((summary.persons, summary.suggestions), (3, 0));
    let rulings = case.decisions().unwrap();
    assert_eq!(rulings.len(), 1);
    assert!(!rulings[0].same);
    assert_eq!(rulings[0].records, Some((2, 4)));

    let summary = case.undo_decision(rulings[0].id, "analyst").unwrap();
    assert_eq!(
        (summary.persons, summary.suggestions),
        (3, 1),
        "the question is open again"
    );
    assert!(case.undo_decision(999, "analyst").is_err());
    assert!(case.decide(2, 2, true, "analyst", "").is_err());
    assert!(case.decide(2, 999, true, "analyst", "").is_err());
}

#[test]
fn a_reviewer_can_split_records_the_policy_merged() {
    let Fixture {
        mut case,
        _home,
        evidence: _evidence,
        ..
    } = fixture();
    let summary = case
        .decide(1, 3, false, "analyst", "different Bob")
        .unwrap();
    assert_eq!(summary.persons, 4);
    assert_eq!(people(&case), vec![vec![1], vec![2], vec![3], vec![4]]);
}

#[test]
fn rulings_survive_reingest_but_not_a_change_to_the_evidence() {
    let Fixture {
        evidence,
        case_path,
        mut case,
        _home,
    } = fixture();
    case.decide(2, 4, true, "analyst", "").unwrap();
    drop(case);

    let mut case = Case::open_existing(&case_path).unwrap();
    let summary = reingest(&mut case, evidence.path());
    assert_eq!(
        (summary.reused, summary.persons, summary.suggestions),
        (2, 2, 0)
    );

    // Editing the file replaces its records: the ruling no longer applies to them.
    fs::write(evidence.path().join("crm.csv"), CRM.replace("0135", "0136")).unwrap();
    let summary = reingest(&mut case, evidence.path());
    assert_eq!(
        (summary.read, summary.persons, summary.suggestions),
        (1, 3, 1)
    );
    let rulings = case.decisions().unwrap();
    assert_eq!(rulings[0].records, None, "kept, but inactive");

    // Restoring the original bytes restores the ruling.
    fs::write(evidence.path().join("crm.csv"), CRM).unwrap();
    let summary = reingest(&mut case, evidence.path());
    assert_eq!((summary.persons, summary.suggestions), (2, 0));
}

#[test]
fn the_audit_log_records_events_and_detects_tampering() {
    let Fixture {
        case_path,
        mut case,
        _home,
        evidence: _evidence,
    } = fixture();
    case.decide(
        2,
        4,
        true,
        "analyst\nwith a line break",
        "checked\tthe source",
    )
    .unwrap();
    case.record_export("People list written.").unwrap();

    let log = case.audit_log().unwrap();
    let kinds: Vec<&str> = log.iter().map(|entry| entry.kind.as_str()).collect();
    assert_eq!(kinds, ["case-created", "ingest", "decision", "export"]);
    assert!(
        log[2]
            .detail
            .starts_with("analyst with a line break ruled records 2 and 4 the same person.")
    );
    assert!(log[2].detail.contains("Note: checked the source."));

    let check = case.verify_audit().unwrap();
    assert_eq!((check.entries, check.broken_at), (4, None));
    assert_eq!(check.head, log[3].hash);
    drop(case);

    let edit = |statement: &str| {
        let connection = rusqlite::Connection::open(&case_path).unwrap();
        connection.execute(statement, []).unwrap();
    };
    edit(
        "UPDATE audit SET detail = replace(detail, 'the same person', 'different people') WHERE id = 3",
    );
    let case = Case::open_existing(&case_path).unwrap();
    assert_eq!(case.verify_audit().unwrap().broken_at, Some(3));
    drop(case);

    edit("DELETE FROM audit WHERE id = 2");
    let case = Case::open_existing(&case_path).unwrap();
    assert_eq!(
        case.verify_audit().unwrap().broken_at,
        Some(3),
        "a removed entry breaks the chain"
    );
}
