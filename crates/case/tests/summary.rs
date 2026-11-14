//! The case summary counts people, not rows.

// Test helpers fail the test by panicking, like the tests themselves.
#![allow(clippy::unwrap_used)]

use std::fs;

use rollcall_case::{Case, IngestOptions, Reach, ingest};
use rollcall_model::{Category, ElementKind};

const HR: &str = "Name,SSN,DOB,Email,Address,State\n\
    Robert Smith,219-09-9999,1980-02-03,bob@example.com,1 Main St,MA\n\
    Ada Young,219-09-9998,2015-06-01,,,\n\
    Uma Xu,000-00-0000,,uma@example.com,,TX\n";
const CRM: &str = "Full Name,E-mail,Mobile,Card Number,Province/State\n\
    Bob Smith,bob@example.com,415-555-0134,4111 1111 1111 1111,NY\n\
    Ken Ito,,415-555-0135,,\n\
    ,nobody@example.com,,,\n";

#[test]
fn people_are_counted_once_by_what_they_expose_and_where_they_live() {
    let evidence = tempfile::tempdir().unwrap();
    fs::write(evidence.path().join("hr.csv"), HR).unwrap();
    fs::write(evidence.path().join("crm.csv"), CRM).unwrap();
    fs::write(evidence.path().join("memo.pdf"), b"not read").unwrap();
    let home = tempfile::tempdir().unwrap();
    let mut case = Case::create_or_open(&home.path().join("case.rollcall")).unwrap();
    ingest(&mut case, evidence.path(), &IngestOptions::default()).unwrap();

    let summary = case.summary((2026, 11, 14)).unwrap();
    // Robert and Bob Smith are one person; the other four records are one person each.
    assert_eq!(
        (summary.people, summary.source_records, summary.files),
        (5, 6, 3)
    );
    assert_eq!((summary.open_questions, summary.coverage_gaps), (0, 1));

    assert_eq!(summary.by_element[&ElementKind::Name], 4);
    assert_eq!(
        summary.by_element[&ElementKind::Ssn],
        2,
        "the SSN that failed validation is not counted"
    );
    assert_eq!(summary.by_element[&ElementKind::Email], 3);
    assert_eq!(summary.by_category[&Category::GovernmentId], 2);
    assert_eq!(summary.by_category[&Category::Financial], 1);
    assert_eq!(summary.by_category[&Category::Contact], 4);
    assert_eq!(summary.contact_only, 3, "Uma, Ken and the unnamed email");

    let regions: Vec<(&str, u64)> = summary
        .by_region
        .iter()
        .map(|(region, count)| (region.as_str(), *count))
        .collect();
    assert_eq!(
        regions,
        [("MA", 1), ("NY", 1), ("TX", 1)],
        "Robert Smith has two states and counts in both"
    );
    assert_eq!(summary.no_region, 3);

    assert_eq!(
        summary.reach,
        Reach {
            by_post: 1,
            by_email_only: 2,
            by_phone_only: 1,
            no_contact: 1
        }
    );
    assert_eq!((summary.minors, summary.no_birth_date), (1, 3));
    assert_eq!((summary.unnamed, summary.needs_review), (1, 1));

    // On her eighteenth birthday Ada is no longer counted as a minor.
    assert_eq!(case.summary((2033, 6, 1)).unwrap().minors, 0);
}
