//! The Milestone 2 gate: records of one person are merged, nobody is mixed up with
//! anybody else, and a reviewer's answers settle what the policy would not decide.

// Test helpers fail the test by panicking, like the tests themselves.
#![allow(clippy::unwrap_used)]

use rollcall_case::{Case, IngestOptions, Values, export_people_csv, export_records_csv, ingest};
use xtask::score::{owners, score, unavoidable_duplicates, unavoidable_duplicates_of};
use xtask::synth::generate;

fn people_list(case: &Case) -> String {
    let mut output = Vec::new();
    export_people_csv(case, &mut output, Values::Full).unwrap();
    String::from_utf8(output).unwrap()
}

fn records_list(case: &Case) -> String {
    let mut output = Vec::new();
    export_records_csv(case, &mut output, Values::Full).unwrap();
    String::from_utf8(output).unwrap()
}

#[test]
fn people_are_merged_without_mixing_anyone_up_and_review_settles_the_rest() {
    for seed in [1, 2, 3] {
        let out = tempfile::tempdir().unwrap();
        let truth = generate(seed, 300, out.path()).unwrap();
        let mut case = Case::create_or_open(&out.path().join("case.rollcall")).unwrap();
        let evidence = out.path().join("evidence");
        let summary = ingest(&mut case, &evidence, &IngestOptions::default()).unwrap();

        // Before any review: every person is listed, and no row mixes two people.
        let automatic = score(&truth, &people_list(&case)).unwrap();
        assert!(
            automatic.is_perfect(),
            "seed {seed}, before review\n{}",
            automatic.report()
        );

        // A reviewer who knows the truth answers every question the tool asks.
        let owner = owners(&truth, &records_list(&case)).unwrap();
        let (mut asked, mut accepted) = (0_usize, 0_usize);
        for _round in 0..20 {
            let open = case.suggestions().unwrap();
            if open.is_empty() {
                break;
            }
            for suggestion in open {
                let same = match (
                    owner.get(&suggestion.record_a),
                    owner.get(&suggestion.record_b),
                ) {
                    (Some(a), Some(b)) => a == b,
                    _ => false,
                };
                asked += 1;
                accepted += usize::from(same);
                case.decide(suggestion.record_a, suggestion.record_b, same, "oracle", "")
                    .unwrap();
            }
        }
        assert!(
            case.suggestions().unwrap().is_empty(),
            "seed {seed}: questions keep coming"
        );

        let reviewed = score(&truth, &people_list(&case)).unwrap();
        let unavoidable = unavoidable_duplicates(&truth);
        eprintln!(
            "seed {seed}: {} records, {} people in truth; {} rows before review ({} repeats), \
             {asked} questions asked ({accepted} were the same person), {} rows after review \
             ({} repeats, {unavoidable} unavoidable)",
            summary.total_records,
            truth.people.len(),
            automatic.rows,
            automatic.duplicate_rows,
            reviewed.rows,
            reviewed.duplicate_rows,
        );
        for (id, repeats) in &reviewed.repeated_people {
            let person = &truth.people[*id];
            if *repeats > unavoidable_duplicates_of(person) {
                eprintln!(
                    "  listed {} times, could be once: {} #{id} in {:?}, also written {:?}",
                    repeats + 1,
                    person.name,
                    person.files,
                    person.aliases
                );
            }
        }
        assert!(
            reviewed.is_perfect(),
            "seed {seed}, after review\n{}",
            reviewed.report()
        );
        assert!(
            reviewed.duplicate_rows <= unavoidable,
            "seed {seed}: {} people listed twice, {unavoidable} cannot be helped",
            reviewed.duplicate_rows
        );

        // The history of all this is intact, and repeating the ingest changes nothing.
        let check = case.verify_audit().unwrap();
        assert_eq!(check.broken_at, None);
        let before = people_list(&case);
        let again = ingest(&mut case, &evidence, &IngestOptions::default()).unwrap();
        assert_eq!((again.read, again.suggestions), (0, 0));
        assert_eq!(people_list(&case), before);
    }
}
