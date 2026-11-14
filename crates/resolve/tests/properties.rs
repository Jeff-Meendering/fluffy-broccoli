//! Properties the resolver must hold for any set of records, checked on random ones.

// Test helpers fail the test by panicking, like the tests themselves.
#![allow(clippy::unwrap_used)]

use std::collections::{BTreeSet, HashMap};

use rollcall_model::ElementKind;
use rollcall_resolve::{
    Constraint, PersonName, Profile, Resolution, fold, jaro_winkler, resolve, street_key,
};

struct Random(u64);

impl Random {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut mixed = self.0;
        mixed = (mixed ^ (mixed >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        mixed = (mixed ^ (mixed >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        mixed ^ (mixed >> 31)
    }

    fn below(&mut self, limit: usize) -> usize {
        usize::try_from(self.next() % limit.max(1) as u64).unwrap()
    }

    fn pick<'a>(&mut self, items: &[&'a str]) -> &'a str {
        items[self.below(items.len())]
    }
}

// Small pools, so that records collide on every kind of value in every combination.
const NAMES: [&str; 12] = [
    "Robert Smith",
    "Bob Smith",
    "Robert Smyth",
    "R Smith",
    "Roberta Smith",
    "Jane Doe",
    "Jane Roe",
    "Jane Q Doe",
    "Janet Doe",
    "Omar Haddad Jr",
    "Omar Haddad Sr",
    "Uma Xu",
];
const SSNS: [&str; 4] = ["219-09-9999", "219-09-9998", "219-09-9997", "219-09-9996"];
const BIRTHS: [&str; 3] = ["1980-02-03", "1975-05-05", "1991-07-08"];
const EMAILS: [&str; 4] = [
    "a@example.com",
    "b@example.com",
    "home@example.com",
    "c@example.org",
];
const PHONES: [&str; 3] = ["+14155550134", "+14155550135", "+12125550100"];
const STREETS: [&str; 3] = ["1 Main St", "1 Main Street", "22 Oak Ave Apt 3"];

fn population(random: &mut Random, size: usize) -> Vec<Profile> {
    (1..=size)
        .map(|id| {
            let mut values: Vec<(ElementKind, &str)> = Vec::new();
            // One record in six has no name at all.
            let pools: [(ElementKind, &[&'static str], usize); 6] = [
                (ElementKind::Name, &NAMES, 1),
                (ElementKind::Ssn, &SSNS, 3),
                (ElementKind::DateOfBirth, &BIRTHS, 2),
                (ElementKind::Email, &EMAILS, 2),
                (ElementKind::Phone, &PHONES, 3),
                (ElementKind::Address, &STREETS, 3),
            ];
            let nameless = random.below(6) == 0;
            for (kind, pool, one_in) in pools {
                let skip = kind == ElementKind::Name && nameless;
                if !skip && random.below(one_in) == 0 {
                    values.push((kind, random.pick(pool)));
                }
            }
            values.push((ElementKind::PostalCode, "02134"));
            Profile::new(i64::try_from(id).unwrap(), values)
        })
        .collect()
}

fn person_of(resolution: &Resolution) -> HashMap<i64, usize> {
    resolution
        .persons
        .iter()
        .enumerate()
        .flat_map(|(person, records)| records.iter().map(move |record| (*record, person)))
        .collect()
}

#[test]
fn every_record_has_one_person_and_no_person_has_two_ssns_or_birth_dates() {
    let mut random = Random(21);
    for round in 0..400 {
        let profiles = population(&mut random, 40);
        let resolution = resolve(&profiles, &[]);

        let mut seen = BTreeSet::new();
        for records in &resolution.persons {
            assert!(!records.is_empty() && records.is_sorted(), "round {round}");
            for record in records {
                assert!(
                    seen.insert(*record),
                    "round {round}: record {record} is in two persons"
                );
            }
            let of_person = |values: fn(&Profile) -> &Vec<String>| -> BTreeSet<&String> {
                profiles
                    .iter()
                    .filter(|profile| records.contains(&profile.id))
                    .flat_map(values)
                    .collect()
            };
            assert!(
                of_person(|profile| &profile.ssns).len() <= 1,
                "round {round}: two SSNs in {records:?}"
            );
            assert!(
                of_person(|profile| &profile.births).len() <= 1,
                "round {round}: two birth dates in {records:?}"
            );
        }
        assert_eq!(
            seen.len(),
            profiles.len(),
            "round {round}: a record has no person"
        );

        // Each merge joined two groups, so there is one link fewer than records per person.
        assert_eq!(
            resolution.links.len(),
            profiles.len() - resolution.persons.len(),
            "round {round}"
        );

        let person = person_of(&resolution);
        let mut asked = BTreeSet::new();
        for suggestion in &resolution.suggestions {
            assert!(
                suggestion.a < suggestion.b && (30..=100).contains(&suggestion.score),
                "round {round}"
            );
            let pair = (
                person[&suggestion.a].min(person[&suggestion.b]),
                person[&suggestion.a].max(person[&suggestion.b]),
            );
            assert_ne!(pair.0, pair.1, "round {round}: a question about one person");
            assert!(
                asked.insert(pair),
                "round {round}: the same two persons asked about twice"
            );
        }
    }
}

#[test]
fn the_outcome_does_not_depend_on_the_order_of_the_records() {
    let mut random = Random(22);
    for round in 0..300 {
        let mut profiles = population(&mut random, 30);
        let expected = resolve(&profiles, &[]);
        for _ in 0..3 {
            for position in (1..profiles.len()).rev() {
                profiles.swap(position, random.below(position + 1));
            }
            let shuffled = resolve(&profiles, &[]);
            assert_eq!(shuffled.persons, expected.persons, "round {round}");
            assert_eq!(shuffled.suggestions, expected.suggestions, "round {round}");
        }
    }
}

#[test]
fn rulings_always_hold() {
    let mut random = Random(23);
    for round in 0..300 {
        let profiles = population(&mut random, 30);
        let before = resolve(&profiles, &[]);
        let person = person_of(&before);
        // Rule against one existing merge, and for one pair that was kept apart.
        let merged = before
            .persons
            .iter()
            .find(|records| records.len() > 1)
            .map(|records| (records[0], records[1]));
        let apart = (1..=30_i64)
            .find(|record| person[record] != person[&1])
            .map(|record| (1, record));
        let rulings: Vec<Constraint> = merged
            .map(|(a, b)| Constraint { a, b, same: false })
            .into_iter()
            .chain(apart.map(|(a, b)| Constraint { a, b, same: true }))
            .collect();
        let after = resolve(&profiles, &rulings);
        let person = person_of(&after);
        for ruling in &rulings {
            assert_eq!(
                person[&ruling.a] == person[&ruling.b],
                ruling.same,
                "round {round}: {ruling:?}"
            );
        }
        let asked: BTreeSet<(i64, i64)> = after
            .suggestions
            .iter()
            .map(|found| (found.a, found.b))
            .collect();
        if let Some((a, b)) = merged {
            assert!(
                !asked.contains(&(a.min(b), a.max(b))),
                "round {round}: a rejected pair was asked about again"
            );
        }
    }
}

#[test]
fn text_helpers_accept_any_text() {
    let pieces = [
        "a", "Z", "é", "ß", "日本", "😀", "\u{301}", "\u{0}", "\n", " ", "-", "'", ".", ",", "1",
        "St", "Jr",
    ];
    let mut random = Random(24);
    for _ in 0..30_000 {
        let text: String = (0..random.below(8))
            .map(|_| pieces[random.below(pieces.len())])
            .collect();
        let other: String = (0..random.below(8))
            .map(|_| pieces[random.below(pieces.len())])
            .collect();
        let folded = fold(&text);
        assert_eq!(fold(&folded), folded, "folding {text:?} twice differs");
        let similarity = jaro_winkler(&text, &other);
        assert!(
            (0.0..=1.0).contains(&similarity),
            "{text:?} / {other:?}: {similarity}"
        );
        assert!(
            (similarity - jaro_winkler(&other, &text)).abs() < 1e-9,
            "{text:?} / {other:?} is not symmetric"
        );
        let _ = (PersonName::parse(&text), street_key(&text));
    }
}
