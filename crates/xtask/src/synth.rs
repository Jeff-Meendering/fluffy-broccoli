//! A synthetic breach dataset: invented people spread over files the way real exports
//! spread them, with a ground-truth record of who appears where.
//!
//! Everything is derived from the seed, so a dataset can be regenerated exactly.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use rollcall_extract::delimited::write_row;
use rollcall_model::ElementKind;
use serde::{Deserialize, Serialize};

use crate::docx::write_document;
use crate::xlsx::{Cell, Sheet, write_workbook};

/// What the tool is expected to make of one generated file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Expect {
    /// Read into person records with no coverage gap.
    Records,
    /// Read into person records, with a gap for one part of the file.
    RecordsAndGap,
    /// Reported as a coverage gap only.
    Gap,
    /// Read, holding nothing: neither records nor a gap.
    Nothing,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TruthFile {
    pub path: String,
    pub expect: Expect,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TruthPerson {
    pub id: usize,
    pub name: String,
    /// Files this person appears in.
    pub files: BTreeSet<String>,
    /// Canonical value of every element exposed for this person, keyed by element.
    pub exposed: BTreeMap<String, String>,
    /// Other ways the name is written somewhere: a short form, a typing error.
    #[serde(default)]
    pub aliases: BTreeSet<String>,
    /// What each file says about the person, exactly as a correct reading gives it.
    #[serde(default)]
    pub appearances: BTreeMap<String, BTreeMap<String, String>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Truth {
    pub seed: u64,
    pub people: Vec<TruthPerson>,
    pub files: Vec<TruthFile>,
}

/// SplitMix64: a small, well-distributed generator, enough for test data.
struct Random(u64);

impl Random {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut mixed = self.0;
        mixed = (mixed ^ (mixed >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        mixed = (mixed ^ (mixed >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        mixed ^ (mixed >> 31)
    }

    /// A value in `low..=high`.
    fn between(&mut self, low: u64, high: u64) -> u64 {
        low + self.next() % (high - low + 1)
    }

    fn pick<'a>(&mut self, items: &[&'a str]) -> &'a str {
        let index = usize::try_from(self.next() % items.len() as u64).unwrap_or(0);
        items[index]
    }

    fn digits(&mut self, count: usize) -> String {
        (0..count)
            .map(|_| char::from(b'0' + self.between(0, 9) as u8))
            .collect()
    }
}

const FIRST_NAMES: [&str; 40] = [
    "Ada",
    "Amara",
    "Robert",
    "Beatriz",
    "Carlos",
    "William",
    "Elizabeth",
    "Daniel",
    "Elena",
    "Emeka",
    "Fatima",
    "Katherine",
    "Grace",
    "Hana",
    "Michael",
    "Imani",
    "James",
    "Jamal",
    "Samuel",
    "Kenji",
    "Thomas",
    "Liam",
    "Maria",
    "Mateo",
    "Nadia",
    "Noah",
    "Olga",
    "Omar",
    "Priya",
    "Quinn",
    "Rosa",
    "Samir",
    "Sofia",
    "Tariq",
    "Uma",
    "Victor",
    "Wei",
    "Ximena",
    "Yusuf",
    "Zoe",
];
const LAST_NAMES: [&str; 40] = [
    "Abbott",
    "Banerjee",
    "Castillo",
    "Dubois",
    "Eriksen",
    "Farouk",
    "Goldberg",
    "Hernandez",
    "Ivanov",
    "Johnson",
    "Kowalski",
    "Lindqvist",
    "Moreau",
    "Nakamura",
    "Okafor",
    "Petrov",
    "Quintero",
    "Rahman",
    "Silva",
    "Tanaka",
    "Underwood",
    "Vasquez",
    "Walker",
    "Xu",
    "Yilmaz",
    "Zimmerman",
    "Adeyemi",
    "Brennan",
    "Cohen",
    "Delgado",
    "Edwards",
    "Fischer",
    "Gupta",
    "Haddad",
    "Ito",
    "Jensen",
    "Khan",
    "Lopez",
    "Murphy",
    "Nguyen",
];
const STREETS: [&str; 8] = [
    "Maple", "Oak", "Cedar", "Harbor", "Mill", "Summit", "Orchard", "Canal",
];
const STREET_KINDS: [&str; 5] = ["St", "Ave", "Rd", "Ln", "Blvd"];
/// City, state and ZIP code. Several ZIP codes start with zero on purpose.
const PLACES: [(&str, &str, &str); 8] = [
    ("Boston", "MA", "02134"),
    ("Newark", "NJ", "07102"),
    ("Hartford", "CT", "06103"),
    ("Chicago", "IL", "60601"),
    ("Austin", "TX", "73301"),
    ("Seattle", "WA", "98101"),
    ("Denver", "CO", "80202"),
    ("Miami", "FL", "33101"),
];
const AREA_CODES: [&str; 8] = ["212", "312", "415", "617", "702", "206", "303", "512"];

struct Person {
    first: String,
    last: String,
    ssn: String,
    birth: (i64, u32, u32),
    email: String,
    phone: String,
    street: String,
    place: (&'static str, &'static str, &'static str),
    card: String,
    routing: String,
    account: String,
    member_id: String,
    spouse: Option<usize>,
}

impl Person {
    fn name(&self) -> String {
        format!("{} {}", self.first, self.last)
    }

    fn ssn_dashed(&self) -> String {
        format!("{}-{}-{}", &self.ssn[..3], &self.ssn[3..5], &self.ssn[5..])
    }

    fn birth_iso(&self) -> String {
        format!(
            "{:04}-{:02}-{:02}",
            self.birth.0, self.birth.1, self.birth.2
        )
    }

    fn phone_parts(&self) -> (&str, &str, &str) {
        (&self.phone[..3], &self.phone[3..6], &self.phone[6..])
    }
}

fn luhn_check_digit(body: &str) -> char {
    let sum: u32 = body
        .bytes()
        .rev()
        .enumerate()
        .map(|(index, byte)| {
            let digit = u32::from(byte - b'0');
            let doubled = if index % 2 == 0 { digit * 2 } else { digit };
            if doubled > 9 { doubled - 9 } else { doubled }
        })
        .sum();
    char::from(b'0' + ((10 - sum % 10) % 10) as u8)
}

fn routing_check_digit(body: &str) -> char {
    let weights = [3, 7, 1, 3, 7, 1, 3, 7];
    let sum: u32 = body
        .bytes()
        .zip(weights)
        .map(|(byte, weight)| u32::from(byte - b'0') * weight)
        .sum();
    char::from(b'0' + ((10 - sum % 10) % 10) as u8)
}

/// Days from 1970-01-01 to a calendar date.
fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let year_of_era = year.rem_euclid(400);
    let month_index = i64::from(if month > 2 { month - 3 } else { month + 9 });
    let day_of_year = (153 * month_index + 2) / 5 + i64::from(day) - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

/// The short form a given name is often written in, for the names that have one.
fn short_form(first: &str) -> Option<&'static str> {
    Some(match first {
        "Robert" => "Bob",
        "William" => "Bill",
        "Elizabeth" => "Liz",
        "Katherine" => "Kate",
        "Michael" => "Mike",
        "James" => "Jim",
        "Samuel" => "Sam",
        "Thomas" => "Tom",
        "Daniel" => "Dan",
        _ => return None,
    })
}

/// A surname with its third and fourth letters swapped, as a slip of the fingers.
fn mistyped(last: &str) -> Option<String> {
    let mut letters: Vec<char> = last.chars().collect();
    (letters.len() >= 5 && letters[2] != letters[3]).then(|| {
        letters.swap(2, 3);
        letters.into_iter().collect()
    })
}

/// True for people who share their full name with the person generated just before
/// them, though they are someone else.
fn is_namesake(index: usize) -> bool {
    index % 18 == 9
}

/// True for people who live with the person generated just before them, and so share
/// a phone number and an address.
fn is_housemate(index: usize) -> bool {
    index % 11 == 4 && !is_namesake(index)
}

fn population(random: &mut Random, primaries: usize) -> Vec<Person> {
    let mut people: Vec<Person> = Vec::new();
    let mut names = BTreeSet::new();
    let mut numbers = BTreeSet::new();
    let mut make = |random: &mut Random, index: usize, last: Option<&str>| {
        let (first, last) = loop {
            let first = random.pick(&FIRST_NAMES);
            let last = last.unwrap_or_else(|| random.pick(&LAST_NAMES));
            if names.insert((first, last.to_owned())) {
                break (first.to_owned(), last.to_owned());
            }
        };
        let ssn = loop {
            // Area numbers below 100 exercise identifiers that lose leading zeros.
            let ssn = format!(
                "{:03}{:02}{:04}",
                random.between(1, 665),
                random.between(1, 99),
                random.between(1, 9999)
            );
            let repeated = ssn.bytes().all(|byte| byte == ssn.as_bytes()[0]);
            if ssn != "123456789" && !repeated && numbers.insert(ssn.clone()) {
                break ssn;
            }
        };
        let phone = loop {
            let phone = format!(
                "{}{}{}",
                random.pick(&AREA_CODES),
                random.between(200, 999),
                random.digits(4)
            );
            if numbers.insert(phone.clone()) {
                break phone;
            }
        };
        let card_body = format!("4{}", random.digits(14));
        let routing_body = format!("{:02}{}", random.between(1, 12), random.digits(6));
        Person {
            email: format!(
                "{first}.{last}{index}@example.{}",
                random.pick(&["com", "org", "net"])
            )
            .to_lowercase(),
            first,
            last,
            ssn,
            birth: (
                random.between(1940, 2004) as i64,
                random.between(1, 12) as u32,
                random.between(1, 28) as u32,
            ),
            phone,
            street: format!(
                "{} {} {}",
                random.between(1, 9999),
                random.pick(&STREETS),
                random.pick(&STREET_KINDS)
            ),
            place: PLACES[usize::try_from(random.next() % PLACES.len() as u64).unwrap_or(0)],
            card: format!("{card_body}{}", luhn_check_digit(&card_body)),
            routing: format!("{routing_body}{}", routing_check_digit(&routing_body)),
            account: format!("{}{}", random.between(1, 9), random.digits(9)),
            member_id: format!("M{}", random.digits(8)),
            spouse: None,
        }
    };
    for index in 0..primaries {
        let mut person = make(random, index, None);
        if let Some(previous) = people.last() {
            if is_namesake(index) {
                // A stranger with the same name: nothing else may coincide.
                person.first = previous.first.clone();
                person.last = previous.last.clone();
                if person.birth == previous.birth {
                    person.birth.0 -= 1;
                }
                if person.street == previous.street {
                    person.street = format!("{} Unity Way", 10_000 + index);
                }
            } else if is_housemate(index) {
                person.phone = previous.phone.clone();
                person.street = previous.street.clone();
                person.place = previous.place;
            }
        }
        people.push(person);
    }
    // Every fifth person has a spouse who appears only as extra columns on their row.
    for index in (0..primaries).step_by(5) {
        let last = people[index].last.clone();
        let spouse = make(random, people.len(), Some(&last));
        people[index].spouse = Some(people.len());
        people.push(spouse);
    }
    people
}

struct Dataset {
    files: Vec<(String, Vec<u8>, Expect)>,
    truth: Vec<TruthPerson>,
}

impl Dataset {
    fn expose(&mut self, person: usize, file: &str, elements: &[(ElementKind, String)]) {
        let entry = &mut self.truth[person];
        entry.files.insert(file.to_owned());
        let appearance = entry.appearances.entry(file.to_owned()).or_default();
        for (kind, value) in elements {
            appearance.insert(kind.as_str().to_owned(), value.clone());
            if *kind == ElementKind::Name {
                // However it is written here, the person has one canonical name.
                entry
                    .exposed
                    .insert(kind.as_str().to_owned(), entry.name.clone());
                if *value != entry.name {
                    entry.aliases.insert(value.clone());
                }
            } else {
                entry
                    .exposed
                    .insert(kind.as_str().to_owned(), value.clone());
            }
        }
    }
}

fn delimited(rows: &[Vec<String>], delimiter: char) -> Vec<u8> {
    let mut text = String::new();
    for row in rows {
        write_row(&mut text, row, delimiter);
    }
    text.into_bytes()
}

fn strings(cells: &[&str]) -> Vec<String> {
    cells.iter().map(|cell| (*cell).to_owned()).collect()
}

/// Generates the dataset under `out`: files in `out/evidence`, truth in `out/truth.json`.
pub fn generate(seed: u64, primaries: usize, out: &Path) -> Result<Truth> {
    use ElementKind as Kind;
    let mut random = Random(seed);
    let primaries = primaries.max(5);
    let people = population(&mut random, primaries);
    let mut dataset = Dataset {
        files: Vec::new(),
        truth: people
            .iter()
            .enumerate()
            .map(|(id, person)| TruthPerson {
                id,
                name: person.name(),
                files: BTreeSet::new(),
                exposed: BTreeMap::new(),
                aliases: BTreeSet::new(),
                appearances: BTreeMap::new(),
            })
            .collect(),
    };

    // Each person is in one file for certain and in each of the others some of the time.
    let membership: Vec<[bool; 5]> = (0..primaries)
        .map(|index| {
            let mut member = [false; 5];
            for (file, slot) in member.iter_mut().enumerate() {
                *slot = index % 5 == file || random.between(1, 100) <= 30;
            }
            // Spouses are only ever seen in the enrollment workbook.
            member[2] |= people[index].spouse.is_some();
            member
        })
        .collect();
    let membership = &membership;
    let members = |file: usize| (0..primaries).filter(move |index| membership[*index][file]);

    // HR export: one person per row, the plainest case.
    let path = "hr/employees.csv";
    let mut rows = vec![strings(&[
        "Employee ID",
        "First Name",
        "Last Name",
        "SSN",
        "Date of Birth",
        "Email",
        "Phone",
        "Address",
        "City",
        "State",
        "Zip",
    ])];
    for index in members(0) {
        let person = &people[index];
        let (area, exchange, line) = person.phone_parts();
        rows.push(vec![
            format!("E{index:05}"),
            person.first.clone(),
            person.last.clone(),
            person.ssn_dashed(),
            format!(
                "{:02}/{:02}/{:04}",
                person.birth.1, person.birth.2, person.birth.0
            ),
            person.email.clone(),
            format!("({area}) {exchange}-{line}"),
            person.street.clone(),
            person.place.0.to_owned(),
            person.place.1.to_owned(),
            person.place.2.to_owned(),
        ]);
        dataset.expose(
            index,
            path,
            &[
                (Kind::Name, person.name()),
                (Kind::Ssn, person.ssn_dashed()),
                (Kind::DateOfBirth, person.birth_iso()),
                (Kind::Email, person.email.clone()),
                (Kind::Phone, format!("+1{}", person.phone)),
                (Kind::Address, person.street.clone()),
                (Kind::City, person.place.0.to_owned()),
                (Kind::State, person.place.1.to_owned()),
                (Kind::PostalCode, person.place.2.to_owned()),
            ],
        );
    }
    dataset
        .files
        .push((path.to_owned(), delimited(&rows, ','), Expect::Records));

    // Payroll: tab-separated, "Last, First" names, identifiers without punctuation.
    let path = "payroll/direct-deposit.tsv";
    let mut rows = vec![strings(&[
        "Employee Name",
        "Social Security Number",
        "Routing Number",
        "Account Number",
    ])];
    for index in members(1) {
        let person = &people[index];
        // Now and then a surname is keyed in wrongly.
        let slip = if index % 17 == 3 {
            mistyped(&person.last)
        } else {
            None
        };
        let last = slip.unwrap_or_else(|| person.last.clone());
        rows.push(vec![
            format!("{last}, {}", person.first),
            person.ssn.clone(),
            person.routing.clone(),
            person.account.clone(),
        ]);
        dataset.expose(
            index,
            path,
            &[
                (Kind::Name, format!("{} {last}", person.first)),
                (Kind::Ssn, person.ssn_dashed()),
                (Kind::RoutingNumber, person.routing.clone()),
                (Kind::BankAccount, person.account.clone()),
            ],
        );
    }
    dataset
        .files
        .push((path.to_owned(), delimited(&rows, '\t'), Expect::Records));

    // Benefits workbook: title rows above the header, real date cells, a spouse on the
    // same row, and spouse SSNs stored as numbers so their leading zeros are gone.
    let path = "benefits/enrollment.xlsx";
    let text = |value: &str| Cell::Text(value.to_owned());
    let mut rows = vec![
        vec![text("Benefits Enrollment - Confidential")],
        Vec::new(),
        [
            "Name",
            "DOB",
            "Member ID",
            "Spouse Name",
            "Spouse SSN",
            "Spouse DOB",
        ]
        .into_iter()
        .map(text)
        .collect(),
    ];
    for index in members(2) {
        let person = &people[index];
        let serial = days_from_civil(person.birth.0, person.birth.1, person.birth.2) + 25_569;
        let mut row = vec![
            text(&person.name()),
            Cell::Date(serial),
            text(&person.member_id),
        ];
        dataset.expose(
            index,
            path,
            &[
                (Kind::Name, person.name()),
                (Kind::DateOfBirth, person.birth_iso()),
                (Kind::HealthInsuranceId, person.member_id.clone()),
            ],
        );
        if let Some(spouse_index) = person.spouse {
            let spouse = &people[spouse_index];
            row.extend([
                text(&spouse.name()),
                Cell::Number(spouse.ssn.parse().unwrap_or(0)),
                text(&spouse.birth_iso()),
            ]);
            dataset.expose(
                spouse_index,
                path,
                &[
                    (Kind::Name, spouse.name()),
                    (Kind::Ssn, spouse.ssn_dashed()),
                    (Kind::DateOfBirth, spouse.birth_iso()),
                ],
            );
        }
        rows.push(row);
    }
    let notes = vec![
        vec![text(
            "Open enrollment closes on the last Friday of the month.",
        )],
        vec![text("Questions go to the benefits desk.")],
    ];
    let workbook = write_workbook(&[
        Sheet {
            name: "Enrollment".to_owned(),
            rows,
        },
        Sheet {
            name: "Notes".to_owned(),
            rows: notes,
        },
    ])?;
    dataset
        .files
        .push((path.to_owned(), workbook, Expect::RecordsAndGap));

    // CRM export: semicolons, a byte-order mark, different words for the same columns.
    let path = "crm/contacts.csv";
    let mut rows = vec![strings(&[
        "Full Name",
        "E-mail",
        "Mobile",
        "Card Number",
        "Mailing Address",
        "Province/State",
        "Postal Code",
        "Country",
    ])];
    for index in members(3) {
        let person = &people[index];
        let (area, exchange, line) = person.phone_parts();
        let mut email = person.email.clone();
        email[..1].make_ascii_uppercase();
        // Customer systems often hold the name a person goes by.
        let written = match short_form(&person.first) {
            Some(short) if index % 2 == 0 => format!("{short} {}", person.last),
            _ => person.name(),
        };
        rows.push(vec![
            written.clone(),
            email,
            format!("+1 {area}-{exchange}-{line}"),
            format!(
                "{} {} {} {}",
                &person.card[..4],
                &person.card[4..8],
                &person.card[8..12],
                &person.card[12..]
            ),
            person.street.clone(),
            person.place.1.to_owned(),
            person.place.2.to_owned(),
            "United States".to_owned(),
        ]);
        dataset.expose(
            index,
            path,
            &[
                (Kind::Name, written),
                (Kind::Email, person.email.clone()),
                (Kind::Phone, format!("+1{}", person.phone)),
                (Kind::PaymentCard, person.card.clone()),
                (Kind::Address, person.street.clone()),
                (Kind::State, person.place.1.to_owned()),
                (Kind::PostalCode, person.place.2.to_owned()),
                (Kind::Country, "US".to_owned()),
            ],
        );
    }
    let mut bytes = vec![0xEF, 0xBB, 0xBF];
    bytes.extend(delimited(&rows, ';'));
    dataset
        .files
        .push((path.to_owned(), bytes, Expect::Records));

    // A raw dump with no header row at all.
    let path = "exports/dump.csv";
    let mut rows = Vec::new();
    for index in members(4) {
        let person = &people[index];
        let (area, exchange, line) = person.phone_parts();
        rows.push(vec![
            person.email.clone(),
            person.ssn_dashed(),
            format!("{area}-{exchange}-{line}"),
        ]);
        dataset.expose(
            index,
            path,
            &[
                (Kind::Email, person.email.clone()),
                (Kind::Ssn, person.ssn_dashed()),
                (Kind::Phone, format!("+1{}", person.phone)),
            ],
        );
    }
    dataset
        .files
        .push((path.to_owned(), delimited(&rows, ','), Expect::Records));

    // Incident notes: blocks of labelled lines for some people, and passing mentions
    // of others in prose.
    let path = "notes/incident-notes.txt";
    let mut notes = String::from("Incident notes, working copy\nDo not forward.\n\n");
    for (index, person) in people.iter().enumerate().take(primaries) {
        let (area, exchange, line) = person.phone_parts();
        if index % 7 == 2 {
            notes.push_str(&format!(
                "Name: {}\nSSN: {}\nDOB: {:02}/{:02}/{:04}\nEmail: {}\n\n",
                person.name(),
                person.ssn_dashed(),
                person.birth.1,
                person.birth.2,
                person.birth.0,
                person.email
            ));
            dataset.expose(
                index,
                path,
                &[
                    (Kind::Name, person.name()),
                    (Kind::Ssn, person.ssn_dashed()),
                    (Kind::DateOfBirth, person.birth_iso()),
                    (Kind::Email, person.email.clone()),
                ],
            );
        } else if index % 7 == 5 {
            notes.push_str(&format!(
                "Password reset requested for {}, callback {area}-{exchange}-{line}.\n",
                person.email
            ));
            dataset.expose(
                index,
                path,
                &[
                    (Kind::Email, person.email.clone()),
                    (Kind::Phone, format!("+1{}", person.phone)),
                ],
            );
        }
    }
    dataset
        .files
        .push((path.to_owned(), notes.into_bytes(), Expect::Records));

    // A Word document: a staff table between paragraphs of ordinary prose.
    let path = "hr/onboarding.docx";
    let mut rows = vec![strings(&["Name", "Email", "Phone"])];
    for index in (0..primaries).filter(|index| index % 9 == 1) {
        let person = &people[index];
        let (area, exchange, line) = person.phone_parts();
        rows.push(vec![
            person.name(),
            person.email.clone(),
            format!("({area}) {exchange}-{line}"),
        ]);
        dataset.expose(
            index,
            path,
            &[
                (Kind::Name, person.name()),
                (Kind::Email, person.email.clone()),
                (Kind::Phone, format!("+1{}", person.phone)),
            ],
        );
    }
    let document = write_document(
        &[
            "New starter checklist",
            "",
            "The people below start this quarter.",
        ],
        &rows,
        &["", "Questions go to the people team."],
    )?;
    dataset
        .files
        .push((path.to_owned(), document, Expect::Records));

    // Files that hold no person records, each for a different reason.
    let inventory = "SKU,Description,Qty,Unit Price\nA-100,Stapler,14,8.50\nA-101,Toner,3,61.00\n";
    dataset.files.extend([
        (
            "misc/inventory.csv".to_owned(),
            inventory.as_bytes().to_vec(),
            Expect::Gap,
        ),
        (
            "misc/handbook.pdf".to_owned(),
            b"%PDF-1.7 not read by this version".to_vec(),
            Expect::Gap,
        ),
        (
            "misc/corrupt.xlsx".to_owned(),
            b"PK\x03\x04 truncated beyond repair".to_vec(),
            Expect::Gap,
        ),
        ("misc/empty.csv".to_owned(), Vec::new(), Expect::Nothing),
    ]);

    let evidence = out.join("evidence");
    for (path, bytes, _) in &dataset.files {
        let target = evidence.join(path);
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&target, bytes)
            .with_context(|| format!("could not write {}", target.display()))?;
    }
    let truth = Truth {
        seed,
        people: dataset.truth,
        files: dataset
            .files
            .into_iter()
            .map(|(path, _, expect)| TruthFile { path, expect })
            .collect(),
    };
    fs::write(out.join("truth.json"), serde_json::to_vec_pretty(&truth)?)?;
    Ok(truth)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_same_seed_gives_the_same_dataset() {
        let (first, second, other) = (
            tempfile::tempdir().unwrap(),
            tempfile::tempdir().unwrap(),
            tempfile::tempdir().unwrap(),
        );
        let truth = generate(7, 40, first.path()).unwrap();
        assert_eq!(truth, generate(7, 40, second.path()).unwrap());
        assert_ne!(truth, generate(8, 40, other.path()).unwrap());
        for file in &truth.files {
            let read = |root: &Path| fs::read(root.join("evidence").join(&file.path)).unwrap();
            assert_eq!(read(first.path()), read(second.path()), "{}", file.path);
        }
    }

    #[test]
    fn every_person_appears_somewhere_and_spouses_are_people_too() {
        let out = tempfile::tempdir().unwrap();
        let truth = generate(1, 40, out.path()).unwrap();
        assert_eq!(truth.people.len(), 48);
        assert!(truth.people.iter().all(|person| !person.files.is_empty()));
        let spouse = &truth.people[40];
        assert_eq!(
            spouse.files.iter().collect::<Vec<_>>(),
            ["benefits/enrollment.xlsx"]
        );
        assert!(spouse.exposed.contains_key("ssn"));
    }

    #[test]
    fn generated_identifiers_carry_valid_check_digits() {
        assert_eq!(luhn_check_digit("411111111111111"), '1');
        assert_eq!(routing_check_digit("02100002"), '1');
        assert_eq!(days_from_civil(1980, 2, 3) + 25_569, 29_254);
        assert_eq!(days_from_civil(1970, 1, 1), 0);
    }
}
