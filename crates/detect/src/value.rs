//! Validation and canonical forms for each kind of data element.

use rollcall_model::ElementKind;
use rollcall_model::date::{current_year, is_valid_date, spreadsheet_serial_to_date};

/// A cell value in canonical form, with the verdict of its kind's format rules.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Normalized {
    pub value: String,
    pub valid: bool,
}

impl Normalized {
    fn valid(value: impl Into<String>) -> Self {
        Self {
            value: value.into(),
            valid: true,
        }
    }

    fn invalid(raw: &str) -> Self {
        Self {
            value: collapse(raw),
            valid: false,
        }
    }

    fn checked(value: Option<String>, raw: &str) -> Self {
        value.map_or_else(|| Self::invalid(raw), Self::valid)
    }
}

/// True for cell text that stands for "no value".
#[must_use]
pub fn is_placeholder(raw: &str) -> bool {
    let text = raw.trim();
    text.is_empty()
        || text
            .chars()
            .all(|character| matches!(character, '-' | '_' | '.' | '?' | '*'))
        || matches!(
            text.to_ascii_lowercase().as_str(),
            "n/a" | "na" | "none" | "null" | "nil" | "unknown" | "tbd" | "#n/a" | "not provided"
        )
}

/// Puts a cell value of a known kind into canonical form and checks it.
#[must_use]
pub fn normalize(kind: ElementKind, raw: &str) -> Normalized {
    match kind {
        ElementKind::Name => name(raw),
        ElementKind::Ssn => Normalized::checked(ssn(raw), raw),
        ElementKind::DateOfBirth => Normalized::checked(date_of_birth(raw), raw),
        ElementKind::Email => Normalized::checked(email(raw), raw),
        ElementKind::Phone => Normalized::checked(phone(raw), raw),
        ElementKind::Address => free_text(raw, 5, true),
        ElementKind::City => free_text(raw, 2, false),
        ElementKind::State => Normalized::checked(state(raw), raw),
        ElementKind::PostalCode => Normalized::checked(postal_code(raw), raw),
        ElementKind::Country => country(raw),
        ElementKind::PaymentCard => Normalized::checked(payment_card(raw), raw),
        ElementKind::BankAccount => Normalized::checked(bank_account(raw), raw),
        ElementKind::RoutingNumber => Normalized::checked(routing_number(raw), raw),
        ElementKind::DriversLicence
        | ElementKind::Passport
        | ElementKind::MedicalRecordNumber
        | ElementKind::HealthInsuranceId => Normalized::checked(identifier(raw), raw),
    }
}

/// Strict test used to type a column from its values alone, with no header to go on.
///
/// Only formats that are unlikely to be anything else qualify: a bare ten-digit number
/// could be a phone number or a customer ID, so a phone must be written like one.
#[must_use]
pub fn looks_like(kind: ElementKind, raw: &str) -> bool {
    let text = raw.trim();
    let separated = text.contains(['-', ' ', '(', '+', '.']);
    match kind {
        ElementKind::Email => email(text).is_some(),
        ElementKind::Ssn => {
            let shape: Vec<usize> = text.split(['-', ' ']).map(str::len).collect();
            shape == [3, 2, 4] && ssn(text).is_some()
        }
        ElementKind::Phone => separated && phone(text).is_some(),
        ElementKind::PaymentCard => {
            payment_card(text).is_some_and(|digits| matches!(digits.len(), 15 | 16))
        }
        _ => false,
    }
}

/// The kinds [`looks_like`] can recognise, in the order they are tried.
pub const CONTENT_KINDS: [ElementKind; 4] = [
    ElementKind::Email,
    ElementKind::Ssn,
    ElementKind::PaymentCard,
    ElementKind::Phone,
];

fn collapse(raw: &str) -> String {
    raw.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn digits_of(text: &str) -> String {
    text.chars().filter(char::is_ascii_digit).collect()
}

/// Digits of a value written only with digits and the given separators.
fn digits_with_separators(text: &str, separators: &[char]) -> Option<String> {
    text.chars()
        .all(|character| character.is_ascii_digit() || separators.contains(&character))
        .then(|| digits_of(text))
}

/// Restores leading zeros a spreadsheet dropped when it stored an identifier as a number.
fn restore_leading_zeros(text: &str, digits: String, width: usize, most_lost: usize) -> String {
    let stored_as_number = text.chars().all(|character| character.is_ascii_digit());
    if stored_as_number && digits.len() < width && digits.len() + most_lost >= width {
        format!("{digits:0>width$}")
    } else {
        digits
    }
}

fn all_same(digits: &str) -> bool {
    digits
        .as_bytes()
        .first()
        .is_some_and(|first| digits.bytes().all(|byte| byte == *first))
}

fn name(raw: &str) -> Normalized {
    let collapsed = collapse(raw);
    let reordered = match collapsed.split_once(',') {
        // "Last, First Middle" becomes "First Middle Last"; a second comma usually
        // introduces a suffix or credentials, which stays where it is.
        Some((last, first)) if !first.contains(',') && !first.trim().is_empty() => {
            format!("{} {}", first.trim(), last.trim())
        }
        _ => collapsed,
    };
    let letters = reordered
        .chars()
        .filter(|character| character.is_alphabetic())
        .count();
    let valid = letters >= 2
        && reordered.chars().count() <= 100
        && !reordered
            .chars()
            .any(|character| character.is_ascii_digit() || character == '@');
    Normalized {
        value: reordered,
        valid,
    }
}

fn ssn(raw: &str) -> Option<String> {
    let text = raw.trim();
    let digits = restore_leading_zeros(text, digits_with_separators(text, &['-', ' '])?, 9, 2);
    if digits.len() != 9 || all_same(&digits) || digits == "123456789" {
        return None;
    }
    let area: u32 = digits[..3].parse().ok()?;
    let group: u32 = digits[3..5].parse().ok()?;
    let serial: u32 = digits[5..].parse().ok()?;
    let issued = match area {
        0 | 666 => false,
        // 9xx is never a Social Security number, but is an ITIN for these groups.
        900..=999 => matches!(group, 50..=65 | 70..=88 | 90..=92 | 94..=99),
        _ => group != 0,
    };
    (issued && serial != 0).then(|| format!("{}-{}-{}", &digits[..3], &digits[3..5], &digits[5..]))
}

fn email(raw: &str) -> Option<String> {
    let text = raw.trim();
    let text = text
        .get(..7)
        .filter(|prefix| prefix.eq_ignore_ascii_case("mailto:"))
        .map_or(text, |_| &text[7..]);
    let (local, domain) = text.split_once('@')?;
    let local_ok = (1..=64).contains(&local.len())
        && !local.starts_with('.')
        && !local.ends_with('.')
        && local.chars().all(|character| {
            character.is_ascii_alphanumeric() || "!#$%&'*+/=?^_`{|}~.-".contains(character)
        });
    let labels: Vec<&str> = domain.split('.').collect();
    let domain_ok = domain.len() <= 253
        && labels.len() >= 2
        && labels.iter().all(|label| {
            !label.is_empty()
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .chars()
                    .all(|character| character.is_alphanumeric() || character == '-')
        })
        && labels.last().is_some_and(|top| {
            top.len() >= 2 && top.chars().all(|character| character.is_ascii_alphabetic())
        });
    (local_ok && domain_ok).then(|| text.to_lowercase())
}

fn phone(raw: &str) -> Option<String> {
    let text = raw.trim();
    // Drop an extension: "x123", "ext. 123", "#123".
    let lower = text.to_ascii_lowercase();
    let main = ["ext", "x", "#"]
        .iter()
        .filter_map(|marker| lower.find(marker))
        .min()
        .map_or(text, |cut| &text[..cut])
        .trim();
    let international = main.starts_with('+');
    let digits = digits_with_separators(main.trim_start_matches('+'), &['-', ' ', '(', ')', '.'])?;
    if international && !digits.starts_with('1') {
        return (8..=15)
            .contains(&digits.len())
            .then(|| format!("+{digits}"));
    }
    let national = match digits.len() {
        10 => digits.as_str(),
        11 if digits.starts_with('1') => &digits[1..],
        _ => return None,
    };
    // North American numbers: area code and exchange both start with 2 to 9.
    let leads = |index: usize| matches!(national.as_bytes()[index], b'2'..=b'9');
    (leads(0) && leads(3) && !all_same(national)).then(|| format!("+1{national}"))
}

fn luhn(digits: &str) -> bool {
    let sum: u32 = digits
        .bytes()
        .rev()
        .enumerate()
        .map(|(index, byte)| {
            let digit = u32::from(byte - b'0');
            match (index % 2, digit * 2) {
                (0, _) => digit,
                (_, doubled) if doubled > 9 => doubled - 9,
                (_, doubled) => doubled,
            }
        })
        .sum();
    sum.is_multiple_of(10)
}

fn payment_card(raw: &str) -> Option<String> {
    let digits = digits_with_separators(raw.trim(), &['-', ' '])?;
    ((13..=19).contains(&digits.len()) && !all_same(&digits) && luhn(&digits)).then_some(digits)
}

fn routing_number(raw: &str) -> Option<String> {
    let text = raw.trim();
    let digits = restore_leading_zeros(text, digits_with_separators(text, &['-', ' '])?, 9, 1);
    if digits.len() != 9 || all_same(&digits) {
        return None;
    }
    let weights = [3, 7, 1, 3, 7, 1, 3, 7, 1];
    let sum: u32 = digits
        .bytes()
        .zip(weights)
        .map(|(byte, weight)| u32::from(byte - b'0') * weight)
        .sum();
    sum.is_multiple_of(10).then_some(digits)
}

fn iban(compact: &str) -> bool {
    let bytes = compact.as_bytes();
    if !(15..=34).contains(&bytes.len())
        || !bytes[..2].iter().all(u8::is_ascii_uppercase)
        || !bytes[2..4].iter().all(u8::is_ascii_digit)
        || !bytes.iter().all(u8::is_ascii_alphanumeric)
    {
        return false;
    }
    // Move the first four characters to the end, read letters as 10 to 35, take mod 97.
    let remainder = bytes[4..]
        .iter()
        .chain(&bytes[..4])
        .fold(0_u32, |remainder, byte| {
            if byte.is_ascii_digit() {
                (remainder * 10 + u32::from(byte - b'0')) % 97
            } else {
                (remainder * 100 + u32::from(byte - b'A') + 10) % 97
            }
        });
    remainder == 1
}

fn bank_account(raw: &str) -> Option<String> {
    let compact: String = raw
        .trim()
        .chars()
        .filter(|character| *character != ' ')
        .collect();
    let upper = compact.to_ascii_uppercase();
    if iban(&upper) {
        return Some(upper);
    }
    let digits = digits_with_separators(&compact, &['-'])?;
    ((4..=17).contains(&digits.len()) && !all_same(&digits)).then_some(digits)
}

/// Licence, passport, medical record and insurance numbers: no public checksum, so
/// only the general shape of an issued identifier is checked.
fn identifier(raw: &str) -> Option<String> {
    let text = collapse(raw).to_uppercase();
    let shaped = (4..=25).contains(&text.chars().count())
        && text
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "- ".contains(character))
        && text.chars().any(|character| character.is_ascii_digit());
    shaped.then_some(text)
}

fn free_text(raw: &str, shortest: usize, digits_allowed: bool) -> Normalized {
    let value = collapse(raw);
    let valid = value.chars().count() >= shortest
        && value.chars().any(char::is_alphabetic)
        && (digits_allowed || !value.chars().any(|character| character.is_ascii_digit()));
    Normalized { value, valid }
}

fn country(raw: &str) -> Normalized {
    let value = collapse(raw);
    let key: String = value
        .chars()
        .filter(|character| character.is_alphabetic())
        .collect::<String>()
        .to_ascii_lowercase();
    if matches!(
        key.as_str(),
        "us" | "usa" | "unitedstates" | "unitedstatesofamerica"
    ) {
        return Normalized::valid("US");
    }
    let valid = (2..=56).contains(&value.chars().count())
        && value
            .chars()
            .all(|character| character.is_alphabetic() || " .'-".contains(character));
    Normalized { value, valid }
}

const REGIONS: [(&str, &str); 69] = [
    ("AL", "alabama"),
    ("AK", "alaska"),
    ("AZ", "arizona"),
    ("AR", "arkansas"),
    ("CA", "california"),
    ("CO", "colorado"),
    ("CT", "connecticut"),
    ("DE", "delaware"),
    ("DC", "district of columbia"),
    ("FL", "florida"),
    ("GA", "georgia"),
    ("HI", "hawaii"),
    ("ID", "idaho"),
    ("IL", "illinois"),
    ("IN", "indiana"),
    ("IA", "iowa"),
    ("KS", "kansas"),
    ("KY", "kentucky"),
    ("LA", "louisiana"),
    ("ME", "maine"),
    ("MD", "maryland"),
    ("MA", "massachusetts"),
    ("MI", "michigan"),
    ("MN", "minnesota"),
    ("MS", "mississippi"),
    ("MO", "missouri"),
    ("MT", "montana"),
    ("NE", "nebraska"),
    ("NV", "nevada"),
    ("NH", "new hampshire"),
    ("NJ", "new jersey"),
    ("NM", "new mexico"),
    ("NY", "new york"),
    ("NC", "north carolina"),
    ("ND", "north dakota"),
    ("OH", "ohio"),
    ("OK", "oklahoma"),
    ("OR", "oregon"),
    ("PA", "pennsylvania"),
    ("RI", "rhode island"),
    ("SC", "south carolina"),
    ("SD", "south dakota"),
    ("TN", "tennessee"),
    ("TX", "texas"),
    ("UT", "utah"),
    ("VT", "vermont"),
    ("VA", "virginia"),
    ("WA", "washington"),
    ("WV", "west virginia"),
    ("WI", "wisconsin"),
    ("WY", "wyoming"),
    ("PR", "puerto rico"),
    ("GU", "guam"),
    ("VI", "virgin islands"),
    ("AS", "american samoa"),
    ("MP", "northern mariana islands"),
    ("AB", "alberta"),
    ("BC", "british columbia"),
    ("MB", "manitoba"),
    ("NB", "new brunswick"),
    ("NL", "newfoundland and labrador"),
    ("NS", "nova scotia"),
    ("NT", "northwest territories"),
    ("NU", "nunavut"),
    ("ON", "ontario"),
    ("PE", "prince edward island"),
    ("QC", "quebec"),
    ("SK", "saskatchewan"),
    ("YT", "yukon"),
];

/// US states and territories and Canadian provinces, as two-letter codes.
fn state(raw: &str) -> Option<String> {
    let text = collapse(raw).replace('.', "");
    let lower = text.to_ascii_lowercase();
    REGIONS
        .iter()
        .find(|(code, name)| code.eq_ignore_ascii_case(&text) || *name == lower)
        .map(|(code, _)| (*code).to_owned())
}

fn postal_code(raw: &str) -> Option<String> {
    let text = collapse(raw).to_uppercase();
    if let Some(digits) = digits_with_separators(&text, &['-', ' ']) {
        let digits = restore_leading_zeros(&text, digits, 5, 2);
        return match digits.len() {
            5 => Some(digits),
            9 => Some(format!("{}-{}", &digits[..5], &digits[5..])),
            _ => None,
        };
    }
    let shaped = (5..=8).contains(&text.len())
        && text
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || character == ' ')
        && text.chars().any(|character| character.is_ascii_digit());
    shaped.then_some(text)
}

const MONTHS: [&str; 12] = [
    "jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec",
];

fn month_named(token: &str) -> Option<u32> {
    let lower = token.to_ascii_lowercase();
    let index = MONTHS.iter().position(|month| lower.starts_with(month))?;
    let full = [
        "january",
        "february",
        "march",
        "april",
        "may",
        "june",
        "july",
        "august",
        "september",
        "october",
        "november",
        "december",
    ][index];
    (full.starts_with(&lower) || lower == "sept").then(|| u32::try_from(index + 1).unwrap_or(1))
}

fn expand_year(text: &str, this_year: i32) -> Option<i32> {
    let value: i32 = text.parse().ok()?;
    match text.len() {
        4 => Some(value),
        // A two-digit birth year is in the past: "24" is 2024 until 2024 is the future.
        2 if value <= this_year % 100 => Some(this_year - this_year % 100 + value),
        2 => Some(this_year - this_year % 100 - 100 + value),
        _ => None,
    }
}

/// Parses the date notations spreadsheets commonly hold, returning `YYYY-MM-DD`.
///
/// Dates outside 1900 to the current year are rejected: they are not birth dates.
fn date_of_birth(raw: &str) -> Option<String> {
    let this_year = current_year();
    let mut text = raw.trim();
    // Drop a time of day: "1980-02-03 00:00:00", "1980-02-03T00:00:00".
    if let Some(colon) = text.find(':') {
        text = text[..colon]
            .rsplit_once([' ', 'T'])
            .map_or(text, |(date, _)| date)
            .trim();
    }
    let (year, month, day) = parse_date_parts(text, this_year)?;
    (is_valid_date(year, month, day) && (1900..=this_year).contains(&year))
        .then(|| format!("{year:04}-{month:02}-{day:02}"))
}

fn parse_date_parts(text: &str, this_year: i32) -> Option<(i32, u32, u32)> {
    let all_digits =
        |part: &str| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit());
    let parts: Vec<&str> = text
        .split(['/', '-', '.', ',', ' '])
        .filter(|part| !part.is_empty())
        .collect();

    if let [single] = parts.as_slice()
        && all_digits(single)
    {
        return match single.len() {
            8 => {
                let number = |range: std::ops::Range<usize>| single[range].parse::<u32>().ok();
                let year_first = (number(0..4)?, number(4..6)?, number(6..8)?);
                if (1900..=u32::try_from(this_year).ok()?).contains(&year_first.0) {
                    Some((
                        i32::try_from(year_first.0).ok()?,
                        year_first.1,
                        year_first.2,
                    ))
                } else {
                    Some((
                        i32::try_from(number(4..8)?).ok()?,
                        number(0..2)?,
                        number(2..4)?,
                    ))
                }
            }
            // A date cell that lost its formatting is a bare serial number.
            4 | 5 => spreadsheet_serial_to_date(single.parse().ok()?, false)
                .map(|date| (date.year, date.month, date.day)),
            _ => None,
        };
    }

    let [first, second, third] = parts.as_slice() else {
        return None;
    };
    if all_digits(first) && all_digits(second) && all_digits(third) {
        let (a, b): (u32, u32) = (first.parse().ok()?, second.parse().ok()?);
        if first.len() == 4 {
            return Some((first.parse().ok()?, b, third.parse().ok()?));
        }
        let year = expand_year(third, this_year)?;
        // Month first unless that is impossible and day first is not.
        return Some(if a > 12 && b <= 12 {
            (year, b, a)
        } else {
            (year, a, b)
        });
    }
    // One part is a month name: "3 Mar 1980", "March 3, 1980", "1980 Mar 3".
    let named: Vec<Option<u32>> = parts.iter().map(|part| month_named(part)).collect();
    match named.as_slice() {
        [None, Some(month), None] if first.len() == 4 => {
            Some((first.parse().ok()?, *month, third.parse().ok()?))
        }
        [None, Some(month), None] => {
            Some((expand_year(third, this_year)?, *month, first.parse().ok()?))
        }
        [Some(month), None, None] => {
            Some((expand_year(third, this_year)?, *month, second.parse().ok()?))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn value(kind: ElementKind, raw: &str) -> Option<String> {
        let normalized = normalize(kind, raw);
        normalized.valid.then_some(normalized.value)
    }

    #[test]
    fn social_security_numbers_follow_issuance_rules() {
        let ssn = |raw| value(ElementKind::Ssn, raw);
        assert_eq!(ssn("219-09-9999").as_deref(), Some("219-09-9999"));
        assert_eq!(ssn("219 09 9999").as_deref(), Some("219-09-9999"));
        assert_eq!(ssn("219099999").as_deref(), Some("219-09-9999"));
        assert_eq!(
            ssn("1234567").as_deref(),
            Some("001-23-4567"),
            "lost leading zeros"
        );
        assert_eq!(ssn("912-70-1234").as_deref(), Some("912-70-1234"), "ITIN");
        for invalid in [
            "000-12-3456",
            "666-12-3456",
            "900-12-3456",
            "219-00-9999",
            "219-09-0000",
            "111-11-1111",
            "123-45-6789",
            "21-909-9999x",
            "12345",
            "***-**-1234",
        ] {
            assert_eq!(ssn(invalid), None, "{invalid}");
        }
    }

    #[test]
    fn birth_dates_parse_from_common_notations() {
        let dob = |raw| value(ElementKind::DateOfBirth, raw);
        for raw in [
            "1980-02-03",
            "1980/02/03",
            "02/03/1980",
            "2/3/80",
            "2-3-1980",
            "19800203",
            "02031980",
            "1980-02-03 00:00:00",
            "1980-02-03T00:00:00",
            "3 Feb 1980",
            "3-Feb-80",
            "February 3, 1980",
            "Feb 3 1980",
            "29254",
        ] {
            assert_eq!(dob(raw).as_deref(), Some("1980-02-03"), "{raw}");
        }
        assert_eq!(
            dob("25/12/1990").as_deref(),
            Some("1990-12-25"),
            "day first when forced"
        );
        for invalid in [
            "02/30/1980",
            "13/13/1980",
            "1880-01-01",
            "2999-01-01",
            "soon",
            "12",
        ] {
            assert_eq!(dob(invalid), None, "{invalid}");
        }
    }

    #[test]
    fn two_digit_birth_years_are_never_in_the_future() {
        let dob = value(ElementKind::DateOfBirth, "1/1/99");
        assert_eq!(dob.as_deref(), Some("1999-01-01"));
        let recent = value(ElementKind::DateOfBirth, "1/1/05");
        assert_eq!(recent.as_deref(), Some("2005-01-01"));
    }

    #[test]
    fn emails_and_phones_are_canonicalised() {
        let email = |raw| value(ElementKind::Email, raw);
        assert_eq!(
            email(" Jane.Doe@Example.COM ").as_deref(),
            Some("jane.doe@example.com")
        );
        assert_eq!(email("mailto:a@b.org").as_deref(), Some("a@b.org"));
        for invalid in [
            "jane@",
            "@example.com",
            "jane@example",
            "a b@example.com",
            "a@-x.com",
        ] {
            assert_eq!(email(invalid), None, "{invalid}");
        }

        let phone = |raw| value(ElementKind::Phone, raw);
        for raw in [
            "(415) 555-0134",
            "415.555.0134",
            "1-415-555-0134",
            "+1 415 555 0134 x22",
        ] {
            assert_eq!(phone(raw).as_deref(), Some("+14155550134"), "{raw}");
        }
        assert_eq!(phone("+44 20 7946 0958").as_deref(), Some("+442079460958"));
        for invalid in [
            "555-0134",
            "(015) 555-0134",
            "415-155-0134",
            "call me",
            "4155550134999",
        ] {
            assert_eq!(phone(invalid), None, "{invalid}");
        }
    }

    #[test]
    fn financial_numbers_are_checked_by_their_checksums() {
        let card = |raw| value(ElementKind::PaymentCard, raw);
        assert_eq!(
            card("4111 1111 1111 1111").as_deref(),
            Some("4111111111111111")
        );
        assert_eq!(card("4111 1111 1111 1112"), None);
        assert_eq!(card("0000 0000 0000 0000"), None);

        let routing = |raw| value(ElementKind::RoutingNumber, raw);
        assert_eq!(routing("021000021").as_deref(), Some("021000021"));
        assert_eq!(
            routing("21000021").as_deref(),
            Some("021000021"),
            "lost leading zero"
        );
        assert_eq!(routing("021000022"), None);

        let account = |raw| value(ElementKind::BankAccount, raw);
        assert_eq!(account("0012-3456-789").as_deref(), Some("00123456789"));
        assert_eq!(
            account("GB82 WEST 1234 5698 7654 32").as_deref(),
            Some("GB82WEST12345698765432")
        );
        assert_eq!(account("GB82 WEST 1234 5698 7654 33"), None);
        assert_eq!(account("123"), None);
    }

    #[test]
    fn names_are_reordered_and_checked() {
        let name = |raw| value(ElementKind::Name, raw);
        assert_eq!(name("  Doe,  Jane  Q ").as_deref(), Some("Jane Q Doe"));
        assert_eq!(
            name("Jane Doe, MD, PhD").as_deref(),
            Some("Jane Doe, MD, PhD")
        );
        assert_eq!(name("José Ñandú").as_deref(), Some("José Ñandú"));
        assert_eq!(name("E10432"), None);
        assert_eq!(name("jane@example.com"), None);
    }

    #[test]
    fn places_are_canonicalised() {
        assert_eq!(value(ElementKind::State, "new york").as_deref(), Some("NY"));
        assert_eq!(value(ElementKind::State, "D.C.").as_deref(), Some("DC"));
        assert_eq!(value(ElementKind::State, "Ontario").as_deref(), Some("ON"));
        assert_eq!(value(ElementKind::State, "West"), None);
        assert_eq!(
            value(ElementKind::PostalCode, "2134").as_deref(),
            Some("02134")
        );
        assert_eq!(
            value(ElementKind::PostalCode, "021341234").as_deref(),
            Some("02134-1234")
        );
        assert_eq!(
            value(ElementKind::PostalCode, "k1a 0b1").as_deref(),
            Some("K1A 0B1")
        );
        assert_eq!(value(ElementKind::PostalCode, "12"), None);
        assert_eq!(value(ElementKind::Country, "U.S.A.").as_deref(), Some("US"));
        assert_eq!(
            value(ElementKind::Country, "Canada").as_deref(),
            Some("Canada")
        );
        assert_eq!(
            value(ElementKind::City, "St. Louis").as_deref(),
            Some("St. Louis")
        );
        assert_eq!(value(ElementKind::City, "12345"), None);
    }

    #[test]
    fn content_typing_demands_unambiguous_formats() {
        assert!(looks_like(ElementKind::Ssn, "219-09-9999"));
        assert!(!looks_like(ElementKind::Ssn, "219099999"));
        assert!(looks_like(ElementKind::Phone, "415-555-0134"));
        assert!(!looks_like(ElementKind::Phone, "4155550134"));
        assert!(looks_like(ElementKind::PaymentCard, "4111111111111111"));
        assert!(looks_like(ElementKind::Email, "a@b.org"));
        assert!(!looks_like(ElementKind::Name, "Jane Doe"));
    }

    #[test]
    fn placeholders_are_not_values() {
        for raw in ["", "  ", "N/A", "null", "--", "***", "Unknown"] {
            assert!(is_placeholder(raw), "{raw:?}");
        }
        assert!(!is_placeholder("Nana"));
    }
}
