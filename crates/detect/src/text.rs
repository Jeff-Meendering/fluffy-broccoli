//! Finding data elements in running text.
//!
//! Two things are trusted in text: a label that names the element (`SSN: 219-09-9999`,
//! `"email": "a@example.com"`), and a value written in a format that is hard to
//! mistake (an email address, a dashed SSN, a punctuated phone number, a card number
//! that passes its checksum). Names are only taken from labelled lines: telling a
//! person's name from any other capitalised words needs more than this module knows.

use rollcall_model::ElementKind;

use crate::header::{Role, classify_header, is_loose_name_header};
use crate::value::{is_placeholder, looks_like, normalize};

/// Which part of a name a labelled line gave.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NamePart {
    Full,
    First,
    Middle,
    Last,
}

/// One element found on a line of text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Found {
    pub kind: ElementKind,
    /// For names, which part the label named; `Full` otherwise.
    pub part: NamePart,
    pub raw: String,
    pub normalized: String,
    /// Character offset of the value within the line.
    pub start: usize,
    /// The label that named the element, for labelled values.
    pub label: Option<String>,
}

/// Finds the elements on one line: at most one labelled value, then every value
/// recognisable by its format.
#[must_use]
pub fn scan_line(line: &str) -> Vec<Found> {
    let mut found: Vec<Found> = labelled(line).into_iter().collect();
    for pattern in patterns(line) {
        let known = found
            .iter()
            .any(|other| other.kind == pattern.kind && other.normalized == pattern.normalized);
        if !known {
            found.push(pattern);
        }
    }
    found
}

/// A person's name as written after a label: two to five words of letters, the first
/// and last capitalised. Lower-case words in between allow for `Jan van der Berg`.
fn is_personal_name(value: &str) -> bool {
    let words: Vec<&str> = value.split_whitespace().collect();
    let capitalised = |word: Option<&&str>| {
        word.and_then(|word| word.chars().next())
            .is_some_and(char::is_uppercase)
    };
    (2..=5).contains(&words.len())
        && capitalised(words.first())
        && capitalised(words.last())
        && words.iter().all(|word| {
            word.chars().next().is_some_and(char::is_alphabetic)
                && word.chars().all(|character| {
                    character.is_alphabetic() || ".,'-\u{2019}".contains(character)
                })
        })
}

fn labelled(line: &str) -> Option<Found> {
    let body = line.trim_start_matches(|character: char| {
        character.is_whitespace() || "-*\u{2022}>\"'{[(".contains(character)
    });
    let separator = body.find([':', '=', '\t'])?;
    let label = body[..separator].trim().trim_matches(['"', '\'']).trim();
    if label.is_empty() || label.chars().count() > 40 || is_loose_name_header(label) {
        return None;
    }
    let meaning = classify_header(label)?;
    // A label about someone else ("Spouse SSN") does not describe this block's person.
    if meaning.relation.is_some() {
        return None;
    }
    let value = body[separator + 1..]
        .trim()
        .trim_end_matches([',', ';'])
        .trim()
        .trim_matches(['"', '\''])
        .trim();
    if is_placeholder(value) {
        return None;
    }
    let (kind, part) = match meaning.role {
        Role::Element(kind) => (kind, NamePart::Full),
        Role::FirstName => (ElementKind::Name, NamePart::First),
        Role::MiddleName => (ElementKind::Name, NamePart::Middle),
        Role::LastName => (ElementKind::Name, NamePart::Last),
        Role::AddressLine2 => return None,
    };
    let normalized = normalize(kind, value);
    let plausible = match part {
        NamePart::Full if kind == ElementKind::Name => is_personal_name(&normalized.value),
        NamePart::Full => true,
        _ => !value.contains(char::is_whitespace) || value.split_whitespace().count() <= 2,
    };
    // In text, a labelled value that fails validation is far more often not the
    // element at all ("name: my-service") than a damaged one, so it is dropped.
    if !normalized.valid || !plausible {
        return None;
    }
    let start = line
        .find(value)
        .map_or(0, |byte| line[..byte].chars().count());
    Some(Found {
        kind,
        part,
        raw: value.to_owned(),
        normalized: normalized.value,
        start,
        label: Some(label.to_owned()),
    })
}

fn patterns(line: &str) -> Vec<Found> {
    let chars: Vec<char> = line.chars().collect();
    let mut found = Vec::new();
    let mut add = |kind: ElementKind, start: usize, end: usize| {
        let raw: String = chars[start..end].iter().collect();
        let normalized = normalize(kind, &raw);
        if normalized.valid && looks_like(kind, &raw) {
            found.push(Found {
                kind,
                part: NamePart::Full,
                raw,
                normalized: normalized.value,
                start,
                label: None,
            });
            true
        } else {
            false
        }
    };

    for (at, _) in chars
        .iter()
        .enumerate()
        .filter(|(_, character)| **character == '@')
    {
        let mut start = at;
        while start > 0
            && (chars[start - 1].is_ascii_alphanumeric() || "._%+-'".contains(chars[start - 1]))
        {
            start -= 1;
        }
        let mut end = at + 1;
        while end < chars.len() && (chars[end].is_alphanumeric() || ".-".contains(chars[end])) {
            end += 1;
        }
        while end > at + 1 && ".-".contains(chars[end - 1]) {
            end -= 1;
        }
        while start < at && ".'-".contains(chars[start]) {
            start += 1;
        }
        add(ElementKind::Email, start, end);
    }

    let mut position = 0;
    while position < chars.len() {
        let opens = chars[position].is_ascii_digit() || matches!(chars[position], '+' | '(');
        let free =
            position == 0 || !(chars[position - 1].is_alphanumeric() || chars[position - 1] == '-');
        if !(opens && free) {
            position += 1;
            continue;
        }
        let matched = card_ends(&chars, position)
            .into_iter()
            .find(|end| add(ElementKind::PaymentCard, position, *end))
            .or_else(|| {
                ssn_end(&chars, position).filter(|end| add(ElementKind::Ssn, position, *end))
            })
            .or_else(|| {
                phone_end(&chars, position).filter(|end| add(ElementKind::Phone, position, *end))
            });
        position = matched.unwrap_or(position + 1);
    }
    found
}

fn digit(chars: &[char], at: usize) -> bool {
    chars.get(at).is_some_and(char::is_ascii_digit)
}

fn digits(chars: &[char], at: usize, count: usize) -> bool {
    (at..at + count).all(|index| digit(chars, index))
}

/// True when a number ending at `end` is not followed by more of the same number.
fn closed(chars: &[char], end: usize) -> bool {
    !chars
        .get(end)
        .is_some_and(|character| character.is_alphanumeric())
}

/// Ends of the groups of digits, separated by single spaces or dashes, that start at
/// `start` and together hold 13 to 19 digits: the lengths a card number can have.
fn card_ends(chars: &[char], start: usize) -> Vec<usize> {
    let mut ends = Vec::new();
    let (mut at, mut count) = (start, 0);
    loop {
        let group = at;
        while digit(chars, at) {
            at += 1;
        }
        if at == group {
            break;
        }
        count += at - group;
        if (13..=19).contains(&count) && closed(chars, at) {
            ends.push(at);
        }
        if count >= 19 || !matches!(chars.get(at), Some(' ' | '-')) || !digit(chars, at + 1) {
            break;
        }
        at += 1;
    }
    // The longest reading first: a card number followed by other digits is the rarer case.
    ends.reverse();
    ends
}

/// The end of an SSN written `123-45-6789` or `123 45 6789` starting at `start`.
fn ssn_end(chars: &[char], start: usize) -> Option<usize> {
    let separator = *chars.get(start + 3)?;
    let shaped = matches!(separator, '-' | ' ')
        && digits(chars, start, 3)
        && digits(chars, start + 4, 2)
        && chars.get(start + 6) == Some(&separator)
        && digits(chars, start + 7, 4);
    let end = start + 11;
    (shaped && closed(chars, end) && chars.get(end) != Some(&'-')).then_some(end)
}

/// The end of a phone number starting at `start`: a North American number written
/// with punctuation, or an international number introduced by `+`.
fn phone_end(chars: &[char], start: usize) -> Option<usize> {
    let separator = |at: usize| matches!(chars.get(at), Some('-' | '.' | ' '));
    if chars[start] == '+' {
        // Digits with single separators or brackets between them.
        let (mut at, mut count, mut end) = (start + 1, 0, start + 1);
        while let Some(character) = chars.get(at) {
            if character.is_ascii_digit() {
                count += 1;
                end = at + 1;
            } else if !(matches!(character, '-' | '.' | ' ' | '(' | ')') && at + 1 < chars.len())
                || at > end + 1
            {
                break;
            }
            at += 1;
        }
        return ((8..=15).contains(&count) && closed(chars, end)).then_some(end);
    }
    let mut at = start;
    if chars[at] == '1'
        && separator(at + 1)
        && (digit(chars, at + 2) || chars.get(at + 2) == Some(&'('))
    {
        at += 2;
    }
    if chars.get(at) == Some(&'(') {
        if !(digits(chars, at + 1, 3) && chars.get(at + 4) == Some(&')')) {
            return None;
        }
        at += 5;
        if chars.get(at) == Some(&' ') {
            at += 1;
        }
    } else {
        if !(digits(chars, at, 3) && separator(at + 3)) {
            return None;
        }
        at += 4;
    }
    let shaped = digits(chars, at, 3) && separator(at + 3) && digits(chars, at + 4, 4);
    let end = at + 8;
    (shaped && closed(chars, end)).then_some(end)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ElementKind::{DateOfBirth, Email, Name, PaymentCard, Phone, Ssn};

    fn found(line: &str) -> Vec<(ElementKind, String, bool)> {
        scan_line(line)
            .into_iter()
            .map(|found| (found.kind, found.normalized, found.label.is_some()))
            .collect()
    }

    fn one(kind: ElementKind, value: &str, labelled: bool) -> Vec<(ElementKind, String, bool)> {
        vec![(kind, value.to_owned(), labelled)]
    }

    #[test]
    fn labels_name_the_element_in_several_notations() {
        assert_eq!(found("Name: Jane Doe"), one(Name, "Jane Doe", true));
        assert_eq!(found("  - SSN = 219099999"), one(Ssn, "219-09-9999", true));
        assert_eq!(
            found("    \"date_of_birth\": \"02/03/1980\","),
            one(DateOfBirth, "1980-02-03", true)
        );
        assert_eq!(
            found("E-mail\tjane@example.com"),
            one(Email, "jane@example.com", true)
        );
        assert_eq!(
            found("Surname: Doe").first().map(|found| found.0),
            Some(Name)
        );
        assert_eq!(scan_line("First Name: Jane")[0].part, NamePart::First);
    }

    #[test]
    fn labels_that_do_not_name_a_person_are_left_alone() {
        for line in [
            "name: my-service",
            "Name: quarterly report",
            "Name:",
            "Contact: the support team",
            "Spouse SSN: 219-09-9999x",
            "SSN: N/A",
            "DOB: unknown",
            "http://example.com/a:b",
            "12:30 meeting",
            "File Name: staff.xlsx",
        ] {
            assert_eq!(found(line), vec![], "{line}");
        }
        assert_eq!(
            found("Name: Acme Holdings").len(),
            1,
            "two capitalised words pass; a reviewer decides"
        );
    }

    #[test]
    fn unmistakable_formats_are_found_anywhere_on_a_line() {
        assert_eq!(
            found("Reach Jane at <jane.doe@example.com>, (415) 555-0134 or 1-415-555-0199."),
            vec![
                (Email, "jane.doe@example.com".to_owned(), false),
                (Phone, "+14155550134".to_owned(), false),
                (Phone, "+14155550199".to_owned(), false),
            ]
        );
        assert_eq!(
            found("her SSN (219-09-9999) and card 4111 1111 1111 1111 exp 02/27").len(),
            2
        );
        assert_eq!(
            found("card 4111-1111-1111-1111."),
            one(PaymentCard, "4111111111111111", false)
        );
        assert_eq!(
            found("intl +44 20 7946 0958 ok"),
            one(Phone, "+442079460958", false)
        );
        assert_eq!(found("219 09 9999"), one(Ssn, "219-09-9999", false));
    }

    #[test]
    fn numbers_that_only_resemble_identifiers_are_not_found() {
        for line in [
            "order 219099999 shipped",
            "ref ID219-09-9999",
            "2026-11-14 05:00:04",
            "version 1.2.3.4",
            "4155550134",
            "part 415-555-01345",
            "serial 4111 1111 1111 1112",
            "000-00-0000",
            "@handle and a@b",
            "range 100-200-3000",
        ] {
            assert_eq!(found(line), vec![], "{line}");
        }
    }

    #[test]
    fn a_labelled_value_is_not_reported_twice() {
        assert_eq!(found("SSN: 219-09-9999"), one(Ssn, "219-09-9999", true));
        assert_eq!(
            found("Phone: 415-555-0134 alt 415-555-0135"),
            vec![
                (Phone, "+14155550134".to_owned(), false),
                (Phone, "+14155550135".to_owned(), false)
            ],
            "a label followed by two numbers names neither; both are still found by format"
        );
    }

    #[test]
    fn offsets_count_characters_not_bytes() {
        let line = "José — jane@example.com";
        let email = &scan_line(line)[0];
        assert_eq!(
            line.chars().skip(email.start).collect::<String>(),
            "jane@example.com"
        );
    }
}
