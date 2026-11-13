use super::pattern::luhn;

fn digits(value: &str, expected: usize) -> Option<Vec<u8>> {
    let mut result = Vec::with_capacity(expected);
    for byte in value.bytes().filter(u8::is_ascii_digit) {
        if result.len() == expected {
            return None;
        }
        result.push(byte - b'0');
    }
    (result.len() == expected).then_some(result)
}

fn all_same(digits: &[u8]) -> bool {
    digits
        .first()
        .is_some_and(|first| digits.iter().all(|digit| digit == first))
}

pub(super) const fn valid_date(year: i32, month: u32, day: u32) -> bool {
    if year < 1 || year > 9999 || month < 1 || month > 12 || day < 1 {
        return false;
    }
    day <= days_in_month(year, month)
}

pub(super) const fn days_in_month(year: i32, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if year % 400 == 0 || (year % 4 == 0 && year % 100 != 0) => 29,
        2 => 28,
        _ => 0,
    }
}

fn label_nearby(text: &str, start: usize, labels: &[&str]) -> bool {
    let mut prefix_start = start.saturating_sub(48);
    while !text.is_char_boundary(prefix_start) {
        prefix_start += 1;
    }
    let before = text[prefix_start..start].to_lowercase();
    labels
        .iter()
        .any(|label| before.contains(&label.to_lowercase()))
}

fn labelled(text: &str, start: usize, labelled: f32, bare: f32, labels: &[&str]) -> f32 {
    if label_nearby(text, start, labels) {
        labelled
    } else {
        bare
    }
}

pub(super) fn cpf(_text: &str, _start: usize, value: &str) -> f32 {
    let Some(d) = digits(value, 11) else {
        return 0.0;
    };
    if all_same(&d) {
        return 0.0;
    }
    for check in 9..=10 {
        let sum: u32 = (0..check)
            .map(|index| u32::from(d[index]) * (check + 1 - index) as u32)
            .sum();
        let mut remainder = (sum * 10) % 11;
        if remainder == 10 {
            remainder = 0;
        }
        if remainder != u32::from(d[check]) {
            return 0.0;
        }
    }
    0.9
}

const VERHOEFF_D: [[u8; 10]; 10] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
    [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
    [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
    [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
    [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
    [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
    [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
    [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
    [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
];
const VERHOEFF_P: [[u8; 10]; 8] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
    [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
    [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
    [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
    [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
    [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
    [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
];

pub(super) fn aadhaar(text: &str, start: usize, value: &str) -> f32 {
    let Some(d) = digits(value, 12) else {
        return 0.0;
    };
    if all_same(&d) {
        return 0.0;
    }
    let mut check = 0usize;
    for index in 0..12 {
        check = usize::from(
            VERHOEFF_D[check][usize::from(VERHOEFF_P[index % 8][usize::from(d[11 - index])])],
        );
    }
    if check == 0 {
        labelled(text, start, 0.85, 0.6, &["aadhaar", "uidai", "आधार"])
    } else {
        0.0
    }
}

pub(super) fn nhs(_text: &str, _start: usize, value: &str) -> f32 {
    let Some(d) = digits(value, 10) else {
        return 0.0;
    };
    if all_same(&d) {
        return 0.0;
    }
    let sum: u32 = (0..9)
        .map(|index| u32::from(d[index]) * (10 - index) as u32)
        .sum();
    let mut check = 11 - sum % 11;
    if check == 11 {
        check = 0;
    }
    if check != 10 && check == u32::from(d[9]) {
        0.85
    } else {
        0.0
    }
}

pub(super) fn sin(text: &str, start: usize, value: &str) -> f32 {
    let Some(d) = digits(value, 9) else {
        return 0.0;
    };
    if d[0] == 0 || d[0] == 8 || !luhn(value) {
        return 0.0;
    }
    labelled(
        text,
        start,
        0.9,
        0.45,
        &["sin", "social insurance", "assurance sociale"],
    )
}

pub(super) fn dni(_text: &str, _start: usize, value: &str) -> f32 {
    const LETTERS: &[u8; 23] = b"TRWAGMYFPDXBNJZSQVHLCKE";
    let compact: Vec<u8> = value
        .bytes()
        .filter(|byte| *byte != b'-' && *byte != b' ')
        .collect();
    if compact.len() < 3 {
        return 0.0;
    }
    let Some(&last) = compact.last() else {
        return 0.0;
    };
    let mut number = match compact[0] {
        b'X' => 0usize,
        b'Y' => 1,
        b'Z' => 2,
        digit if digit.is_ascii_digit() => usize::from(digit - b'0'),
        _ => return 0.0,
    };
    for byte in &compact[1..compact.len() - 1] {
        if !byte.is_ascii_digit() {
            return 0.0;
        }
        number = number * 10 + usize::from(byte - b'0');
    }
    if LETTERS[number % 23] == last {
        0.85
    } else {
        0.0
    }
}

const ODD_VALUES: [u8; 36] = [
    1, 0, 5, 7, 9, 13, 15, 17, 19, 21, 1, 0, 5, 7, 9, 13, 15, 17, 19, 21, 2, 4, 18, 20, 11, 3, 6,
    8, 12, 14, 16, 10, 22, 25, 24, 23,
];

pub(super) fn codice_fiscale(_text: &str, _start: usize, value: &str) -> f32 {
    let bytes = value.as_bytes();
    if bytes.len() != 16 || !bytes.iter().all(u8::is_ascii_alphanumeric) {
        return 0.0;
    }
    let mut sum = 0u32;
    for (index, byte) in bytes[..15].iter().copied().enumerate() {
        let value_index = if byte.is_ascii_digit() {
            usize::from(byte - b'0')
        } else if byte.is_ascii_uppercase() {
            usize::from(byte - b'A') + 10
        } else {
            return 0.0;
        };
        sum += if index % 2 == 0 {
            u32::from(ODD_VALUES[value_index])
        } else if byte.is_ascii_digit() {
            u32::from(byte - b'0')
        } else {
            u32::from(byte - b'A')
        };
    }
    if bytes[15] == b'A' + (sum % 26) as u8 {
        0.9
    } else {
        0.0
    }
}

pub(super) fn pesel(text: &str, start: usize, value: &str) -> f32 {
    const WEIGHTS: [u32; 10] = [1, 3, 7, 9, 1, 3, 7, 9, 1, 3];
    let Some(d) = digits(value, 11) else {
        return 0.0;
    };
    if all_same(&d) {
        return 0.0;
    }
    let sum: u32 = (0..10)
        .map(|index| u32::from(d[index]) * WEIGHTS[index])
        .sum();
    if (10 - sum % 10) % 10 != u32::from(d[10]) {
        return 0.0;
    }
    let month = u32::from(d[2] * 10 + d[3]);
    let century = month / 20;
    let base = match century {
        0 => 1900,
        1 => 2000,
        2 => 2100,
        3 => 2200,
        4 => 1800,
        _ => return 0.0,
    };
    let year = base + i32::from(d[0] * 10 + d[1]);
    if valid_date(year, month - century * 20, u32::from(d[4] * 10 + d[5])) {
        labelled(text, start, 0.8, 0.45, &["pesel"])
    } else {
        0.0
    }
}

pub(super) fn nir(_text: &str, _start: usize, value: &str) -> f32 {
    let compact = value.replace(' ', "").to_ascii_uppercase();
    if compact.len() != 15 || !compact.is_ascii() {
        return 0.0;
    }
    let body = compact[..13].replace("2A", "19").replace("2B", "18");
    let (Ok(number), Ok(key)) = (body.parse::<u64>(), compact[13..].parse::<u64>()) else {
        return 0.0;
    };
    if 97 - number % 97 == key { 0.9 } else { 0.0 }
}

pub(super) fn personnummer(_text: &str, _start: usize, value: &str) -> f32 {
    let count = value.bytes().filter(|byte| byte.is_ascii_digit()).count();
    if !matches!(count, 10 | 12) {
        return 0.0;
    }
    let Some(d) = digits(value, count) else {
        return 0.0;
    };
    let offset = d.len() - 10;
    let century = if offset == 2 {
        i32::from(d[0]) * 1000 + i32::from(d[1]) * 100
    } else {
        1900
    };
    let year = century + i32::from(d[offset] * 10 + d[offset + 1]);
    let mut day = u32::from(d[offset + 4] * 10 + d[offset + 5]);
    if day > 60 {
        day -= 60;
    }
    if !valid_date(year, u32::from(d[offset + 2] * 10 + d[offset + 3]), day) {
        return 0.0;
    }
    let last10: String = d[offset..]
        .iter()
        .map(|digit| char::from(b'0' + *digit))
        .collect();
    if luhn(&last10) { 0.8 } else { 0.0 }
}

pub(super) fn bsn(_text: &str, _start: usize, value: &str) -> f32 {
    let Some(d) = digits(value, 9) else {
        return 0.0;
    };
    if all_same(&d) {
        return 0.0;
    }
    let sum: i32 = (0..8)
        .map(|index| i32::from(d[index]) * (9 - index) as i32)
        .sum();
    if (sum - i32::from(d[8])).rem_euclid(11) == 0 {
        0.85
    } else {
        0.0
    }
}

pub(super) fn tfn(_text: &str, _start: usize, value: &str) -> f32 {
    const NINE: [u32; 9] = [1, 4, 3, 7, 5, 8, 6, 9, 10];
    const EIGHT: [u32; 8] = [10, 7, 8, 4, 6, 3, 5, 1];
    let count = value.bytes().filter(|byte| byte.is_ascii_digit()).count();
    if !matches!(count, 8 | 9) {
        return 0.0;
    }
    let Some(d) = digits(value, count) else {
        return 0.0;
    };
    if all_same(&d) {
        return 0.0;
    }
    let sum: u32 = d
        .iter()
        .enumerate()
        .map(|(index, digit)| {
            u32::from(*digit)
                * if d.len() == 9 {
                    NINE[index]
                } else {
                    EIGHT[index]
                }
        })
        .sum();
    if sum.is_multiple_of(11) { 0.85 } else { 0.0 }
}

pub(super) fn south_africa(text: &str, start: usize, value: &str) -> f32 {
    let Some(d) = digits(value, 13) else {
        return 0.0;
    };
    if all_same(&d) || d[10] > 1 {
        return 0.0;
    }
    let yy = i32::from(d[0] * 10 + d[1]);
    let current = time::OffsetDateTime::now_utc().year() % 100;
    let year = if yy > current { 1900 + yy } else { 2000 + yy };
    if !valid_date(
        year,
        u32::from(d[2] * 10 + d[3]),
        u32::from(d[4] * 10 + d[5]),
    ) || !luhn(value)
    {
        return 0.0;
    }
    labelled(
        text,
        start,
        0.8,
        0.45,
        &["id number", "identity", "id no", "rsa id", "sa id"],
    )
}

pub(super) fn rrn(_text: &str, _start: usize, value: &str) -> f32 {
    const WEIGHTS: [u32; 12] = [2, 3, 4, 5, 6, 7, 8, 9, 2, 3, 4, 5];
    let Some(d) = digits(value, 13) else {
        return 0.0;
    };
    let century = match d[6] {
        1 | 2 | 5 | 6 => 1900,
        3 | 4 | 7 | 8 => 2000,
        _ => 1800,
    };
    if !valid_date(
        century + i32::from(d[0] * 10 + d[1]),
        u32::from(d[2] * 10 + d[3]),
        u32::from(d[4] * 10 + d[5]),
    ) {
        return 0.0;
    }
    let sum: u32 = (0..12)
        .map(|index| u32::from(d[index]) * WEIGHTS[index])
        .sum();
    if (11 - sum % 11) % 10 == u32::from(d[12]) {
        0.85
    } else {
        0.0
    }
}

pub(super) fn china_id(_text: &str, _start: usize, value: &str) -> f32 {
    const WEIGHTS: [u32; 17] = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2];
    let bytes = value.as_bytes();
    if bytes.len() != 18
        || !bytes[..17].iter().all(u8::is_ascii_digit)
        || !matches!(bytes[17], b'0'..=b'9' | b'X')
    {
        return 0.0;
    }
    let number = |from: usize, to: usize| -> i32 {
        bytes[from..to]
            .iter()
            .fold(0, |value, byte| value * 10 + i32::from(byte - b'0'))
    };
    let year = number(6, 10);
    if year < 1900 || !valid_date(year, number(10, 12) as u32, number(12, 14) as u32) {
        return 0.0;
    }
    let sum: u32 = (0..17)
        .map(|index| u32::from(bytes[index] - b'0') * WEIGHTS[index])
        .sum();
    if b"10X98765432"[sum as usize % 11] == bytes[17] {
        0.85
    } else {
        0.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn calendar_validation_handles_leap_years_and_impossible_dates() {
        assert!(valid_date(2024, 2, 29));
        assert!(valid_date(2000, 2, 29));
        assert!(!valid_date(1900, 2, 29));
        assert!(!valid_date(2023, 2, 29));
        assert!(!valid_date(2024, 4, 31));
        assert!(!valid_date(0, 1, 1));
        assert!(!valid_date(2024, 13, 1));
    }

    #[test]
    fn published_valid_identifiers_verify() {
        assert_eq!(cpf("", 0, "123.456.789-09"), 0.9);
        assert_eq!(aadhaar("Aadhaar ", 8, "2234 5678 9018"), 0.85);
        assert_eq!(nhs("", 0, "943 476 5919"), 0.85);
        assert_eq!(sin("SIN ", 4, "130 692 544"), 0.9);
        assert_eq!(dni("", 0, "12345678Z"), 0.85);
        assert_eq!(dni("", 0, "X1234567L"), 0.85);
        assert_eq!(codice_fiscale("", 0, "RSSMRA85T10A562S"), 0.9);
        assert_eq!(pesel("PESEL ", 6, "44051401359"), 0.8);
        assert_eq!(nir("", 0, "2 69 05 49 588 157 80"), 0.9);
        assert_eq!(nir("", 0, "1 84 03 75 123 456 90"), 0.9);
        assert_eq!(personnummer("", 0, "811218-9876"), 0.8);
        assert_eq!(bsn("", 0, "111222333"), 0.85);
        assert_eq!(tfn("", 0, "123 456 782"), 0.85);
        assert_eq!(south_africa("ID number ", 10, "8001015009087"), 0.8);
        assert_eq!(rrn("", 0, "900101-1234568"), 0.85);
        assert_eq!(china_id("", 0, "11010519491231002X"), 0.85);
    }

    #[test]
    fn altered_check_digits_and_impossible_dates_fail_closed() {
        assert_eq!(cpf("", 0, "123.456.789-00"), 0.0);
        assert_eq!(aadhaar("", 0, "2234 5678 9019"), 0.0);
        assert_eq!(nhs("", 0, "943 476 5918"), 0.0);
        assert_eq!(sin("", 0, "130 692 545"), 0.0);
        assert_eq!(sin("", 0, "046 454 286"), 0.0);
        assert_eq!(dni("", 0, "12345678A"), 0.0);
        assert_eq!(codice_fiscale("", 0, "RSSMRA85T10A562T"), 0.0);
        assert_eq!(pesel("", 0, "44051401358"), 0.0);
        assert_eq!(pesel("", 0, "44991401359"), 0.0);
        assert_eq!(nir("", 0, "2 69 05 49 588 157 81"), 0.0);
        assert_eq!(bsn("", 0, "111222334"), 0.0);
        assert_eq!(tfn("", 0, "123 456 789"), 0.0);
        assert_eq!(rrn("", 0, "900101-1234569"), 0.0);
        assert_eq!(rrn("", 0, "901301-1234568"), 0.0);
        assert_eq!(china_id("", 0, "11010519491231002Y"), 0.0);
        assert_eq!(china_id("", 0, "110105000001010020"), 0.0);
        assert_eq!(personnummer("", 0, "00000101-1234"), 0.0);
    }

    #[test]
    fn repeated_and_zero_filled_values_are_not_accepted() {
        assert_eq!(nhs("", 0, "000 000 0000"), 0.0);
        assert_eq!(tfn("", 0, "000 000 000"), 0.0);
        assert_eq!(bsn("", 0, "000000000"), 0.0);
        assert_eq!(pesel("", 0, "11111111111"), 0.0);
    }
}
