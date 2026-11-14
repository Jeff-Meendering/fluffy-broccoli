//! Calendar arithmetic for the proleptic Gregorian calendar.

use std::time::{SystemTime, UNIX_EPOCH};

/// Converts a count of days since 1970-01-01 into `(year, month, day)`.
#[must_use]
pub fn civil_from_days(days: i64) -> (i32, u32, u32) {
    let shifted = days + 719_468;
    let era = shifted.div_euclid(146_097);
    let day_of_era = shifted.rem_euclid(146_097);
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_index = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_index + 2) / 5 + 1;
    let month = if month_index < 10 {
        month_index + 3
    } else {
        month_index - 9
    };
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    (
        i32::try_from(year).unwrap_or(i32::MAX),
        u32::try_from(month).unwrap_or(1),
        u32::try_from(day).unwrap_or(1),
    )
}

#[must_use]
pub const fn is_leap_year(year: i32) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

#[must_use]
pub const fn days_in_month(year: i32, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap_year(year) => 29,
        2 => 28,
        _ => 0,
    }
}

#[must_use]
pub const fn is_valid_date(year: i32, month: u32, day: u32) -> bool {
    month >= 1 && month <= 12 && day >= 1 && day <= days_in_month(year, month)
}

/// The current calendar year in UTC.
#[must_use]
pub fn current_year() -> i32 {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs());
    let days = i64::try_from(seconds / 86_400).unwrap_or(0);
    civil_from_days(days).0
}

/// A calendar date with the number of seconds elapsed in that day.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SerialDate {
    pub year: i32,
    pub month: u32,
    pub day: u32,
    pub seconds: u32,
}

impl SerialDate {
    /// `YYYY-MM-DD`, with ` HH:MM:SS` appended when the value carries a time of day.
    #[must_use]
    pub fn to_text(self) -> String {
        let date = format!("{:04}-{:02}-{:02}", self.year, self.month, self.day);
        if self.seconds == 0 {
            return date;
        }
        format!(
            "{date} {:02}:{:02}:{:02}",
            self.seconds / 3_600,
            self.seconds / 60 % 60,
            self.seconds % 60
        )
    }
}

/// Converts a spreadsheet date serial number into a calendar date.
///
/// The 1900 date system counts 1900-02-29, a day that never existed, as serial 60; that
/// serial has no calendar date and returns `None`, as do serials outside 1900 to 9999.
#[must_use]
pub fn spreadsheet_serial_to_date(serial: f64, date1904: bool) -> Option<SerialDate> {
    if !serial.is_finite() || !(1.0..2_958_466.0).contains(&serial) {
        return None;
    }
    let whole = serial.floor();
    // Bounded above by the range check, so the conversions cannot overflow.
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let (day_number, seconds) = (
        whole as i64,
        (((serial - whole) * 86_400.0).round() as u32).min(86_399),
    );
    let unix_days = if date1904 {
        day_number - 24_107
    } else {
        match day_number {
            60 => return None,
            ..60 => day_number - 25_568,
            _ => day_number - 25_569,
        }
    };
    let (year, month, day) = civil_from_days(unix_days);
    Some(SerialDate {
        year,
        month,
        day,
        seconds,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn converts_day_counts_to_calendar_dates() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(-1), (1969, 12, 31));
        assert_eq!(civil_from_days(11_016), (2000, 2, 29));
        assert_eq!(civil_from_days(20_770), (2026, 11, 13));
    }

    #[test]
    fn validates_month_lengths_and_leap_years() {
        assert!(is_valid_date(2024, 2, 29));
        assert!(!is_valid_date(2023, 2, 29));
        assert!(!is_valid_date(1900, 2, 29));
        assert!(!is_valid_date(2020, 13, 1));
        assert!(!is_valid_date(2020, 4, 31));
    }

    #[test]
    fn converts_spreadsheet_serials_in_both_date_systems() {
        let date = |serial| spreadsheet_serial_to_date(serial, false).map(SerialDate::to_text);
        assert_eq!(date(1.0).as_deref(), Some("1900-01-01"));
        assert_eq!(date(59.0).as_deref(), Some("1900-02-28"));
        assert_eq!(date(60.0), None);
        assert_eq!(date(61.0).as_deref(), Some("1900-03-01"));
        assert_eq!(date(29_254.0).as_deref(), Some("1980-02-03"));
        assert_eq!(date(45_000.5).as_deref(), Some("2023-03-15 12:00:00"));
        assert_eq!(date(0.5), None);
        assert_eq!(
            spreadsheet_serial_to_date(0.0, true).map(SerialDate::to_text),
            None
        );
        assert_eq!(
            spreadsheet_serial_to_date(27_792.0, true)
                .map(SerialDate::to_text)
                .as_deref(),
            Some("1980-02-03")
        );
    }
}
