//! Reading and writing delimiter-separated text (CSV, TSV and relatives).

/// Decodes file bytes to text, honouring UTF-8 and UTF-16 byte-order marks.
///
/// Returns the text and whether any byte sequence had to be replaced because it was
/// not valid in the detected encoding.
#[must_use]
pub fn decode(bytes: &[u8]) -> (String, bool) {
    if let Some(rest) = bytes.strip_prefix(&[0xEF, 0xBB, 0xBF]) {
        return decode_utf8(rest);
    }
    if let Some(rest) = bytes.strip_prefix(&[0xFF, 0xFE]) {
        return decode_utf16(rest, u16::from_le_bytes);
    }
    if let Some(rest) = bytes.strip_prefix(&[0xFE, 0xFF]) {
        return decode_utf16(rest, u16::from_be_bytes);
    }
    decode_utf8(bytes)
}

fn decode_utf8(bytes: &[u8]) -> (String, bool) {
    match std::str::from_utf8(bytes) {
        Ok(text) => (text.to_owned(), false),
        Err(_) => (String::from_utf8_lossy(bytes).into_owned(), true),
    }
}

fn decode_utf16(bytes: &[u8], combine: fn([u8; 2]) -> u16) -> (String, bool) {
    let (pairs, leftover) = bytes.as_chunks::<2>();
    let units = pairs.iter().map(|pair| combine(*pair));
    let mut lossy = !leftover.is_empty();
    let text = char::decode_utf16(units)
        .map(|unit| {
            unit.unwrap_or_else(|_| {
                lossy = true;
                char::REPLACEMENT_CHARACTER
            })
        })
        .collect();
    (text, lossy)
}

const CANDIDATES: [char; 4] = [',', ';', '\t', '|'];

/// Picks the delimiter that splits the leading lines most consistently.
#[must_use]
pub fn sniff_delimiter(text: &str) -> char {
    let lines: Vec<&str> = text
        .lines()
        .filter(|line| !line.trim().is_empty())
        .take(20)
        .collect();
    let mut best = (',', 0_usize);
    for candidate in CANDIDATES {
        let counts: Vec<usize> = lines
            .iter()
            .map(|line| count_outside_quotes(line, candidate))
            .collect();
        let Some(&least) = counts.iter().min() else {
            continue;
        };
        let consistent = counts.iter().all(|count| *count == least);
        let score = least * 2 + usize::from(consistent && least > 0);
        if score > best.1 {
            best = (candidate, score);
        }
    }
    best.0
}

fn count_outside_quotes(line: &str, wanted: char) -> usize {
    let mut quoted = false;
    let mut count = 0;
    for character in line.chars() {
        if character == '"' {
            quoted = !quoted;
        } else if character == wanted && !quoted {
            count += 1;
        }
    }
    count
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct Parsed {
    pub rows: Vec<Vec<String>>,
    /// The text ended inside a quoted field; the last row may be incomplete.
    pub unterminated_quote: bool,
    /// Parsing stopped at the row or cell limit.
    pub truncated: bool,
}

/// Parses delimited text into rows of fields.
///
/// Fields may be wrapped in double quotes, inside which delimiters and line breaks are
/// literal and `""` stands for one quote. Blank lines are kept as single-field rows so
/// row numbers match the source.
#[must_use]
pub fn parse(text: &str, delimiter: char, max_rows: usize, max_cells: usize) -> Parsed {
    let mut parsed = Parsed::default();
    let mut row: Vec<String> = Vec::new();
    let mut field = String::new();
    let mut quoted = false;
    let mut was_quoted = false;
    let mut cells = 0_usize;
    let mut characters = text.chars().peekable();

    while let Some(character) = characters.next() {
        if quoted {
            if character != '"' {
                field.push(character);
            } else if characters.peek() == Some(&'"') {
                characters.next();
                field.push('"');
            } else {
                quoted = false;
            }
            continue;
        }
        match character {
            '"' if field.is_empty() && !was_quoted => {
                quoted = true;
                was_quoted = true;
            }
            '\r' | '\n' => {
                if character == '\r' && characters.peek() == Some(&'\n') {
                    characters.next();
                }
                row.push(std::mem::take(&mut field));
                was_quoted = false;
                cells += row.len();
                parsed.rows.push(std::mem::take(&mut row));
                if parsed.rows.len() >= max_rows || cells >= max_cells {
                    parsed.truncated = characters.peek().is_some();
                    return parsed;
                }
            }
            _ if character == delimiter => {
                row.push(std::mem::take(&mut field));
                was_quoted = false;
            }
            _ => field.push(character),
        }
    }
    if !field.is_empty() || !row.is_empty() || was_quoted {
        row.push(field);
        parsed.rows.push(row);
    }
    parsed.unterminated_quote = quoted;
    parsed
}

/// Appends one row to `output`, quoting fields that need it, ending with a line feed.
pub fn write_row<S: AsRef<str>>(output: &mut String, fields: &[S], delimiter: char) {
    for (index, field) in fields.iter().enumerate() {
        if index > 0 {
            output.push(delimiter);
        }
        let field = field.as_ref();
        let needs_quotes = field.contains([delimiter, '"', '\r', '\n'])
            || field.starts_with(' ')
            || field.ends_with(' ');
        if needs_quotes {
            output.push('"');
            output.push_str(&field.replace('"', "\"\""));
            output.push('"');
        } else {
            output.push_str(field);
        }
    }
    output.push('\n');
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rows(text: &str, delimiter: char) -> Vec<Vec<String>> {
        parse(text, delimiter, usize::MAX, usize::MAX).rows
    }

    #[test]
    fn parses_quotes_escapes_and_embedded_line_breaks() {
        let text = "name,note\r\n\"Doe, Jane\",\"said \"\"hi\"\"\nthen left\"\nplain,\n";
        assert_eq!(
            rows(text, ','),
            vec![
                vec!["name", "note"],
                vec!["Doe, Jane", "said \"hi\"\nthen left"],
                vec!["plain", ""],
            ]
        );
    }

    #[test]
    fn keeps_blank_lines_and_a_final_row_without_newline() {
        assert_eq!(rows("a\n\nb", ','), vec![vec!["a"], vec![""], vec!["b"]]);
        assert_eq!(rows("a,\"\"", ','), vec![vec!["a", ""]]);
        assert!(rows("", ',').is_empty());
    }

    #[test]
    fn treats_a_quote_inside_an_unquoted_field_as_literal() {
        assert_eq!(rows("5\" disk,x", ','), vec![vec!["5\" disk", "x"]]);
    }

    #[test]
    fn reports_unterminated_quotes_and_limits() {
        let open = parse("a,\"never closed", ',', usize::MAX, usize::MAX);
        assert!(open.unterminated_quote);
        assert_eq!(open.rows, vec![vec!["a", "never closed"]]);

        let limited = parse("1\n2\n3\n", ',', 2, usize::MAX);
        assert!(limited.truncated);
        assert_eq!(limited.rows.len(), 2);
        assert!(!parse("1\n2\n", ',', 2, usize::MAX).truncated);
    }

    #[test]
    fn sniffs_the_consistent_delimiter() {
        assert_eq!(sniff_delimiter("a;b;c\n1;\"x, y\";3\n"), ';');
        assert_eq!(sniff_delimiter("a\tb\n1\t2\n"), '\t');
        assert_eq!(sniff_delimiter("a|b|c\n1|2|3\n"), '|');
        assert_eq!(sniff_delimiter("just one column\n"), ',');
    }

    #[test]
    fn decodes_byte_order_marks() {
        assert_eq!(decode(b"\xEF\xBB\xBFa,b"), ("a,b".to_owned(), false));
        assert_eq!(decode(b"\xFF\xFEa\x00,\x00"), ("a,".to_owned(), false));
        assert_eq!(decode(b"\xFE\xFF\x00a\x00,"), ("a,".to_owned(), false));
        assert!(decode(b"caf\xE9").1);
    }

    #[test]
    fn written_rows_parse_back_unchanged() {
        let fields = [
            "plain",
            "has,comma",
            "has \"quote\"",
            "line\nbreak",
            " padded ",
        ];
        let mut text = String::new();
        write_row(&mut text, &fields, ',');
        assert_eq!(rows(&text, ','), vec![fields.to_vec()]);
    }
}
