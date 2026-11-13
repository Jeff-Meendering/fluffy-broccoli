//! Recognises which columns of a table hold which personal data elements.
//!
//! Headers are read first. Columns without a usable header fall back to strict checks
//! of the values themselves, which only accept formats that are hard to mistake.

mod header;
mod value;

use rollcall_model::{ElementKind, Method, Table};

pub use header::{HeaderMeaning, Role, classify_header, normalize_header};
pub use value::{Normalized, is_placeholder, looks_like, normalize};

/// How far down a sheet a header row is looked for, past any title lines.
const HEADER_SEARCH_ROWS: usize = 25;
/// How many values are sampled when a column is typed from its content.
const SAMPLE_CELLS: usize = 200;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Column {
    /// Index into each row of the table.
    pub index: usize,
    pub header: Option<String>,
    pub role: Role,
    pub relation: Option<String>,
    pub method: Method,
}

/// The recognised columns of one table.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Schema {
    /// Index of the header row within the table, when one was found.
    pub header_row: Option<usize>,
    pub columns: Vec<Column>,
}

impl Schema {
    /// Index of the first row that holds data rather than titles or headers.
    #[must_use]
    pub fn first_data_row(&self) -> usize {
        self.header_row.map_or(0, |row| row + 1)
    }
}

#[must_use]
pub fn infer_schema(table: &Table) -> Schema {
    let header_row = find_header_row(table);
    let first_data_row = header_row.map_or(0, |row| row + 1);
    let width = table.rows.iter().map(Vec::len).max().unwrap_or(0);
    let mut columns = Vec::new();

    for index in 0..width {
        let header = header_row
            .and_then(|row| table.rows[row].get(index))
            .map(|cell| cell.trim())
            .filter(|cell| !cell.is_empty());
        let samples = || {
            table.rows[first_data_row.min(table.rows.len())..]
                .iter()
                .filter_map(move |row| row.get(index))
                .filter(|cell| !is_placeholder(cell))
                .take(SAMPLE_CELLS)
        };
        let from_header = header
            .and_then(classify_header)
            .filter(|_| header.is_none_or(|text| !contradicted_by_content(text, samples())));
        if let Some(meaning) = from_header {
            columns.push(Column {
                index,
                header: header.map(str::to_owned),
                role: meaning.role,
                relation: meaning.relation,
                method: Method::Header,
            });
        } else if let Some(kind) = kind_from_content(samples()) {
            columns.push(Column {
                index,
                header: header.map(str::to_owned),
                role: Role::Element(kind),
                relation: None,
                method: Method::Content,
            });
        }
    }
    Schema {
        header_row,
        columns,
    }
}

/// The header is the row, near the top, where the most cells read as known headers.
fn find_header_row(table: &Table) -> Option<usize> {
    let mut best: Option<(usize, usize)> = None;
    for (index, row) in table.rows.iter().take(HEADER_SEARCH_ROWS).enumerate() {
        let recognised = row
            .iter()
            .filter(|cell| classify_header(cell).is_some())
            .count();
        if recognised > best.map_or(0, |(_, count)| count) {
            best = Some((index, recognised));
        }
    }
    best.map(|(index, _)| index)
}

/// A loosely worded name header (`Customer`, `Member`) over values that are not names.
fn contradicted_by_content<'a>(header: &str, samples: impl Iterator<Item = &'a String>) -> bool {
    if !header::is_loose_name_header(header) {
        return false;
    }
    let (mut total, mut names) = (0_usize, 0_usize);
    for cell in samples {
        total += 1;
        names += usize::from(normalize(ElementKind::Name, cell).valid);
    }
    total > 0 && names * 2 < total
}

fn kind_from_content<'a>(samples: impl Iterator<Item = &'a String>) -> Option<ElementKind> {
    let cells: Vec<&String> = samples.collect();
    if cells.is_empty() {
        return None;
    }
    value::CONTENT_KINDS.into_iter().find(|kind| {
        let matching = cells.iter().filter(|cell| looks_like(*kind, cell)).count();
        // At least four in five, so a stray typo does not hide the whole column.
        matching * 5 >= cells.len() * 4
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn table(rows: &[&[&str]]) -> Table {
        Table {
            scope: None,
            first_row: 0,
            first_column: 0,
            rows: rows
                .iter()
                .map(|row| row.iter().map(|cell| (*cell).to_owned()).collect())
                .collect(),
        }
    }

    fn roles(schema: &Schema) -> Vec<(usize, Role, Method)> {
        schema
            .columns
            .iter()
            .map(|column| (column.index, column.role, column.method))
            .collect()
    }

    #[test]
    fn finds_the_header_below_title_rows() {
        let schema = infer_schema(&table(&[
            &["Benefits Enrollment 2026"],
            &[],
            &["Name", "DOB", "Dept", "Member ID"],
            &["Jane Doe", "1980-02-03", "Ops", "M1234567"],
        ]));
        assert_eq!(schema.header_row, Some(2));
        assert_eq!(schema.first_data_row(), 3);
        assert_eq!(
            roles(&schema),
            vec![
                (0, Role::Element(ElementKind::Name), Method::Header),
                (1, Role::Element(ElementKind::DateOfBirth), Method::Header),
                (
                    3,
                    Role::Element(ElementKind::HealthInsuranceId),
                    Method::Header
                ),
            ]
        );
    }

    #[test]
    fn types_headerless_columns_from_unambiguous_content() {
        let schema = infer_schema(&table(&[
            &[
                "a@example.com",
                "219-09-9999",
                "415-555-0134",
                "4155550134",
                "blue",
            ],
            &[
                "b@example.com",
                "219-09-9998",
                "415-555-0135",
                "4155550135",
                "green",
            ],
            &["c@example.com", "219-09-9997", "N/A", "4155550136", "red"],
        ]));
        assert_eq!(schema.header_row, None);
        assert_eq!(
            roles(&schema),
            vec![
                (0, Role::Element(ElementKind::Email), Method::Content),
                (1, Role::Element(ElementKind::Ssn), Method::Content),
                (2, Role::Element(ElementKind::Phone), Method::Content),
            ]
        );
    }

    #[test]
    fn unheaded_columns_beside_a_header_row_are_still_checked() {
        let schema = infer_schema(&table(&[
            &["Name", "Contact Info", "Notes"],
            &["Jane Doe", "jane@example.com", "x"],
            &["John Roe", "john@example.com", "y"],
        ]));
        assert_eq!(
            roles(&schema),
            vec![
                (0, Role::Element(ElementKind::Name), Method::Header),
                (1, Role::Element(ElementKind::Email), Method::Content),
            ]
        );
    }

    #[test]
    fn a_loose_name_header_over_numbers_is_not_a_name() {
        let schema = infer_schema(&table(&[
            &["Customer", "Email"],
            &["100234", "a@example.com"],
            &["100235", "b@example.com"],
        ]));
        assert_eq!(
            roles(&schema),
            vec![(1, Role::Element(ElementKind::Email), Method::Header)]
        );

        let named = infer_schema(&table(&[
            &["Customer", "Email"],
            &["Jane Doe", "a@example.com"],
        ]));
        assert_eq!(named.columns.len(), 2);
    }

    #[test]
    fn a_table_without_personal_columns_has_an_empty_schema() {
        let schema = infer_schema(&table(&[&["SKU", "Qty"], &["A-1", "4"], &["A-2", "9"]]));
        assert_eq!(schema, Schema::default());
        assert_eq!(infer_schema(&table(&[])), Schema::default());
    }
}
