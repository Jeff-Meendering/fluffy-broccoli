//! Reading Office Open XML workbooks (`.xlsx`, `.xlsm`).
//!
//! A workbook is a zip container of XML parts. This reader follows the package
//! relationships to each worksheet and resolves shared strings and date-formatted
//! numbers, so cells come out as the text a person would see. Formulas are not
//! evaluated; the value the producing application cached is used.

use std::collections::HashMap;
use std::io::{Cursor, Read};

use rollcall_model::date::spreadsheet_serial_to_date;
use rollcall_model::{CoverageGap, GapKind, Table};
use zip::ZipArchive;
use zip::result::ZipError;

use crate::xml::{Event, Reader, attribute, local_name};
use crate::{Extraction, Limits};

/// The widest sheet a workbook can hold; cells beyond it are ignored.
const MAX_COLUMNS: usize = 16_384;

type Archive<'a> = ZipArchive<Cursor<&'a [u8]>>;

pub(crate) fn read(bytes: &[u8], limits: &Limits) -> Extraction {
    if bytes.starts_with(&[0xD0, 0xCF, 0x11, 0xE0]) {
        return Extraction::gap(
            GapKind::Unreadable,
            "Workbook is password-protected or stored in a legacy container; \
             its contents were not read.",
        );
    }
    let Ok(mut archive) = ZipArchive::new(Cursor::new(bytes)) else {
        return Extraction::gap(
            GapKind::Unreadable,
            "File is not a readable workbook container.",
        );
    };
    read_workbook(&mut archive, limits)
        .unwrap_or_else(|detail| Extraction::gap(GapKind::Unreadable, detail))
}

fn read_workbook(archive: &mut Archive<'_>, limits: &Limits) -> Result<Extraction, String> {
    let root = match read_part(archive, "_rels/.rels", limits)? {
        Some(text) => relationships(&text, "")?,
        None => Vec::new(),
    };
    let workbook_path = root
        .iter()
        .find(|relationship| relationship.kind.ends_with("/officeDocument"))
        .map_or_else(
            || "xl/workbook.xml".to_owned(),
            |found| found.target.clone(),
        );
    let workbook_text = read_part(archive, &workbook_path, limits)?
        .ok_or("Container has no workbook part; it may not be a spreadsheet.")?;
    let workbook = parse_workbook(&workbook_text)?;

    let base = parent_directory(&workbook_path);
    let links = match read_part(archive, &relationships_path(&workbook_path), limits)? {
        Some(text) => relationships(&text, base)?,
        None => Vec::new(),
    };
    let part_of_kind = |suffix: &str, fallback: &str| {
        links
            .iter()
            .find(|relationship| relationship.kind.ends_with(suffix))
            .map_or_else(|| resolve(base, fallback), |found| found.target.clone())
    };
    let shared = match read_part(
        archive,
        &part_of_kind("/sharedStrings", "sharedStrings.xml"),
        limits,
    )? {
        Some(text) => parse_shared_strings(&text)?,
        None => Vec::new(),
    };
    let date_styles = match read_part(archive, &part_of_kind("/styles", "styles.xml"), limits)? {
        Some(text) => parse_styles(&text)?,
        None => Vec::new(),
    };
    let context = SheetContext {
        shared: &shared,
        date_styles: &date_styles,
        date1904: workbook.date1904,
        limits,
    };

    let mut extraction = Extraction::default();
    for sheet in workbook.sheets {
        let scope = Some(sheet.name);
        let Some(link) = links
            .iter()
            .find(|relationship| relationship.id == sheet.link)
        else {
            extraction.gaps.push(CoverageGap::new(
                scope,
                GapKind::Unreadable,
                "Sheet is listed in the workbook but has no content part.",
            ));
            continue;
        };
        if !link.kind.ends_with("/worksheet") {
            // Chart and dialog sheets hold no cell data.
            continue;
        }
        let parsed = read_part(archive, &link.target, limits)
            .and_then(|text| text.ok_or_else(|| "Sheet content part is missing.".to_owned()))
            .and_then(|text| parse_sheet(&text, &context));
        match parsed {
            Ok(sheet) => {
                if sheet.truncated {
                    extraction.gaps.push(CoverageGap::new(
                        scope.clone(),
                        GapKind::Truncated,
                        format!(
                            "Reading stopped after {} rows at the size limit.",
                            sheet.rows.len()
                        ),
                    ));
                }
                if !sheet.rows.is_empty() {
                    extraction.tables.push(Table {
                        scope,
                        first_row: sheet.first_row,
                        first_column: 0,
                        rows: sheet.rows,
                    });
                }
            }
            Err(detail) => {
                extraction
                    .gaps
                    .push(CoverageGap::new(scope, GapKind::Unreadable, detail));
            }
        }
    }
    Ok(extraction)
}

/// Decompresses one part as UTF-8 text. `Ok(None)` means the part does not exist.
fn read_part(
    archive: &mut Archive<'_>,
    path: &str,
    limits: &Limits,
) -> Result<Option<String>, String> {
    let entry = match archive.by_name(path) {
        Ok(entry) => entry,
        Err(ZipError::FileNotFound) => return Ok(None),
        Err(_) => return Err(format!("Workbook part {path} could not be opened.")),
    };
    let mut data = Vec::new();
    entry
        .take(limits.max_part_bytes.saturating_add(1))
        .read_to_end(&mut data)
        .map_err(|_| format!("Workbook part {path} could not be decompressed."))?;
    if u64::try_from(data.len()).unwrap_or(u64::MAX) > limits.max_part_bytes {
        return Err(format!(
            "Workbook part {path} is larger than the size limit."
        ));
    }
    String::from_utf8(data)
        .map(Some)
        .map_err(|_| format!("Workbook part {path} is not UTF-8 text."))
}

struct Relationship {
    id: String,
    kind: String,
    target: String,
}

fn relationships(text: &str, base: &str) -> Result<Vec<Relationship>, String> {
    let mut found = Vec::new();
    for event in Reader::new(text) {
        let Event::Start {
            name, attributes, ..
        } = event.map_err(|error| error.to_string())?
        else {
            continue;
        };
        if local_name(name) != "Relationship"
            || attribute(attributes, "TargetMode").as_deref() == Some("External")
        {
            continue;
        }
        if let (Some(id), Some(kind), Some(target)) = (
            attribute(attributes, "Id"),
            attribute(attributes, "Type"),
            attribute(attributes, "Target"),
        ) {
            found.push(Relationship {
                id,
                kind,
                target: resolve(base, &target),
            });
        }
    }
    Ok(found)
}

fn parent_directory(part: &str) -> &str {
    part.rsplit_once('/').map_or("", |(directory, _)| directory)
}

fn relationships_path(part: &str) -> String {
    let (directory, file) = part.rsplit_once('/').unwrap_or(("", part));
    resolve(directory, &format!("_rels/{file}.rels"))
}

/// Resolves a relationship target against the directory of the part that declared it.
fn resolve(base: &str, target: &str) -> String {
    let mut segments: Vec<&str> = match target.strip_prefix('/') {
        Some(_) => Vec::new(),
        None => base
            .split('/')
            .filter(|segment| !segment.is_empty())
            .collect(),
    };
    for segment in target.split('/') {
        match segment {
            "" | "." => {}
            ".." => {
                segments.pop();
            }
            other => segments.push(other),
        }
    }
    segments.join("/")
}

struct SheetEntry {
    name: String,
    link: String,
}

struct Workbook {
    sheets: Vec<SheetEntry>,
    date1904: bool,
}

fn parse_workbook(text: &str) -> Result<Workbook, String> {
    let mut workbook = Workbook {
        sheets: Vec::new(),
        date1904: false,
    };
    for event in Reader::new(text) {
        let Event::Start {
            name, attributes, ..
        } = event.map_err(|error| error.to_string())?
        else {
            continue;
        };
        match local_name(name) {
            "workbookPr" => {
                workbook.date1904 = matches!(
                    attribute(attributes, "date1904").as_deref(),
                    Some("1" | "true")
                );
            }
            "sheet" => {
                if let (Some(name), Some(link)) =
                    (attribute(attributes, "name"), attribute(attributes, "id"))
                {
                    workbook.sheets.push(SheetEntry { name, link });
                }
            }
            _ => {}
        }
    }
    Ok(workbook)
}

fn parse_shared_strings(text: &str) -> Result<Vec<String>, String> {
    let mut strings = Vec::new();
    let mut current = String::new();
    let (mut in_text, mut phonetic) = (false, false);
    for event in Reader::new(text) {
        let event = event.map_err(|error| error.to_string())?;
        match event {
            Event::Start { name, empty, .. } => match local_name(name) {
                "si" if empty => strings.push(String::new()),
                "si" => current.clear(),
                "rPh" => phonetic = !empty,
                "t" => in_text = !empty,
                _ => {}
            },
            Event::End { name } => match local_name(name) {
                "si" => strings.push(decode_escapes(std::mem::take(&mut current))),
                "rPh" => phonetic = false,
                "t" => in_text = false,
                _ => {}
            },
            Event::Text { .. } if in_text && !phonetic => current.push_str(&event.text()),
            Event::Text { .. } => {}
        }
    }
    Ok(strings)
}

/// Returns, for each cell style index, whether it formats numbers as dates.
fn parse_styles(text: &str) -> Result<Vec<bool>, String> {
    let mut custom: HashMap<u32, bool> = HashMap::new();
    let mut styles = Vec::new();
    let mut in_cell_formats = false;
    for event in Reader::new(text) {
        match event.map_err(|error| error.to_string())? {
            Event::Start {
                name,
                attributes,
                empty,
            } => match local_name(name) {
                "numFmt" => {
                    let id = attribute(attributes, "numFmtId").and_then(|id| id.parse().ok());
                    if let (Some(id), Some(code)) = (id, attribute(attributes, "formatCode")) {
                        custom.insert(id, is_date_code(&code));
                    }
                }
                "cellXfs" => in_cell_formats = !empty,
                "xf" if in_cell_formats => {
                    let id: u32 = attribute(attributes, "numFmtId")
                        .and_then(|id| id.parse().ok())
                        .unwrap_or(0);
                    styles.push(
                        custom
                            .get(&id)
                            .copied()
                            .unwrap_or_else(|| is_builtin_date(id)),
                    );
                }
                _ => {}
            },
            Event::End { name } if local_name(name) == "cellXfs" => in_cell_formats = false,
            _ => {}
        }
    }
    Ok(styles)
}

const fn is_builtin_date(format: u32) -> bool {
    matches!(format, 14..=22 | 27..=36 | 45..=47 | 50..=58)
}

/// True when a custom number format renders a number as a date or time of day.
fn is_date_code(code: &str) -> bool {
    let mut quoted = false;
    let mut bracketed = false;
    let mut characters = code.chars();
    while let Some(character) = characters.next() {
        match character {
            '"' => quoted = !quoted,
            _ if quoted => {}
            '\\' => {
                characters.next();
            }
            '[' => bracketed = true,
            ']' => bracketed = false,
            _ if bracketed => {}
            'y' | 'Y' | 'm' | 'M' | 'd' | 'D' | 'h' | 'H' | 's' | 'S' => return true,
            _ => {}
        }
    }
    false
}

/// Decodes `_xHHHH_` sequences, which workbooks use for characters XML cannot carry.
fn decode_escapes(text: String) -> String {
    if !text.contains("_x") {
        return text;
    }
    let mut output = String::with_capacity(text.len());
    let mut rest = text.as_str();
    while let Some(start) = rest.find("_x") {
        output.push_str(&rest[..start]);
        let candidate = &rest[start..];
        let decoded = candidate
            .get(2..6)
            .filter(|_| candidate.as_bytes().get(6) == Some(&b'_'))
            .and_then(|hex| u32::from_str_radix(hex, 16).ok())
            .and_then(char::from_u32);
        if let Some(character) = decoded {
            output.push(character);
            rest = &candidate[7..];
        } else {
            output.push_str("_x");
            rest = &candidate[2..];
        }
    }
    output.push_str(rest);
    output
}

struct SheetContext<'a> {
    shared: &'a [String],
    date_styles: &'a [bool],
    date1904: bool,
    limits: &'a Limits,
}

struct Sheet {
    first_row: u32,
    rows: Vec<Vec<String>>,
    truncated: bool,
}

struct PendingCell {
    column: usize,
    kind: Option<String>,
    style: usize,
    text: String,
}

fn parse_sheet(text: &str, context: &SheetContext<'_>) -> Result<Sheet, String> {
    // Sparse cells first: (row, column, text) for every non-empty cell.
    let mut cells: Vec<(u32, usize, String)> = Vec::new();
    let mut truncated = false;
    let (mut row, mut next_row, mut next_column) = (0_u32, 0_u32, 0_usize);
    let mut pending: Option<PendingCell> = None;
    let (mut capturing, mut inline, mut phonetic) = (false, false, false);

    for event in Reader::new(text) {
        let event = event.map_err(|error| error.to_string())?;
        match event {
            Event::Start {
                name,
                attributes,
                empty,
            } => match local_name(name) {
                "row" => {
                    row = attribute(attributes, "r")
                        .and_then(|number| number.parse::<u32>().ok())
                        .and_then(|number| number.checked_sub(1))
                        .unwrap_or(next_row);
                    next_row = row.saturating_add(1);
                    next_column = 0;
                }
                "c" => {
                    let column = attribute(attributes, "r")
                        .and_then(|reference| column_of(&reference))
                        .unwrap_or(next_column);
                    next_column = column.saturating_add(1);
                    pending = (!empty).then(|| PendingCell {
                        column,
                        kind: attribute(attributes, "t"),
                        style: attribute(attributes, "s")
                            .and_then(|style| style.parse().ok())
                            .unwrap_or(0),
                        text: String::new(),
                    });
                }
                "v" => capturing = !empty,
                "is" => inline = !empty,
                "rPh" => phonetic = !empty,
                "t" if inline && !phonetic => capturing = !empty,
                _ => {}
            },
            Event::End { name } => match local_name(name) {
                "v" | "t" => capturing = false,
                "is" => inline = false,
                "rPh" => phonetic = false,
                "c" => {
                    if let Some(cell) = pending.take() {
                        let column = cell.column;
                        let value = cell_text(cell, context);
                        if !value.is_empty() && column < MAX_COLUMNS {
                            cells.push((row, column, value));
                            if cells.len() >= context.limits.max_cells {
                                truncated = true;
                                break;
                            }
                        }
                    }
                }
                "sheetData" => break,
                _ => {}
            },
            Event::Text { .. } => {
                if let Some(cell) = pending.as_mut().filter(|_| capturing) {
                    cell.text.push_str(&event.text());
                }
            }
        }
    }
    Ok(assemble(cells, truncated, context.limits))
}

/// Lays sparse cells out as rows, keeping blank rows between the first and last.
fn assemble(mut cells: Vec<(u32, usize, String)>, mut truncated: bool, limits: &Limits) -> Sheet {
    cells.sort_by_key(|(row, column, _)| (*row, *column));
    let Some(first_row) = cells.first().map(|(row, _, _)| *row) else {
        return Sheet {
            first_row: 0,
            rows: Vec::new(),
            truncated,
        };
    };
    let mut rows: Vec<Vec<String>> = Vec::new();
    let mut allocated = 0_usize;
    for (row, column, value) in cells {
        let index = usize::try_from(row - first_row).unwrap_or(usize::MAX);
        let growth = (index + 1).saturating_sub(rows.len());
        if index >= limits.max_rows || allocated + growth + column + 1 > limits.max_cells.max(1) * 4
        {
            truncated = true;
            break;
        }
        if growth > 0 {
            rows.resize_with(index + 1, Vec::new);
            allocated += growth;
        }
        let cells_in_row = &mut rows[index];
        if cells_in_row.len() <= column {
            allocated += column + 1 - cells_in_row.len();
            cells_in_row.resize_with(column + 1, String::new);
        }
        cells_in_row[column] = value;
    }
    Sheet {
        first_row,
        rows,
        truncated,
    }
}

/// Zero-based column of a cell reference such as `AB12`.
fn column_of(reference: &str) -> Option<usize> {
    let mut column = 0_usize;
    let mut letters = 0;
    for byte in reference.bytes() {
        if !byte.is_ascii_alphabetic() {
            break;
        }
        column = column * 26 + usize::from(byte.to_ascii_uppercase() - b'A') + 1;
        letters += 1;
        if letters > 3 {
            return None;
        }
    }
    column.checked_sub(1)
}

fn cell_text(cell: PendingCell, context: &SheetContext<'_>) -> String {
    match cell.kind.as_deref() {
        Some("s") => cell
            .text
            .trim()
            .parse::<usize>()
            .ok()
            .and_then(|index| context.shared.get(index))
            .cloned()
            .unwrap_or_default(),
        Some("inlineStr" | "str") => decode_escapes(cell.text),
        Some("b") => if cell.text.trim() == "1" {
            "TRUE"
        } else {
            "FALSE"
        }
        .to_owned(),
        Some("e") => String::new(),
        Some("d") => cell.text.trim().to_owned(),
        _ => {
            let is_date = context
                .date_styles
                .get(cell.style)
                .copied()
                .unwrap_or(false);
            number_text(cell.text.trim(), is_date, context.date1904)
        }
    }
}

fn number_text(text: &str, is_date: bool, date1904: bool) -> String {
    let Ok(value) = text.parse::<f64>() else {
        return text.to_owned();
    };
    if is_date && let Some(date) = spreadsheet_serial_to_date(value, date1904) {
        return date.to_text();
    }
    if value.is_finite() && value.fract() == 0.0 && value.abs() < 1e15 {
        // Integral and well inside the i64 range, so the conversion is exact.
        #[allow(clippy::cast_possible_truncation)]
        return (value as i64).to_string();
    }
    text.to_owned()
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use zip::ZipWriter;
    use zip::write::SimpleFileOptions;

    use super::*;

    const ROOT_RELS: &str = r#"<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>"#;
    const WORKBOOK: &str = r#"<workbook xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets><sheet name="Staff &amp; Pay" sheetId="1" r:id="rId1"/><sheet name="Empty" sheetId="2" r:id="rId2"/><sheet name="Lost" sheetId="3" r:id="rId9"/></sheets></workbook>"#;
    const WORKBOOK_RELS: &str = r#"<Relationships><Relationship Id="rId1" Type="http://x/relationships/worksheet" Target="worksheets/sheet1.xml"/><Relationship Id="rId2" Type="http://x/relationships/worksheet" Target="/xl/worksheets/sheet2.xml"/><Relationship Id="rId3" Type="http://x/relationships/sharedStrings" Target="sharedStrings.xml"/><Relationship Id="rId4" Type="http://x/relationships/styles" Target="styles.xml"/></Relationships>"#;
    const SHARED: &str = r#"<sst><si><t>Name</t></si><si><r><t>Jane </t></r><r><t>Doe</t></r><rPh><t>ignored</t></rPh></si><si><t>line_x000A_break</t></si></sst>"#;
    const STYLES: &str = r#"<styleSheet><numFmts><numFmt numFmtId="164" formatCode="yyyy\-mm\-dd"/><numFmt numFmtId="165" formatCode="0.00&quot; days&quot;"/></numFmts><cellStyleXfs><xf numFmtId="14"/></cellStyleXfs><cellXfs><xf numFmtId="0"/><xf numFmtId="14"/><xf numFmtId="164"/><xf numFmtId="165"/></cellXfs></styleSheet>"#;
    const SHEET: &str = r#"<worksheet><sheetData>
        <row r="3"><c r="A3" t="s"><v>0</v></c><c r="C3" t="inlineStr"><is><t>SSN</t></is></c></row>
        <row r="4"><c r="A4" t="s"><v>1</v></c><c r="B4" s="1"><v>29254</v></c><c r="C4"><v>12345678</v></c><c r="D4" s="2"><v>29254.5</v></c></row>
        <row r="6"><c r="A6" t="s"><v>2</v></c><c r="B6" t="b"><v>1</v></c><c r="C6" t="str"><f>A1&amp;"x"</f><v>calc</v></c><c r="D6" t="e"><v>#N/A</v></c><c r="E6" s="3"><v>2.5</v></c></row>
    </sheetData></worksheet>"#;

    fn workbook(parts: &[(&str, &str)]) -> Vec<u8> {
        let mut writer = ZipWriter::new(Cursor::new(Vec::new()));
        for (path, text) in parts {
            writer
                .start_file(*path, SimpleFileOptions::default())
                .unwrap();
            writer.write_all(text.as_bytes()).unwrap();
        }
        writer.finish().unwrap().into_inner()
    }

    fn standard() -> Vec<u8> {
        workbook(&[
            ("_rels/.rels", ROOT_RELS),
            ("xl/workbook.xml", WORKBOOK),
            ("xl/_rels/workbook.xml.rels", WORKBOOK_RELS),
            ("xl/sharedStrings.xml", SHARED),
            ("xl/styles.xml", STYLES),
            ("xl/worksheets/sheet1.xml", SHEET),
            (
                "xl/worksheets/sheet2.xml",
                "<worksheet><sheetData/></worksheet>",
            ),
        ])
    }

    #[test]
    fn reads_cells_with_coordinates_strings_and_dates() {
        let extraction = read(&standard(), &Limits::default());
        assert_eq!(extraction.tables.len(), 1);
        let table = &extraction.tables[0];
        assert_eq!(table.scope.as_deref(), Some("Staff & Pay"));
        assert_eq!(table.first_row, 2);
        assert_eq!(table.rows[0], vec!["Name", "", "SSN"]);
        assert_eq!(
            table.rows[1],
            vec!["Jane Doe", "1980-02-03", "12345678", "1980-02-03 12:00:00"]
        );
        assert!(table.rows[2].is_empty(), "the blank row keeps its place");
        assert_eq!(
            table.rows[3],
            vec!["line\nbreak", "TRUE", "calc", "", "2.5"]
        );
    }

    #[test]
    fn reports_a_sheet_without_a_content_part_and_skips_empty_sheets() {
        let extraction = read(&standard(), &Limits::default());
        assert_eq!(extraction.gaps.len(), 1);
        assert_eq!(extraction.gaps[0].scope.as_deref(), Some("Lost"));
        assert_eq!(extraction.gaps[0].kind, GapKind::Unreadable);
    }

    #[test]
    fn reports_containers_that_are_not_workbooks() {
        for bytes in [
            b"not a zip at all".to_vec(),
            vec![0xD0, 0xCF, 0x11, 0xE0, 0, 0, 0, 0],
            workbook(&[("word/document.xml", "<document/>")]),
        ] {
            let extraction = read(&bytes, &Limits::default());
            assert!(extraction.tables.is_empty());
            assert_eq!(extraction.gaps[0].kind, GapKind::Unreadable);
        }
    }

    #[test]
    fn reports_malformed_sheets_and_oversized_parts_per_sheet() {
        let broken = workbook(&[
            ("xl/workbook.xml", WORKBOOK),
            ("xl/_rels/workbook.xml.rels", WORKBOOK_RELS),
            ("xl/worksheets/sheet1.xml", "<worksheet><sheetData><row"),
            ("xl/worksheets/sheet2.xml", SHEET),
        ]);
        let extraction = read(&broken, &Limits::default());
        assert_eq!(extraction.tables.len(), 1);
        assert_eq!(extraction.tables[0].scope.as_deref(), Some("Empty"));
        assert!(
            extraction
                .gaps
                .iter()
                .any(|gap| gap.scope.as_deref() == Some("Staff & Pay"))
        );

        let tiny = Limits {
            max_part_bytes: 64,
            ..Limits::default()
        };
        let limited = read(&standard(), &tiny);
        assert!(limited.tables.is_empty());
        assert_eq!(limited.gaps[0].kind, GapKind::Unreadable);
    }

    #[test]
    fn stops_at_the_row_limit_and_says_so() {
        let limits = Limits {
            max_rows: 2,
            ..Limits::default()
        };
        let extraction = read(&standard(), &limits);
        assert_eq!(extraction.tables[0].rows.len(), 2);
        assert!(
            extraction
                .gaps
                .iter()
                .any(|gap| gap.kind == GapKind::Truncated)
        );
    }

    #[test]
    fn recognises_date_formats_and_cell_references() {
        assert!(is_date_code("dd/mm/yyyy"));
        assert!(is_date_code("[$-409]mmmm d, yyyy"));
        assert!(!is_date_code("#,##0.00"));
        assert!(!is_date_code("0.0\" hours\""));
        assert!(!is_date_code("[Red]0"));
        assert!(!is_date_code("General"));
        assert_eq!(column_of("A1"), Some(0));
        assert_eq!(column_of("AB12"), Some(27));
        assert_eq!(column_of("XFD1"), Some(16_383));
        assert_eq!(column_of("12"), None);
    }

    #[test]
    fn resolves_relationship_targets() {
        assert_eq!(
            resolve("xl", "worksheets/sheet1.xml"),
            "xl/worksheets/sheet1.xml"
        );
        assert_eq!(resolve("xl", "/xl/styles.xml"), "xl/styles.xml");
        assert_eq!(
            resolve("xl/worksheets", "../sharedStrings.xml"),
            "xl/sharedStrings.xml"
        );
        assert_eq!(
            relationships_path("xl/workbook.xml"),
            "xl/_rels/workbook.xml.rels"
        );
    }
}
