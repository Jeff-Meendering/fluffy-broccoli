//! Writing small Office Open XML workbooks for synthetic test data.

use std::fmt::Write as _;
use std::io::{Cursor, Write};

use anyhow::Result;
use zip::ZipWriter;
use zip::write::SimpleFileOptions;

pub enum Cell {
    Text(String),
    /// Stored as a number with no formatting, the way a spreadsheet keeps an identifier
    /// typed in without quotes; leading zeros do not survive.
    Number(u64),
    /// A date serial number displayed through a date format.
    Date(i64),
}

pub struct Sheet {
    pub name: String,
    pub rows: Vec<Vec<Cell>>,
}

const CONTENT_TYPES_HEAD: &str = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/><Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>"#;
const ROOT_RELATIONSHIPS: &str = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>"#;
const STYLES: &str = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?><styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><fonts count="1"><font><sz val="11"/><name val="Calibri"/></font></fonts><fills count="2"><fill><patternFill patternType="none"/></fill><fill><patternFill patternType="gray125"/></fill></fills><borders count="1"><border><left/><right/><top/><bottom/><diagonal/></border></borders><cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs><cellXfs count="2"><xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/><xf numFmtId="14" fontId="0" fillId="0" borderId="0" xfId="0" applyNumberFormat="1"/></cellXfs></styleSheet>"#;
const RELATIONSHIP_BASE: &str =
    "http://schemas.openxmlformats.org/officeDocument/2006/relationships";

fn escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn column_letters(mut index: usize) -> String {
    let mut letters = Vec::new();
    loop {
        letters.push(b'A' + u8::try_from(index % 26).unwrap_or(0));
        if index < 26 {
            break;
        }
        index = index / 26 - 1;
    }
    letters.reverse();
    String::from_utf8_lossy(&letters).into_owned()
}

fn sheet_xml(sheet: &Sheet) -> Result<String> {
    let mut xml = String::from(
        r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?><worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData>"#,
    );
    for (row_index, row) in sheet.rows.iter().enumerate() {
        if row.is_empty() {
            continue;
        }
        let number = row_index + 1;
        write!(xml, r#"<row r="{number}">"#)?;
        for (column, cell) in row.iter().enumerate() {
            let reference = format!("{}{number}", column_letters(column));
            match cell {
                Cell::Text(text) => write!(
                    xml,
                    r#"<c r="{reference}" t="inlineStr"><is><t xml:space="preserve">{}</t></is></c>"#,
                    escape(text)
                )?,
                Cell::Number(value) => write!(xml, r#"<c r="{reference}"><v>{value}</v></c>"#)?,
                Cell::Date(serial) => {
                    write!(xml, r#"<c r="{reference}" s="1"><v>{serial}</v></c>"#)?
                }
            }
        }
        xml.push_str("</row>");
    }
    xml.push_str("</sheetData></worksheet>");
    Ok(xml)
}

/// Builds a workbook file in memory.
pub fn write_workbook(sheets: &[Sheet]) -> Result<Vec<u8>> {
    let mut content_types = String::from(CONTENT_TYPES_HEAD);
    let mut workbook = format!(
        r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?><workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="{RELATIONSHIP_BASE}"><sheets>"#
    );
    let mut relationships = String::from(
        r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">"#,
    );
    for (index, sheet) in sheets.iter().enumerate() {
        let number = index + 1;
        write!(
            content_types,
            r#"<Override PartName="/xl/worksheets/sheet{number}.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>"#
        )?;
        write!(
            workbook,
            r#"<sheet name="{}" sheetId="{number}" r:id="rId{number}"/>"#,
            escape(&sheet.name)
        )?;
        write!(
            relationships,
            r#"<Relationship Id="rId{number}" Type="{RELATIONSHIP_BASE}/worksheet" Target="worksheets/sheet{number}.xml"/>"#
        )?;
    }
    content_types.push_str("</Types>");
    workbook.push_str("</sheets></workbook>");
    write!(
        relationships,
        r#"<Relationship Id="rId{}" Type="{RELATIONSHIP_BASE}/styles" Target="styles.xml"/></Relationships>"#,
        sheets.len() + 1
    )?;

    let mut writer = ZipWriter::new(Cursor::new(Vec::new()));
    let mut add = |path: &str, text: &str| -> Result<()> {
        writer.start_file(path, SimpleFileOptions::default())?;
        writer.write_all(text.as_bytes())?;
        Ok(())
    };
    add("[Content_Types].xml", &content_types)?;
    add("_rels/.rels", ROOT_RELATIONSHIPS)?;
    add("xl/workbook.xml", &workbook)?;
    add("xl/_rels/workbook.xml.rels", &relationships)?;
    add("xl/styles.xml", STYLES)?;
    for (index, sheet) in sheets.iter().enumerate() {
        add(
            &format!("xl/worksheets/sheet{}.xml", index + 1),
            &sheet_xml(sheet)?,
        )?;
    }
    Ok(writer.finish()?.into_inner())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn column_letters_follow_spreadsheet_order() {
        let letters: Vec<String> = [0, 25, 26, 27, 701, 702]
            .into_iter()
            .map(column_letters)
            .collect();
        assert_eq!(letters, ["A", "Z", "AA", "AB", "ZZ", "AAA"]);
    }
}
