//! Writing small Word documents for synthetic test data.

use std::fmt::Write as _;
use std::io::{Cursor, Write};

use anyhow::Result;
use zip::ZipWriter;
use zip::write::SimpleFileOptions;

const CONTENT_TYPES: &str = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>"#;
const RELATIONSHIPS: &str = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>"#;

fn escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn paragraph(xml: &mut String, text: &str) -> Result<()> {
    if text.is_empty() {
        xml.push_str("<w:p/>");
    } else {
        write!(
            xml,
            r#"<w:p><w:r><w:t xml:space="preserve">{}</w:t></w:r></w:p>"#,
            escape(text)
        )?;
    }
    Ok(())
}

/// Builds a document with some opening paragraphs, one table, and closing paragraphs.
pub fn write_document(
    opening: &[&str],
    table: &[Vec<String>],
    closing: &[&str],
) -> Result<Vec<u8>> {
    let mut xml = String::from(
        r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body>"#,
    );
    for text in opening {
        paragraph(&mut xml, text)?;
    }
    xml.push_str("<w:tbl>");
    for row in table {
        xml.push_str("<w:tr>");
        for cell in row {
            xml.push_str("<w:tc>");
            paragraph(&mut xml, cell)?;
            xml.push_str("</w:tc>");
        }
        xml.push_str("</w:tr>");
    }
    xml.push_str("</w:tbl>");
    for text in closing {
        paragraph(&mut xml, text)?;
    }
    xml.push_str("</w:body></w:document>");

    let mut writer = ZipWriter::new(Cursor::new(Vec::new()));
    for (path, text) in [
        ("[Content_Types].xml", CONTENT_TYPES),
        ("_rels/.rels", RELATIONSHIPS),
        ("word/document.xml", xml.as_str()),
    ] {
        writer.start_file(path, SimpleFileOptions::default())?;
        writer.write_all(text.as_bytes())?;
    }
    Ok(writer.finish()?.into_inner())
}
