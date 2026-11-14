//! Evidence is made by an adversary. Whatever the bytes, reading them must end with
//! tables and gaps: never a crash, and never more memory than the limits allow.

// Test helpers fail the test by panicking, like the tests themselves.
#![allow(clippy::unwrap_used)]

use std::io::{Cursor, Write};

use rollcall_extract::{Extraction, Limits, extract};
use rollcall_model::GapKind;
use zip::ZipWriter;
use zip::write::SimpleFileOptions;

/// SplitMix64, seeded per test so a failure can be replayed.
struct Random(u64);

impl Random {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut mixed = self.0;
        mixed = (mixed ^ (mixed >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        mixed = (mixed ^ (mixed >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        mixed ^ (mixed >> 31)
    }

    fn below(&mut self, limit: usize) -> usize {
        usize::try_from(self.next() % limit.max(1) as u64).unwrap()
    }
}

const WORKBOOK: &str = r#"<workbook xmlns:r="r"><sheets><sheet name="One" sheetId="1" r:id="rId1"/><sheet name="Two" sheetId="2" r:id="rId2"/></sheets></workbook>"#;
const RELATIONSHIPS: &str = r#"<Relationships><Relationship Id="rId1" Type="x/worksheet" Target="worksheets/sheet1.xml"/><Relationship Id="rId2" Type="x/worksheet" Target="worksheets/sheet2.xml"/><Relationship Id="rId3" Type="x/sharedStrings" Target="sharedStrings.xml"/><Relationship Id="rId4" Type="x/styles" Target="styles.xml"/></Relationships>"#;
const SHARED: &str = r#"<sst><si><t>Name</t></si><si><r><t>Jane </t></r><r><t>Doe</t></r></si><si><t>SSN</t></si></sst>"#;
const STYLES: &str = r#"<styleSheet><numFmts><numFmt numFmtId="164" formatCode="yyyy-mm-dd"/></numFmts><cellXfs><xf numFmtId="0"/><xf numFmtId="14"/><xf numFmtId="164"/></cellXfs></styleSheet>"#;
const SHEET: &str = r#"<worksheet><sheetData><row r="1"><c r="A1" t="s"><v>0</v></c><c r="B1" t="s"><v>2</v></c><c r="C1" t="inlineStr"><is><t>DOB</t></is></c></row><row r="2"><c r="A2" t="s"><v>1</v></c><c r="B2"><v>219099999</v></c><c r="C2" s="1"><v>29254</v></c></row></sheetData></worksheet>"#;

fn workbook(parts: &[(&str, &[u8])]) -> Vec<u8> {
    let mut writer = ZipWriter::new(Cursor::new(Vec::new()));
    for (path, bytes) in parts {
        writer
            .start_file(*path, SimpleFileOptions::default())
            .unwrap();
        writer.write_all(bytes).unwrap();
    }
    writer.finish().unwrap().into_inner()
}

fn standard_parts() -> Vec<(&'static str, Vec<u8>)> {
    vec![
        ("xl/workbook.xml", WORKBOOK.into()),
        ("xl/_rels/workbook.xml.rels", RELATIONSHIPS.into()),
        ("xl/sharedStrings.xml", SHARED.into()),
        ("xl/styles.xml", STYLES.into()),
        ("xl/worksheets/sheet1.xml", SHEET.into()),
        ("xl/worksheets/sheet2.xml", SHEET.into()),
    ]
}

fn build(parts: &[(&'static str, Vec<u8>)]) -> Vec<u8> {
    let borrowed: Vec<(&str, &[u8])> = parts
        .iter()
        .map(|(path, bytes)| (*path, bytes.as_slice()))
        .collect();
    workbook(&borrowed)
}

fn sheet(body: &str) -> Vec<u8> {
    let mut parts = standard_parts();
    parts[4].1 = format!("<worksheet><sheetData>{body}</sheetData></worksheet>").into_bytes();
    parts.truncate(5);
    parts[0].1 = WORKBOOK
        .replace(r#"<sheet name="Two" sheetId="2" r:id="rId2"/>"#, "")
        .into_bytes();
    build(&parts)
}

/// What every extraction must satisfy, whatever it was given.
fn check(extraction: &Extraction, limits: &Limits, what: &str) {
    let mut cells = 0_usize;
    for table in &extraction.tables {
        assert!(
            table.rows.len() <= limits.max_rows,
            "{what}: {} rows",
            table.rows.len()
        );
        cells += table.rows.iter().map(Vec::len).sum::<usize>();
        let scope = table.scope.as_deref().unwrap_or_default();
        assert!(
            !scope.chars().any(char::is_control),
            "{what}: sheet name {scope:?}"
        );
    }
    // Blank cells between filled ones are held too, up to four times the limit.
    assert!(
        cells <= limits.max_cells.saturating_mul(5),
        "{what}: {cells} cells"
    );
    for gap in &extraction.gaps {
        let shown = format!("{}{}", gap.scope.as_deref().unwrap_or_default(), gap.detail);
        assert!(
            !shown.chars().any(char::is_control),
            "{what}: gap text {shown:?}"
        );
        assert!(!gap.detail.is_empty(), "{what}: a gap must say why");
    }
}

const TIGHT: Limits = Limits {
    max_rows: 40,
    max_cells: 200,
    max_part_bytes: 4_096,
};

#[test]
fn random_bytes_end_in_tables_or_gaps() {
    let mut random = Random(1);
    for round in 0..3_000 {
        let length = random.below(600);
        let bytes: Vec<u8> = (0..length)
            .map(|_| random.next().to_le_bytes()[0])
            .collect();
        for name in [
            "x.csv", "x.tsv", "x.xlsx", "x.xlsm", "x.txt", "x.json", "x.html", "x.docx",
        ] {
            for limits in [Limits::default(), TIGHT] {
                check(
                    &extract(name, &bytes, &limits),
                    &limits,
                    &format!("round {round} as {name}"),
                );
            }
        }
    }
}

/// Fragments that steer a mutated part towards the parser's edges.
const FRAGMENTS: [&str; 24] = [
    "<",
    ">",
    "</",
    "/>",
    "\"",
    "'",
    "&",
    "&#x0;",
    "&#1114112;",
    "&amp;amp;",
    "<![CDATA[",
    "]]>",
    "<!--",
    "<!DOCTYPE x [",
    "<row r=\"0\">",
    "<row r=\"4294967295\">",
    "<c r=\"XFD1048576\" t=\"s\" s=\"99999\">",
    "<c r=\"\" t=\"inlineStr\"><is><t>",
    "<v>99999999999999999999</v>",
    "<v>-1</v>",
    "<v>1e999</v>",
    "<v>NaN</v>",
    "\u{0}",
    "_x000A_",
];

fn mutate(random: &mut Random, bytes: &mut Vec<u8>) {
    let at = random.below(bytes.len() + 1);
    match random.below(5) {
        0 => bytes.truncate(at),
        1 if !bytes.is_empty() => {
            let position = random.below(bytes.len());
            bytes[position] ^= 1 << random.below(8);
        }
        2 => {
            let fragment = FRAGMENTS[random.below(FRAGMENTS.len())].as_bytes();
            bytes.splice(at..at, fragment.iter().copied());
        }
        3 => {
            let end = (at + random.below(40)).min(bytes.len());
            let copy: Vec<u8> = bytes[at..end].to_vec();
            for _ in 0..random.below(30) {
                bytes.splice(at..at, copy.iter().copied());
            }
        }
        _ => {
            let end = (at + random.below(40)).min(bytes.len());
            bytes.drain(at..end);
        }
    }
}

#[test]
fn damaged_workbooks_end_in_tables_or_gaps() {
    let mut random = Random(2);
    for round in 0..2_500 {
        let mut parts = standard_parts();
        for _ in 0..=random.below(3) {
            let part = random.below(parts.len());
            mutate(&mut random, &mut parts[part].1);
        }
        let bytes = build(&parts);
        for limits in [Limits::default(), TIGHT] {
            check(
                &extract("book.xlsx", &bytes, &limits),
                &limits,
                &format!("round {round}"),
            );
        }
    }
}

#[test]
fn damaged_delimited_text_ends_in_tables_or_gaps() {
    let mut random = Random(3);
    let original =
        b"Name,SSN,\"Note\"\n\"Doe, Jane\",219-09-9999,\"said \"\"hi\"\"\nthen left\"\n".to_vec();
    for round in 0..3_000 {
        let mut bytes = original.clone();
        for _ in 0..=random.below(4) {
            mutate(&mut random, &mut bytes);
        }
        for limits in [Limits::default(), TIGHT] {
            check(
                &extract("list.csv", &bytes, &limits),
                &limits,
                &format!("round {round}"),
            );
        }
    }
}

#[test]
fn a_cell_at_the_far_corner_of_a_sheet_is_bounded_by_the_limits() {
    let far = sheet(
        r#"<row r="1"><c r="A1"><v>1</v></c></row><row r="1048576"><c r="XFD1048576"><v>2</v></c></row>"#,
    );
    let roomy = extract("far.xlsx", &far, &Limits::default());
    check(&roomy, &Limits::default(), "far corner");
    assert_eq!(roomy.tables[0].rows.len(), 1_048_576);
    assert_eq!(
        roomy.tables[0].rows[1_048_575].last().map(String::as_str),
        Some("2")
    );

    let tight = extract("far.xlsx", &far, &TIGHT);
    check(&tight, &TIGHT, "far corner, tight limits");
    assert_eq!(tight.tables[0].rows, vec![vec!["1".to_owned()]]);
    assert!(tight.gaps.iter().any(|gap| gap.kind == GapKind::Truncated));
}

#[test]
fn nonsense_references_indexes_and_numbers_are_read_as_far_as_they_make_sense() {
    let odd = sheet(
        r#"<row r="0"><c r="A0"><v>zero</v></c></row>
           <row r="abc"><c r="1A"><v>7</v></c><c r="ZZZZ9"><v>8</v></c><c><v>9</v></c></row>
           <row r="4294967295"><c r="A4294967295"><v>10</v></c></row>
           <row r="5"><c r="A5" t="s"><v>99999999999999999999</v></c><c r="B5" t="s"><v>-1</v></c>
               <c r="C5" s="4294967295"><v>29254</v></c><c r="D5" s="1"><v>1e300</v></c>
               <c r="E5"><v>NaN</v></c><c r="F5"><v>1e999</v></c><c r="G5" t="b"><v>maybe</v></c></row>"#,
    );
    let extraction = extract("odd.xlsx", &odd, &Limits::default());
    check(&extraction, &Limits::default(), "nonsense");
    let cells: Vec<&str> = extraction.tables[0]
        .rows
        .iter()
        .flatten()
        .map(String::as_str)
        .filter(|cell| !cell.is_empty())
        .collect();
    assert!(
        cells.contains(&"29254"),
        "an unknown style is no style: {cells:?}"
    );
    assert!(
        cells.contains(&"1e300"),
        "a date too large to be one stays a number: {cells:?}"
    );
    assert!(
        cells.contains(&"NaN") && cells.contains(&"FALSE"),
        "{cells:?}"
    );
    assert!(
        extraction
            .gaps
            .iter()
            .any(|gap| gap.kind == GapKind::Truncated),
        "the far row is cut off, and said so"
    );
}

#[test]
fn entity_declarations_are_never_expanded() {
    let mut parts = standard_parts();
    parts[2].1 = br#"<!DOCTYPE sst [<!ENTITY a "aaaaaaaaaa"><!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;">]><sst><si><t>&b;&b;&b;</t></si><si><t>x</t></si><si><t>y</t></si></sst>"#.to_vec();
    let extraction = extract("bomb.xlsx", &build(&parts), &Limits::default());
    check(&extraction, &Limits::default(), "entities");
    assert_eq!(extraction.tables[0].rows[0][0], "&b;&b;&b;");
}

#[test]
fn a_part_that_inflates_past_the_limit_is_not_held_in_memory() {
    let mut parts = standard_parts();
    parts[4].1 = vec![b' '; 6 * 1024 * 1024];
    let bytes = build(&parts);
    assert!(bytes.len() < 64 * 1024, "the container itself is small");
    let limits = Limits {
        max_part_bytes: 1024 * 1024,
        ..Limits::default()
    };
    let extraction = extract("inflate.xlsx", &bytes, &limits);
    check(&extraction, &limits, "inflating part");
    assert_eq!(extraction.tables.len(), 1, "the other sheet is still read");
    let gap = extraction
        .gaps
        .iter()
        .find(|gap| gap.scope.as_deref() == Some("One"))
        .unwrap();
    assert_eq!(gap.kind, GapKind::Unreadable);
    assert!(gap.detail.contains("larger than the size limit"));
}

#[test]
fn many_sheets_share_one_cell_limit() {
    let sheets: String = (1..=60)
        .map(|number| format!(r#"<sheet name="S{number}" sheetId="{number}" r:id="rId1"/>"#))
        .collect();
    let mut parts = standard_parts();
    parts[0].1 =
        format!(r#"<workbook xmlns:r="r"><sheets>{sheets}</sheets></workbook>"#).into_bytes();
    let limits = Limits {
        max_cells: 50,
        ..Limits::default()
    };
    let extraction = extract("many.xlsx", &build(&parts), &limits);
    check(&extraction, &limits, "many sheets");
    assert!(extraction.tables.len() < 60);
    assert!(
        extraction
            .gaps
            .iter()
            .all(|gap| gap.kind == GapKind::Truncated)
    );
    let accounted: std::collections::BTreeSet<&str> = extraction
        .tables
        .iter()
        .filter_map(|table| table.scope.as_deref())
        .chain(
            extraction
                .gaps
                .iter()
                .filter_map(|gap| gap.scope.as_deref()),
        )
        .collect();
    assert_eq!(
        accounted.len(),
        60,
        "every sheet is either read or reported"
    );
}

#[test]
fn names_chosen_by_the_adversary_cannot_forge_output() {
    let mut parts = standard_parts();
    parts[0].1 = br#"<workbook xmlns:r="r"><sheets><sheet name="Staff&#10;unreadable   fake.csv&#27;[2J" sheetId="1" r:id="rId1"/><sheet name="Two" sheetId="2" r:id="rId2"/></sheets></workbook>"#.to_vec();
    parts[1].1 = RELATIONSHIPS
        .replace("worksheets/sheet2.xml", "../../../etc/passwd&#10;x")
        .into_bytes();
    let extraction = extract("names.xlsx", &build(&parts), &Limits::default());
    check(&extraction, &Limits::default(), "hostile names");
    assert_eq!(
        extraction.tables[0].scope.as_deref(),
        Some("Staff\\u{a}unreadable   fake.csv\\u{1b}[2J")
    );
    assert_eq!(
        extraction.gaps.len(),
        1,
        "the part outside the container does not exist"
    );
}

const DOCUMENT: &str = r#"<w:document xmlns:w="w"><w:body><w:p><w:r><w:t>Name: Jane Doe</w:t></w:r></w:p><w:p/><w:tbl><w:tr><w:tc><w:p><w:r><w:t>SSN</w:t></w:r></w:p></w:tc></w:tr><w:tr><w:tc><w:p><w:r><w:t>219-09-9999</w:t><w:tab/><w:br/></w:r></w:p></w:tc></w:tr></w:tbl></w:body></w:document>"#;

#[test]
fn damaged_documents_and_pages_end_in_text_tables_or_gaps() {
    let mut random = Random(4);
    let page = b"<html><head><script>x</script></head><body><p>Jane &amp; co<br>jane@example.com</p></body></html>";
    for round in 0..2_500 {
        let mut body = DOCUMENT.as_bytes().to_vec();
        let mut footer = b"<w:ftr><w:p><w:r><w:t>hr@example.com</w:t></w:r></w:p></w:ftr>".to_vec();
        let mut html = page.to_vec();
        for _ in 0..=random.below(3) {
            mutate(&mut random, &mut body);
            mutate(&mut random, &mut footer);
            mutate(&mut random, &mut html);
        }
        let document = workbook(&[("word/document.xml", &body), ("word/footer1.xml", &footer)]);
        for limits in [Limits::default(), TIGHT] {
            check(
                &extract("letter.docx", &document, &limits),
                &limits,
                &format!("document round {round}"),
            );
            check(
                &extract("page.html", &html, &limits),
                &limits,
                &format!("page round {round}"),
            );
            check(
                &extract("notes.txt", &html, &limits),
                &limits,
                &format!("text round {round}"),
            );
        }
    }
}

#[test]
fn deeply_nested_tables_and_endless_paragraphs_stay_within_the_limits() {
    let nested = format!(
        r#"<w:document xmlns:w="w"><w:body>{}<w:p><w:r><w:t>x</w:t></w:r></w:p>{}</w:body></w:document>"#,
        "<w:tbl><w:tr><w:tc>".repeat(5_000),
        "</w:tc></w:tr></w:tbl>".repeat(5_000)
    );
    let extraction = extract(
        "nested.docx",
        &workbook(&[("word/document.xml", nested.as_bytes())]),
        &Limits::default(),
    );
    check(&extraction, &Limits::default(), "nested tables");
    assert_eq!(extraction.tables[0].rows, [["x"]]);

    let many = format!(
        r#"<w:document xmlns:w="w"><w:body>{}</w:body></w:document>"#,
        "<w:p><w:r><w:t>line</w:t></w:r></w:p>".repeat(500)
    );
    let few_rows = Limits {
        max_rows: 40,
        ..Limits::default()
    };
    let extraction = extract(
        "many.docx",
        &workbook(&[("word/document.xml", many.as_bytes())]),
        &few_rows,
    );
    check(&extraction, &few_rows, "many paragraphs");
    assert_eq!(extraction.texts[0].lines.len(), 40);
    assert!(
        extraction
            .gaps
            .iter()
            .any(|gap| gap.kind == GapKind::Truncated)
    );
}
