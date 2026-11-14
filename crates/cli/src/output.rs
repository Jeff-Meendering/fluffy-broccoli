use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::io::Write;

use anyhow::{Context, Result};
use clap::ValueEnum;
use percent_encoding::{AsciiSet, CONTROLS, utf8_percent_encode};
use pii_explorer_core::hash::sha256_hex;
use pii_explorer_core::{
    AttentionItem, CoordinateUnit, EntityType, Finding, ScanOptions, ScanResult, ScanSummary,
    SourceRecord,
};
use serde_json::{Value, json};

const PATH_ENCODE_SET: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'%')
    .add(b'#')
    .add(b'?')
    .add(b'\\')
    .add(b':')
    .add(b'"')
    .add(b'<')
    .add(b'>')
    .add(b'`')
    .add(b'{')
    .add(b'}')
    .add(b'[')
    .add(b']')
    .add(b'|')
    .add(b'^');

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum OutputFormat {
    Json,
    Jsonl,
    Csv,
    Sarif,
    Text,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Redaction {
    None,
    Mask,
    Hash,
}

pub fn redact_finding(finding: &Finding, redaction: Redaction) -> Finding {
    let mut output = finding.clone();
    match redaction {
        Redaction::None => {}
        Redaction::Mask => {
            output.value = format!("[masked: {} UTF-16 units]", output.length);
            output.context.clear();
        }
        Redaction::Hash => {
            output.value = format!("[sha256:{}]", sha256_hex(output.value.as_bytes()));
            output.context.clear();
        }
    }
    output
}

pub fn included(finding: &Finding, types: &BTreeSet<EntityType>) -> bool {
    types.is_empty() || types.contains(&finding.entity_type)
}

pub fn write_jsonl_finding<W: Write + ?Sized>(
    writer: &mut W,
    finding: &Finding,
    redaction: Redaction,
    types: &BTreeSet<EntityType>,
) -> Result<()> {
    if !included(finding, types) {
        return Ok(());
    }
    let finding = redact_finding(finding, redaction);
    write_json_line(writer, &json!({"kind": "finding", "finding": finding}))
}

pub fn write_jsonl_attention<W: Write + ?Sized>(
    writer: &mut W,
    attention: &AttentionItem,
) -> Result<()> {
    write_json_line(
        writer,
        &json!({"kind": "attention", "attention": attention}),
    )
}

pub fn write_jsonl_settings<W: Write + ?Sized>(
    writer: &mut W,
    settings: &ScanOptions,
) -> Result<()> {
    write_json_line(writer, &json!({"kind": "settings", "settings": settings}))
}

pub fn write_jsonl_source<W: Write + ?Sized>(writer: &mut W, source: &SourceRecord) -> Result<()> {
    write_json_line(writer, &json!({"kind": "source", "source": source}))
}

pub fn write_jsonl_summary<W: Write + ?Sized>(writer: &mut W, summary: &ScanSummary) -> Result<()> {
    write_json_line(writer, &json!({"kind": "summary", "summary": summary}))
}

fn write_json_line<W: Write + ?Sized>(writer: &mut W, value: &Value) -> Result<()> {
    serde_json::to_writer(&mut *writer, value)?;
    writer.write_all(b"\n")?;
    Ok(())
}

pub fn write_result<W: Write + ?Sized>(
    writer: &mut W,
    result: &ScanResult,
    format: OutputFormat,
    redaction: Redaction,
    types: &BTreeSet<EntityType>,
) -> Result<()> {
    match format {
        OutputFormat::Json => write_json(writer, result, redaction, types),
        OutputFormat::Jsonl => write_jsonl_result(writer, result, redaction, types),
        OutputFormat::Csv => write_csv(writer, result, redaction, types),
        OutputFormat::Sarif => write_sarif(writer, result, redaction, types),
        OutputFormat::Text => write_text(writer, result, redaction, types),
    }
}

fn write_json<W: Write + ?Sized>(
    writer: &mut W,
    result: &ScanResult,
    redaction: Redaction,
    types: &BTreeSet<EntityType>,
) -> Result<()> {
    let findings = result
        .findings
        .iter()
        .filter(|finding| included(finding, types))
        .map(|finding| redact_finding(finding, redaction))
        .collect::<Vec<_>>();
    let emitted = findings.len();
    let value = json!({
        "engineVersion": pii_explorer_core::ENGINE_VERSION,
        "settings": &result.settings,
        "findings": findings,
        "attention": &result.attention,
        "sources": &result.sources,
        "summary": &result.summary,
        "emittedFindings": emitted,
    });
    serde_json::to_writer_pretty(&mut *writer, &value)?;
    writer.write_all(b"\n")?;
    Ok(())
}

fn write_jsonl_result<W: Write + ?Sized>(
    writer: &mut W,
    result: &ScanResult,
    redaction: Redaction,
    types: &BTreeSet<EntityType>,
) -> Result<()> {
    write_jsonl_settings(writer, &result.settings)?;
    for finding in &result.findings {
        write_jsonl_finding(writer, finding, redaction, types)?;
    }
    for attention in &result.attention {
        write_jsonl_attention(writer, attention)?;
    }
    for source in &result.sources {
        write_jsonl_source(writer, source)?;
    }
    write_jsonl_summary(writer, &result.summary)
}

fn write_csv<W: Write + ?Sized>(
    writer: &mut W,
    result: &ScanResult,
    redaction: Redaction,
    types: &BTreeSet<EntityType>,
) -> Result<()> {
    let mut csv = csv::Writer::from_writer(writer);
    write_csv_record(
        &mut csv,
        [
            "record_type",
            "resource",
            "stream",
            "representation",
            "type",
            "start",
            "length",
            "value",
            "confidence",
            "method",
            "context",
            "sha256",
            "message",
        ],
    )?;
    for finding in result
        .findings
        .iter()
        .filter(|finding| included(finding, types))
    {
        let finding = redact_finding(finding, redaction);
        write_csv_record(
            &mut csv,
            [
                "finding".to_owned(),
                finding.origin.resource_id,
                finding.origin.stream_id,
                finding.origin.representation,
                finding.entity_type.to_string(),
                finding.start.to_string(),
                finding.length.to_string(),
                finding.value,
                format!("{:.3}", finding.confidence),
                finding.method,
                finding.context,
                String::new(),
                String::new(),
            ],
        )?;
    }
    for attention in &result.attention {
        write_csv_record(
            &mut csv,
            [
                "attention".to_owned(),
                attention.resource_id.clone(),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                attention.message.clone(),
            ],
        )?;
    }
    for source in &result.sources {
        write_csv_record(
            &mut csv,
            [
                "source".to_owned(),
                source.resource_id.clone(),
                String::new(),
                String::new(),
                String::new(),
                source.size.to_string(),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                source.sha256.clone().unwrap_or_default(),
                String::new(),
            ],
        )?;
    }
    csv.flush().context("flush CSV output")
}

// CSV is intended for spreadsheets. Preserve exact values in JSON/JSONL; neutralize
// executable formula prefixes in every CSV field, including attacker-controlled paths.
fn write_csv_record<W: Write, S: AsRef<str>, const N: usize>(
    writer: &mut csv::Writer<W>,
    fields: [S; N],
) -> Result<()> {
    writer.write_record(fields.iter().map(|field| {
        let text = field.as_ref();
        let trimmed = text.trim_start_matches([' ', '\t', '\r', '\n']);
        if text.starts_with(['\t', '\r', '\n']) || trimmed.starts_with(['=', '+', '-', '@']) {
            format!("'{text}")
        } else {
            text.to_owned()
        }
    }))?;
    Ok(())
}

fn write_sarif<W: Write + ?Sized>(
    writer: &mut W,
    result: &ScanResult,
    redaction: Redaction,
    types: &BTreeSet<EntityType>,
) -> Result<()> {
    let source_hashes: HashMap<_, _> = result
        .sources
        .iter()
        .map(|source| (source.resource_id.as_str(), source.sha256.as_deref()))
        .collect();
    let selected_types = EntityType::ALL
        .into_iter()
        .filter(|kind| types.is_empty() || types.contains(kind))
        .collect::<Vec<_>>();
    let rules = selected_types
        .iter()
        .map(|kind| {
            json!({
                "id": kind.as_str(),
                "name": kind.as_str(),
                "shortDescription": {"text": format!("{} detection", kind.as_str())},
                "defaultConfiguration": {"level": "warning"},
                "properties": {"category": "PII", "offline": true}
            })
        })
        .collect::<Vec<_>>();
    let rule_indices: BTreeMap<_, _> = selected_types
        .iter()
        .enumerate()
        .map(|(index, kind)| (*kind, index))
        .collect();
    let findings = result
        .findings
        .iter()
        .filter(|finding| included(finding, types))
        .map(|finding| {
            let finding = redact_finding(finding, redaction);
            let region = match finding.origin.coordinate_unit {
                CoordinateUnit::Utf16CodeUnits => json!({
                    "charOffset": finding.start,
                    "charLength": finding.length,
                    "snippet": {"text": &finding.value}
                }),
                CoordinateUnit::Bytes => json!({
                    "byteOffset": finding.start,
                    "byteLength": finding.length,
                    "snippet": {"text": &finding.value}
                }),
            };
            let identity = format!(
                "{}:{}:{:?}:{}:{}",
                finding.origin.resource_id,
                finding.origin.stream_id,
                finding.entity_type,
                finding.start,
                finding.length
            );
            let mut fingerprints = json!({"occurrenceSha256": sha256_hex(identity.as_bytes())});
            if let Some(Some(hash)) = source_hashes.get(finding.origin.resource_id.as_str()) {
                fingerprints["sourceSha256"] = json!(hash);
            }
            let mut physical_location = json!({
                "artifactLocation": {
                    "uri": utf8_percent_encode(&finding.origin.resource_id, PATH_ENCODE_SET).to_string(),
                    "description": {"text": &finding.origin.stream_id}
                }
            });
            // Page OCR, MIME parts, metadata and generated table offsets do not identify
            // positions in the container file. Keep them as explicit stream properties.
            let physical_coordinates = finding.origin.coordinate_unit == CoordinateUnit::Bytes
                || (finding.origin.kind == pii_explorer_core::EvidenceKind::Body
                    && finding.origin.representation == "decoded-text"
                    && matches!(finding.origin.stream_id.as_str(), "body" | "decoded-text"));
            if physical_coordinates {
                physical_location["region"] = region;
            }
            json!({
                "ruleId": finding.entity_type.as_str(),
                "ruleIndex": rule_indices.get(&finding.entity_type),
                "level": "warning",
                "message": {"text": format!("{}: {}", finding.entity_type, terminal_safe(&finding.value))},
                "locations": [{
                    "physicalLocation": physical_location,
                    "logicalLocations": [{"name": &finding.origin.stream_id}]
                }],
                "partialFingerprints": fingerprints,
                "properties": {
                    "confidence": finding.confidence,
                    "method": finding.method,
                    "representation": finding.origin.representation,
                    "streamStart": finding.start,
                    "streamLength": finding.length,
                    "coordinateUnit": finding.origin.coordinate_unit,
                    "stride": finding.origin.stride,
                    "context": finding.context
                }
            })
        })
        .collect::<Vec<_>>();
    let attention = result
        .attention
        .iter()
        .map(|item| json!({"resource": item.resource_id, "message": item.message}))
        .collect::<Vec<_>>();
    let sarif = json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "PII Explorer",
                "version": pii_explorer_core::ENGINE_VERSION,
                "informationUri": "https://github.com/Jeff-Meendering/fluffy-broccoli",
                "rules": rules
            }},
            "columnKind": "utf16CodeUnits",
            "results": findings,
            "invocations": [{
                "executionSuccessful": !result.summary.cancelled,
                "properties": {
                    "summary": result.summary,
                    "attention": attention,
                    "offline": true,
                    "valuesRedacted": redaction != Redaction::None
                }
            }]
        }]
    });
    serde_json::to_writer_pretty(&mut *writer, &sarif)?;
    writer.write_all(b"\n")?;
    Ok(())
}

fn write_text<W: Write + ?Sized>(
    writer: &mut W,
    result: &ScanResult,
    redaction: Redaction,
    types: &BTreeSet<EntityType>,
) -> Result<()> {
    for finding in result
        .findings
        .iter()
        .filter(|finding| included(finding, types))
    {
        let finding = redact_finding(finding, redaction);
        writeln!(
            writer,
            "{}:{} [{}] {} {} offset={} length={} confidence={:.0}% method={}",
            terminal_safe(&finding.origin.resource_id),
            terminal_safe(&finding.origin.stream_id),
            terminal_safe(&finding.origin.representation),
            finding.entity_type,
            terminal_safe(&finding.value),
            finding.start,
            finding.length,
            finding.confidence * 100.0,
            terminal_safe(&finding.method),
        )?;
    }
    for attention in &result.attention {
        writeln!(
            writer,
            "ATTENTION {}: {}",
            terminal_safe(&attention.resource_id),
            terminal_safe(&attention.message)
        )?;
    }
    writeln!(
        writer,
        "SUMMARY discovered={} completed={} findings={} attention={} cancelled={} elapsedMs={}",
        result.summary.discovered,
        result.summary.completed,
        result.summary.findings,
        result.summary.attention,
        result.summary.cancelled,
        result.summary.elapsed_ms
    )?;
    Ok(())
}

fn terminal_safe(value: &str) -> String {
    let mut output = String::with_capacity(value.len());
    for character in value.chars() {
        if character.is_control()
            || matches!(
                character,
                '\u{200b}'..='\u{200f}'
                    | '\u{202a}'..='\u{202e}'
                    | '\u{2060}'..='\u{206f}'
                    | '\u{feff}'
            )
        {
            for unit in character.encode_utf8(&mut [0; 4]).chars() {
                output.extend(unit.escape_default());
            }
        } else {
            output.push(character);
        }
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use pii_explorer_core::{EvidenceKind, EvidenceOrigin};

    fn finding() -> Finding {
        Finding {
            entity_type: EntityType::Email,
            value: "alice@example.com".into(),
            start: 0,
            length: 17,
            context: "alice@example.com".into(),
            context_start: 0,
            detector_start: 0,
            detector_length: 17,
            confidence: 0.9,
            method: "test".into(),
            origin: EvidenceOrigin {
                resource_id: "folder/employee one.txt".into(),
                stream_id: "body".into(),
                kind: EvidenceKind::Body,
                representation: "decoded-text".into(),
                chunk_start: 0,
                coordinate_unit: CoordinateUnit::Utf16CodeUnits,
                stride: 1,
            },
        }
    }

    #[test]
    fn redaction_also_removes_context() {
        let masked = redact_finding(&finding(), Redaction::Mask);
        assert!(!masked.value.contains("alice"));
        assert!(masked.context.is_empty());
        let hashed = redact_finding(&finding(), Redaction::Hash);
        assert!(hashed.value.starts_with("[sha256:"));
        assert!(hashed.context.is_empty());
    }

    #[test]
    fn sarif_is_parseable_and_uses_relative_uris() {
        let result = ScanResult {
            findings: vec![finding()],
            ..ScanResult::default()
        };
        let mut bytes = Vec::new();
        write_sarif(&mut bytes, &result, Redaction::Mask, &BTreeSet::new()).expect("SARIF output");
        let value: Value = serde_json::from_slice(&bytes).expect("valid SARIF JSON");
        assert_eq!(value["version"], "2.1.0");
        let uri =
            value["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]
                ["uri"]
                .as_str()
                .expect("URI");
        assert_eq!(uri, "folder/employee%20one.txt");
        assert!(!bytes.windows(5).any(|window| window == b"alice"));
    }

    #[test]
    fn terminal_text_cannot_contain_escape_or_bidi_controls() {
        assert_eq!(
            terminal_safe("safe\u{1b}[31m\u{202e}txt"),
            "safe\\u{1b}[31m\\u{202e}txt"
        );
    }

    #[test]
    fn sarif_does_not_invent_container_offsets_or_null_fingerprints() {
        let mut finding = finding();
        finding.origin.resource_id = "sensitive:record.pdf".into();
        finding.origin.kind = EvidenceKind::Ocr;
        finding.origin.stream_id = "ocr:pdf:page:1".into();
        finding.origin.representation = "ocr-text".into();
        let result = ScanResult {
            findings: vec![finding],
            ..ScanResult::default()
        };
        let mut bytes = Vec::new();
        write_sarif(&mut bytes, &result, Redaction::Mask, &BTreeSet::new()).expect("SARIF");
        let value: Value = serde_json::from_slice(&bytes).expect("JSON");
        let finding = &value["runs"][0]["results"][0];
        let location = &finding["locations"][0]["physicalLocation"];
        assert!(location.get("region").is_none());
        assert_eq!(
            location["artifactLocation"]["uri"],
            "sensitive%3Arecord.pdf"
        );
        assert!(
            finding["partialFingerprints"]
                .as_object()
                .expect("fingerprints")
                .values()
                .all(Value::is_string)
        );
        assert_eq!(finding["properties"]["coordinateUnit"], "utf16");
    }
}
