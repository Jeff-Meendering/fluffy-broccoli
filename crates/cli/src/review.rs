//! Review saved observations without opening evidence or disclosing captured values.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{Result, bail};
use clap::Args;
use pii_explorer_core::hash::sha256_hex;
use pii_explorer_core::storage::load_scan;
use pii_explorer_core::{EntityType, ScanResult};
use serde::Serialize;

#[derive(Debug, Args)]
pub struct TriageArgs {
    /// Saved CLI JSON/JSONL or desktop JSON scan.
    input: PathBuf,
    /// New JSON report path; defaults to stdout.
    #[arg(short, long)]
    output: Option<PathBuf>,
    /// Number of resources to rank by occurrence count.
    #[arg(long, default_value_t = 20, value_parser = clap::value_parser!(u16).range(1..=1000))]
    top: u16,
}

#[derive(Debug, Args)]
pub struct CompareArgs {
    baseline: PathBuf,
    current: PathBuf,
    /// New JSON report path; defaults to stdout. Values are SHA-256 fingerprints only.
    #[arg(short, long)]
    output: Option<PathBuf>,
    /// Exit 4 if current-only occurrences exist.
    #[arg(long)]
    fail_on_new: bool,
}

#[derive(Debug, Serialize)]
struct Coverage {
    interrupted: bool,
    discovered: u64,
    completed: u64,
    attention: usize,
    retained_findings: usize,
    detected_findings: usize,
    filtered: bool,
}

impl Coverage {
    fn from_scan(scan: &ScanResult) -> Self {
        Self {
            interrupted: scan.summary.cancelled
                || scan.summary.limit_reached.is_some()
                || scan.summary.discovered != scan.summary.completed,
            discovered: scan.summary.discovered,
            completed: scan.summary.completed,
            attention: scan.attention.len(),
            retained_findings: scan.findings.len(),
            detected_findings: scan.summary.findings,
            filtered: scan.summary.findings != scan.findings.len(),
        }
    }
}

#[derive(Debug, Default, Serialize)]
struct Counts {
    occurrences: usize,
    distinct_values: Option<usize>,
    resources: usize,
}

#[derive(Debug, Serialize)]
struct ResourceCounts {
    resource_id: String,
    occurrences: usize,
    by_type: BTreeMap<EntityType, usize>,
}

pub fn triage(args: TriageArgs) -> Result<ExitCode> {
    let scan = load_scan(&args.input)?;
    let mut values: BTreeMap<EntityType, BTreeSet<&str>> = BTreeMap::new();
    let mut resources: BTreeMap<EntityType, BTreeSet<&str>> = BTreeMap::new();
    let mut by_type: BTreeMap<EntityType, Counts> = BTreeMap::new();
    let mut by_resource: BTreeMap<&str, ResourceCounts> = BTreeMap::new();
    for finding in &scan.findings {
        let kind = finding.entity_type;
        values.entry(kind).or_default().insert(&finding.value);
        resources
            .entry(kind)
            .or_default()
            .insert(&finding.origin.resource_id);
        by_type.entry(kind).or_default().occurrences += 1;
        let resource = by_resource
            .entry(&finding.origin.resource_id)
            .or_insert_with(|| ResourceCounts {
                resource_id: finding.origin.resource_id.clone(),
                occurrences: 0,
                by_type: BTreeMap::new(),
            });
        resource.occurrences += 1;
        *resource.by_type.entry(kind).or_default() += 1;
    }
    for (kind, counts) in &mut by_type {
        counts.distinct_values = values
            .get(kind)
            .filter(|items| !items.iter().any(|value| transformed(value)))
            .map(BTreeSet::len);
        counts.resources = resources.get(kind).map_or(0, BTreeSet::len);
    }
    let resource_count = by_resource.len();
    let mut ranked: Vec<_> = by_resource.into_values().collect();
    ranked.sort_by(|a, b| {
        b.occurrences
            .cmp(&a.occurrences)
            .then_with(|| a.resource_id.cmp(&b.resource_id))
    });
    ranked.truncate(usize::from(args.top));
    write_report(
        args.output.as_deref(),
        &serde_json::json!({
            "format_version": 1,
            "coverage": Coverage::from_scan(&scan),
            "resources_with_findings": resource_count,
            "by_type": by_type,
            "top_resources": ranked,
            "interpretation": "Occurrence counts include separate extracted streams, metadata and filename evidence. Distinct values are exact captured strings per entity type, not people. Redacted scans cannot establish distinct-value counts. Resource names may contain PII. Review attention items in the original scan.",
        }),
    )?;
    Ok(ExitCode::SUCCESS)
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
struct Observation {
    resource_id: String,
    stream_id: String,
    entity_type: EntityType,
    value_sha256: String,
}

#[derive(Debug, Serialize)]
struct Change {
    #[serde(flatten)]
    observation: Observation,
    occurrences: usize,
}

#[derive(Debug, Serialize)]
struct Comparison {
    format_version: u32,
    baseline_coverage: Coverage,
    current_coverage: Coverage,
    same_recorded_settings: bool,
    unchanged_occurrences: usize,
    current_only_occurrences: usize,
    baseline_only_occurrences: usize,
    current_only: Vec<Change>,
    baseline_only: Vec<Change>,
    interpretation: &'static str,
}

fn observations(scan: &ScanResult) -> Result<BTreeMap<Observation, usize>> {
    if scan.summary.findings != scan.findings.len() {
        bail!(
            "comparison requires unfiltered saved scans; retained finding count differs from the scan summary"
        );
    }
    let mut observations = BTreeMap::new();
    for finding in &scan.findings {
        if transformed(&finding.value) {
            bail!(
                "comparison requires unredacted saved scans; masked or hashed values cannot establish value equality"
            );
        }
        let key = Observation {
            resource_id: finding.origin.resource_id.clone(),
            stream_id: finding.origin.stream_id.clone(),
            entity_type: finding.entity_type,
            value_sha256: sha256_hex(finding.value.as_bytes()),
        };
        *observations.entry(key).or_default() += 1;
    }
    Ok(observations)
}

fn transformed(value: &str) -> bool {
    value.starts_with("[masked:") || value.starts_with("[sha256:")
}

fn compare_scans(baseline: &ScanResult, current: &ScanResult) -> Result<Comparison> {
    let mut previous = observations(baseline)?;
    let latest = observations(current)?;
    let mut report = Comparison {
        format_version: 1,
        baseline_coverage: Coverage::from_scan(baseline),
        current_coverage: Coverage::from_scan(current),
        same_recorded_settings: serde_json::to_value(&baseline.settings)?
            == serde_json::to_value(&current.settings)?,
        unchanged_occurrences: 0,
        current_only_occurrences: 0,
        baseline_only_occurrences: 0,
        current_only: Vec::new(),
        baseline_only: Vec::new(),
        interpretation: "Matches exact value, entity type, relative resource and stream, with occurrence counts; ignores offsets so inserted text does not create false changes. Baseline-only observations are not proof of remediation: review coverage, attention, scan scope, model/build versions and settings. Recorded settings do not identify model bytes. SHA-256 fingerprints are correlatable and do not anonymize low-entropy values. Resource names may contain PII.",
    };
    for (observation, count) in latest {
        let before = previous.remove(&observation).unwrap_or(0);
        report.unchanged_occurrences += before.min(count);
        if count > before {
            report.current_only_occurrences += count - before;
            report.current_only.push(Change {
                observation,
                occurrences: count - before,
            });
        } else if before > count {
            report.baseline_only_occurrences += before - count;
            report.baseline_only.push(Change {
                observation,
                occurrences: before - count,
            });
        }
    }
    for (observation, occurrences) in previous {
        report.baseline_only_occurrences += occurrences;
        report.baseline_only.push(Change {
            observation,
            occurrences,
        });
    }
    report
        .baseline_only
        .sort_by(|a, b| a.observation.cmp(&b.observation));
    Ok(report)
}

pub fn compare(args: CompareArgs) -> Result<ExitCode> {
    let baseline = load_scan(&args.baseline)?;
    let current = load_scan(&args.current)?;
    let report = compare_scans(&baseline, &current)?;
    write_report(args.output.as_deref(), &report)?;
    Ok(if args.fail_on_new && report.current_only_occurrences > 0 {
        ExitCode::from(4)
    } else {
        ExitCode::SUCCESS
    })
}

fn write_report(path: Option<&std::path::Path>, report: &impl Serialize) -> Result<()> {
    let mut writer = crate::create_writer(path)?;
    serde_json::to_writer_pretty(&mut writer, report)?;
    writer.write_all(b"\n")?;
    writer.flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, atomic::AtomicBool};

    use pii_explorer_core::{ScanOptions, Scanner};

    use super::*;

    fn scan(text: &str) -> ScanResult {
        Scanner::new(ScanOptions {
            detect_names: false,
            ocr: false,
            ..ScanOptions::default()
        })
        .expect("scanner")
        .detect_text(text, Arc::new(AtomicBool::new(false)))
    }

    #[test]
    fn retests_preserve_multiplicity_but_ignore_shifted_offsets() {
        let before = scan("a@example.com a@example.com b@example.org");
        let after = scan("inserted text a@example.com c@example.net");
        let report = compare_scans(&before, &after).expect("compare");
        assert_eq!(report.unchanged_occurrences, 1);
        assert_eq!(report.current_only_occurrences, 1);
        assert_eq!(report.baseline_only_occurrences, 2);
        let json = serde_json::to_string(&report).expect("serialize");
        assert!(!json.contains("@example"));
        assert!(json.contains(&sha256_hex(b"c@example.net")));
    }

    #[test]
    fn comparison_rejects_transformed_inputs_and_exposes_partial_coverage() {
        let before = scan("a@example.com");
        let mut after = before.clone();
        after.findings[0].value = "[masked: 13 UTF-16 units]".into();
        assert!(compare_scans(&before, &after).is_err());
        after = before.clone();
        after.summary.findings += 1;
        assert!(compare_scans(&before, &after).is_err());
        after = before.clone();
        after.summary.cancelled = true;
        after.settings.detect_names = true;
        let report = compare_scans(&before, &after).expect("partial report");
        assert!(report.current_coverage.interrupted);
        assert!(!report.same_recorded_settings);
    }
}
