use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use pii_explorer_core::ScanOptions;
use pii_explorer_core::detectors::PatternDetector;

#[derive(Debug, Clone)]
pub struct ScanSettings {
    pub ocr: bool,
    pub detect_names: bool,
    pub max_file_mib: u64,
    pub workers: usize,
    pub phone_regions: String,
}

impl Default for ScanSettings {
    fn default() -> Self {
        let options = ScanOptions::default();
        Self {
            ocr: options.ocr,
            detect_names: options.detect_names,
            max_file_mib: options.max_file_bytes / (1024 * 1024),
            workers: options.workers,
            phone_regions: options
                .phone_regions
                .into_iter()
                .collect::<Vec<_>>()
                .join(", "),
        }
    }
}

impl ScanSettings {
    pub fn scan_options(&self) -> Result<ScanOptions, String> {
        if !(1..=2048).contains(&self.max_file_mib) {
            return Err("Maximum file size must be between 1 and 2048 MiB.".into());
        }
        if !(1..=8).contains(&self.workers) {
            return Err("Parallel workers must be between 1 and 8.".into());
        }
        let phone_regions = parse_phone_regions(&self.phone_regions)?;
        // Keep context available in the evidence viewer and for a future report export.
        Ok(ScanOptions {
            detect_names: self.detect_names,
            ocr: self.ocr,
            max_file_bytes: self.max_file_mib * 1024 * 1024,
            workers: self.workers,
            phone_regions,
            include_context: true,
            ..ScanOptions::default()
        })
    }
}

pub fn parse_phone_regions(input: &str) -> Result<BTreeSet<String>, String> {
    let input = if input.trim().is_empty() {
        "US,GB"
    } else {
        input
    };
    let requested: BTreeSet<String> = input
        .split(',')
        .map(str::trim)
        .filter(|region| !region.is_empty())
        .map(str::to_ascii_uppercase)
        .collect();
    if requested.is_empty() {
        return Ok(["GB".to_owned(), "US".to_owned()].into_iter().collect());
    }

    // Use the detector's metadata rather than maintaining a second region list in the GUI.
    let valid = PatternDetector::new(&requested);
    let valid: BTreeSet<&str> = valid.phone_regions().iter().map(String::as_str).collect();
    let invalid: Vec<&str> = requested
        .iter()
        .map(String::as_str)
        .filter(|region| !valid.contains(region))
        .collect();
    if invalid.is_empty() {
        Ok(requested)
    } else {
        Err(format!(
            "Unknown phone region(s): {}. Use comma-separated ISO country codes such as US, GB, or DE.",
            invalid.join(", ")
        ))
    }
}

#[must_use]
pub fn normalize_folder_input(input: &str) -> &str {
    let input = input.trim();
    if input.len() >= 2 && input.starts_with('"') && input.ends_with('"') {
        input[1..input.len() - 1].trim()
    } else {
        input
    }
}

pub fn resolve_folder(input: &str) -> Result<PathBuf, String> {
    let input = normalize_folder_input(input);
    if input.is_empty() {
        return Err("Choose a folder or paste its path first.".into());
    }
    let path = Path::new(input);
    let metadata = std::fs::metadata(path)
        .map_err(|_| "The selected folder does not exist or is not accessible.".to_owned())?;
    if !metadata.is_dir() {
        return Err("The scan location must be a folder.".into());
    }
    std::fs::canonicalize(path)
        .map_err(|_| "The selected folder could not be resolved. Check its permissions.".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pasted_paths_trim_space_and_one_pair_of_quotes() {
        assert_eq!(normalize_folder_input("  /tmp/example  "), "/tmp/example");
        assert_eq!(
            normalize_folder_input(" \"/tmp/a folder\" "),
            "/tmp/a folder"
        );
        assert_eq!(
            normalize_folder_input(" \"/tmp/mismatch "),
            "\"/tmp/mismatch"
        );
        assert_eq!(normalize_folder_input("   "), "");
    }

    #[test]
    fn phone_regions_are_normalized_and_deduplicated() {
        let regions = parse_phone_regions(" us,gb, US ").expect("valid regions");
        assert_eq!(
            regions,
            ["GB".to_owned(), "US".to_owned()].into_iter().collect()
        );
        let defaults = parse_phone_regions(" ").expect("default regions");
        assert_eq!(defaults, regions);
    }

    #[test]
    fn invalid_phone_regions_are_reported_before_scanning() {
        let error = parse_phone_regions("US,not-a-region").expect_err("invalid region");
        assert!(error.contains("NOT-A-REGION"));
    }

    #[test]
    fn settings_build_core_options_without_losing_context() {
        let settings = ScanSettings {
            ocr: false,
            detect_names: false,
            max_file_mib: 25,
            workers: 3,
            phone_regions: "DE,US".into(),
        };
        let options = settings.scan_options().expect("valid options");
        assert!(!options.ocr);
        assert!(!options.detect_names);
        assert_eq!(options.max_file_bytes, 25 * 1024 * 1024);
        assert_eq!(options.workers, 3);
        assert!(options.include_context);
        assert!(options.phone_regions.contains("DE"));
    }
}
