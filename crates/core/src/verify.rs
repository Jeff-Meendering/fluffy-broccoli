//! Compare recorded source hashes with a local evidence directory.

use std::collections::HashSet;
use std::fs::File;
use std::io::{self, Read};
use std::path::{Component, Path};
use std::sync::atomic::{AtomicBool, Ordering};

use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::{ScanResult, SourceRecord};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceStatus {
    Match,
    Changed,
    Missing,
    Unreadable,
    UnsafePath,
    Unhashed,
}

#[derive(Debug, Serialize)]
pub struct SourceVerification {
    pub resource_id: String,
    pub status: SourceStatus,
}

#[derive(Debug, Serialize)]
pub struct VerificationReport {
    pub sources: Vec<SourceVerification>,
    pub cancelled: bool,
    pub scan_incomplete: bool,
}

impl VerificationReport {
    #[must_use]
    pub fn all_match(&self) -> bool {
        !self.cancelled
            && !self.scan_incomplete
            && !self.sources.is_empty()
            && self
                .sources
                .iter()
                .all(|source| source.status == SourceStatus::Match)
    }
}

/// Resource IDs must be relative, unique, and free of links. Only root source files are
/// hashed: archive member identities are covered by the containing file's hash. Hashes
/// establish equality to a saved record, not authenticity of that record or a snapshot.
pub fn verify_sources(
    result: &ScanResult,
    root: &Path,
    cancelled: &AtomicBool,
) -> io::Result<VerificationReport> {
    let root = std::fs::canonicalize(root)?;
    if !root.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "verification root must be a directory",
        ));
    }
    let mut report = VerificationReport {
        sources: Vec::with_capacity(result.sources.len()),
        cancelled: false,
        scan_incomplete: result.summary.cancelled
            || result.summary.limit_reached.is_some()
            || result.summary.completed != result.summary.discovered,
    };
    let mut seen = HashSet::new();
    for source in &result.sources {
        if cancelled.load(Ordering::Relaxed) {
            report.cancelled = true;
            break;
        }
        let status = if !seen.insert(&source.resource_id) {
            SourceStatus::UnsafePath
        } else {
            verify_one(source, &root, cancelled)
        };
        report.sources.push(SourceVerification {
            resource_id: source.resource_id.clone(),
            status,
        });
    }
    report.cancelled |= cancelled.load(Ordering::Relaxed);
    Ok(report)
}

fn verify_one(source: &SourceRecord, root: &Path, cancelled: &AtomicBool) -> SourceStatus {
    let relative = Path::new(&source.resource_id);
    if source.resource_id.is_empty()
        || source.resource_id.contains(['\\', ':', '\0'])
        || relative
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return SourceStatus::UnsafePath;
    }
    let Some(expected) = &source.sha256 else {
        return SourceStatus::Unhashed;
    };
    if expected.len() != 64 || !expected.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return SourceStatus::Unhashed;
    }
    let mut path = root.to_path_buf();
    for component in relative.components() {
        path.push(component);
        match std::fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.file_type().is_symlink() => return SourceStatus::UnsafePath,
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => return SourceStatus::Missing,
            Err(_) => return SourceStatus::Unreadable,
        }
    }
    let Ok(mut file) = File::open(&path) else {
        return SourceStatus::Unreadable;
    };
    let Ok(before) = file.metadata() else {
        return SourceStatus::Unreadable;
    };
    if !before.is_file() {
        return SourceStatus::UnsafePath;
    }
    if before.len() != source.size {
        return SourceStatus::Changed;
    }
    let mut hash = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    let mut total = 0_u64;
    loop {
        if cancelled.load(Ordering::Relaxed) {
            return SourceStatus::Unreadable;
        }
        match file.read(&mut buffer) {
            Ok(0) => break,
            Ok(read) => {
                total = total.saturating_add(read as u64);
                if total > source.size {
                    return SourceStatus::Changed;
                }
                hash.update(&buffer[..read]);
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => return SourceStatus::Unreadable,
        }
    }
    let Ok(after) = file.metadata() else {
        return SourceStatus::Unreadable;
    };
    if total != source.size
        || after.len() != before.len()
        || after.modified().ok() != before.modified().ok()
        || !crate::hash::hex(&hash.finalize()).eq_ignore_ascii_case(expected)
    {
        SourceStatus::Changed
    } else {
        SourceStatus::Match
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verifies_bytes_and_reports_changes_missing_files_and_unhashed_sources() {
        let directory = tempfile::tempdir().expect("directory");
        std::fs::write(directory.path().join("case.txt"), b"test").expect("write");
        let mut result = ScanResult::default();
        result.sources.push(SourceRecord {
            resource_id: "case.txt".into(),
            size: 4,
            sha256: Some(crate::hash::sha256_hex(b"test")),
        });
        let verify = |result: &ScanResult| {
            verify_sources(result, directory.path(), &AtomicBool::new(false)).expect("verify")
        };
        assert!(verify(&result).all_match());
        std::fs::write(directory.path().join("case.txt"), b"edit").expect("edit");
        assert_eq!(verify(&result).sources[0].status, SourceStatus::Changed);
        std::fs::remove_file(directory.path().join("case.txt")).expect("remove");
        assert_eq!(verify(&result).sources[0].status, SourceStatus::Missing);
        result.sources[0].sha256 = None;
        assert_eq!(verify(&result).sources[0].status, SourceStatus::Unhashed);
        result.summary.cancelled = true;
        assert!(!verify(&result).all_match());
    }

    #[test]
    fn refuses_paths_that_escape_the_evidence_root() {
        let directory = tempfile::tempdir().expect("directory");
        let mut result = ScanResult::default();
        for resource_id in ["../secret", "/etc/passwd", "C:/secret", "..\\secret"] {
            result.sources.push(SourceRecord {
                resource_id: resource_id.into(),
                size: 0,
                sha256: None,
            });
        }
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink("/etc", directory.path().join("link")).expect("link");
            result.sources.push(SourceRecord {
                resource_id: "link/passwd".into(),
                size: 0,
                sha256: Some("a".repeat(64)),
            });
        }
        let report =
            verify_sources(&result, directory.path(), &AtomicBool::new(false)).expect("verify");
        assert!(
            report
                .sources
                .iter()
                .all(|source| source.status == SourceStatus::UnsafePath)
        );
    }
}
