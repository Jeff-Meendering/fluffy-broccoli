//! Ingest: walk an evidence folder and record what each file holds.

use std::collections::HashSet;
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use rollcall_detect::infer_schema;
use rollcall_extract::{Limits, extract};
use rollcall_link::link_table;
use rollcall_model::{CoverageGap, GapKind, PersonRecord, visible};
use rusqlite::{OptionalExtension, Transaction, params};
use sha2::{Digest, Sha256};

use crate::store::{Case, ENGINE, sha256_hex};

#[derive(Debug, Clone, Copy)]
pub struct IngestOptions {
    /// Files larger than this are hashed and reported, but not read.
    pub max_file_bytes: u64,
    pub limits: Limits,
}

impl Default for IngestOptions {
    fn default() -> Self {
        Self {
            max_file_bytes: 512 * 1024 * 1024,
            limits: Limits::default(),
        }
    }
}

/// What one ingest run did. Counts refer to this run except where noted.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct IngestSummary {
    /// Regular files found under the evidence folder.
    pub discovered: u64,
    /// Files whose content was extracted in this run.
    pub read: u64,
    /// Files unchanged since an earlier run, whose records were kept as they were.
    pub reused: u64,
    /// Files that could not be opened or were over the size limit.
    pub not_read: u64,
    /// Person records created in this run.
    pub new_records: u64,
    /// Files ingested earlier that are no longer in the folder.
    pub missing: u64,
    /// Person records in the case after this run.
    pub total_records: u64,
    /// Coverage gaps in the case after this run.
    pub total_gaps: u64,
    /// People in the case after this run, once records were resolved.
    pub persons: u64,
    /// Pairs of records that may be one person and await a reviewer.
    pub suggestions: u64,
}

enum Found {
    File(PathBuf),
    /// Something under the evidence folder that was not read, and why.
    Skipped(GapKind, String),
}

/// Ingests every file under `root` into the case.
pub fn ingest(case: &mut Case, root: &Path, options: &IngestOptions) -> Result<IngestSummary> {
    let root = root
        .canonicalize()
        .with_context(|| format!("evidence folder {} is not accessible", root.display()))?;
    if !root.is_dir() {
        bail!("{} is not a folder", root.display());
    }
    if case
        .path()
        .canonicalize()
        .is_ok_and(|path| path.starts_with(&root))
    {
        bail!("the case file must be kept outside the evidence folder");
    }

    let run = case
        .meta("run")?
        .and_then(|value| value.parse::<i64>().ok())
        .unwrap_or(0)
        + 1;
    case.connection.execute(
        "INSERT INTO meta(key, value) VALUES('run', ?1)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        params![run.to_string()],
    )?;
    // Gaps not tied to a stored document describe the folder as it was last run.
    case.connection.execute(
        "DELETE FROM gaps WHERE document_id IS NULL OR kind = 'missing'",
        [],
    )?;

    let mut summary = IngestSummary::default();
    for (logical, found) in walk(&root) {
        let transaction = case.connection.transaction()?;
        match found {
            Found::Skipped(kind, detail) => {
                insert_gap(
                    &transaction,
                    None,
                    &logical,
                    &CoverageGap::new(None, kind, detail),
                )?;
            }
            Found::File(path) => {
                summary.discovered += 1;
                ingest_file(&transaction, run, &logical, &path, options, &mut summary)?;
            }
        }
        transaction.commit()?;
    }

    summary.missing = u64::try_from(case.connection.execute(
        "INSERT INTO gaps(document_id, path, scope, kind, detail)
         SELECT id, path, NULL, 'missing',
                'File was ingested earlier but is no longer in the evidence folder; \
                 its records are kept.'
         FROM documents WHERE last_seen_run < ?1",
        params![run],
    )?)
    .unwrap_or(0);
    let resolved = case.resolve()?;
    let counts = case.counts()?;
    summary.total_records = counts.records;
    summary.total_gaps = counts.gaps;
    summary.persons = resolved.persons;
    summary.suggestions = resolved.suggestions;
    case.append_audit(
        "ingest",
        &format!(
            "Run {run}: {} files found, {} read, {} unchanged, {} not read, {} no longer present. \
             Case now holds {} records, {} persons, {} open suggestions, {} coverage gaps. Engine: {ENGINE}.",
            summary.discovered,
            summary.read,
            summary.reused,
            summary.not_read,
            summary.missing,
            summary.total_records,
            summary.persons,
            summary.suggestions,
            summary.total_gaps,
        ),
    )?;
    Ok(summary)
}

fn ingest_file(
    transaction: &Transaction<'_>,
    run: i64,
    logical: &str,
    path: &Path,
    options: &IngestOptions,
    summary: &mut IngestSummary,
) -> Result<()> {
    let content = read_bounded(path, options.max_file_bytes);
    let (sha256, bytes) = match &content {
        Content::Read { sha256, data } => (Some(sha256.as_str()), data.len() as u64),
        Content::TooLarge { sha256, bytes } => (Some(sha256.as_str()), *bytes),
        Content::Failed(_) => (None, 0),
    };
    let file_hash = sha256.unwrap_or_default().to_owned();

    let existing: Option<(i64, Option<String>, String)> = transaction
        .query_row(
            "SELECT id, sha256, engine FROM documents WHERE path = ?1",
            params![logical],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?;
    if let Some((id, stored_hash, engine)) = existing {
        if sha256.is_some() && stored_hash.as_deref() == sha256 && engine == ENGINE {
            transaction.execute(
                "UPDATE documents SET last_seen_run = ?1 WHERE id = ?2",
                params![run, id],
            )?;
            summary.reused += 1;
            return Ok(());
        }
        transaction.execute("DELETE FROM documents WHERE id = ?1", params![id])?;
    }

    let status = if matches!(content, Content::Read { .. }) {
        "read"
    } else {
        "not_read"
    };
    transaction.execute(
        "INSERT INTO documents(path, sha256, bytes, engine, status, last_seen_run)
         VALUES(?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            logical,
            sha256,
            i64::try_from(bytes).unwrap_or(i64::MAX),
            ENGINE,
            status,
            run
        ],
    )?;
    let document = transaction.last_insert_rowid();

    let data = match content {
        Content::Read { data, .. } => data,
        Content::TooLarge { bytes, .. } => {
            summary.not_read += 1;
            let detail = format!(
                "File is {bytes} bytes, above the {} byte limit; it was not read.",
                options.max_file_bytes
            );
            let gap = CoverageGap::new(None, GapKind::Truncated, detail);
            return insert_gap(transaction, Some(document), logical, &gap);
        }
        Content::Failed(reason) => {
            summary.not_read += 1;
            let gap = CoverageGap::new(
                None,
                GapKind::Unreadable,
                format!("File could not be read: {reason}."),
            );
            return insert_gap(transaction, Some(document), logical, &gap);
        }
    };
    summary.read += 1;

    let extraction = extract(logical, &data, &options.limits);
    for gap in &extraction.gaps {
        insert_gap(transaction, Some(document), logical, gap)?;
    }
    for table in &extraction.tables {
        let schema = infer_schema(table);
        if schema.columns.is_empty() {
            let rows = table
                .rows
                .iter()
                .filter(|row| row.iter().any(|cell| !cell.trim().is_empty()));
            let widest = table.rows.iter().map(Vec::len).max().unwrap_or(0);
            let detail = format!(
                "No column of this table (rows: {}, columns: {widest}) was recognised as personal data.",
                rows.count()
            );
            let gap = CoverageGap::new(table.scope.clone(), GapKind::Unrecognised, detail);
            insert_gap(transaction, Some(document), logical, &gap)?;
            continue;
        }
        for record in link_table(table, &schema) {
            insert_record(transaction, document, logical, &file_hash, &record)?;
            summary.new_records += 1;
        }
    }
    Ok(())
}

fn insert_record(
    transaction: &Transaction<'_>,
    document: i64,
    logical: &str,
    file_hash: &str,
    record: &PersonRecord,
) -> Result<()> {
    let fingerprint = sha256_hex(
        format!(
            "{logical}\n{file_hash}\n{}\n{}\n{}",
            record.scope.as_deref().unwrap_or_default(),
            record.row,
            record.relation.as_deref().unwrap_or_default()
        )
        .as_bytes(),
    );
    transaction
        .prepare_cached(
            "INSERT INTO records(document_id, scope, row, relation, fingerprint)
             VALUES(?1, ?2, ?3, ?4, ?5)",
        )?
        .execute(params![
            document,
            record.scope,
            record.row,
            record.relation,
            fingerprint
        ])?;
    let id = transaction.last_insert_rowid();
    let mut statement = transaction.prepare_cached(
        "INSERT INTO observations(record_id, kind, raw, normalized, valid, col, header, method)
         VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
    )?;
    for observation in &record.observations {
        statement.execute(params![
            id,
            observation.kind.as_str(),
            observation.raw,
            observation.normalized,
            observation.valid,
            observation.column,
            observation.header,
            observation.method.as_str(),
        ])?;
    }
    Ok(())
}

fn insert_gap(
    transaction: &Transaction<'_>,
    document: Option<i64>,
    logical: &str,
    gap: &CoverageGap,
) -> Result<()> {
    transaction
        .prepare_cached(
            "INSERT INTO gaps(document_id, path, scope, kind, detail) VALUES(?1, ?2, ?3, ?4, ?5)",
        )?
        .execute(params![
            document,
            logical,
            gap.scope,
            gap.kind.as_str(),
            gap.detail
        ])?;
    Ok(())
}

enum Content {
    Read { sha256: String, data: Vec<u8> },
    TooLarge { sha256: String, bytes: u64 },
    Failed(String),
}

/// Reads a file up to `limit` bytes; larger files are hashed in passing but not kept.
fn read_bounded(path: &Path, limit: u64) -> Content {
    let outcome = (|| -> std::io::Result<Content> {
        let mut file = File::open(path)?;
        let mut hasher = Sha256::new();
        let mut data = Vec::new();
        let mut bytes = 0_u64;
        let mut buffer = vec![0_u8; 64 * 1024];
        loop {
            let count = file.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            hasher.update(&buffer[..count]);
            bytes += count as u64;
            if bytes <= limit {
                data.extend_from_slice(&buffer[..count]);
            } else {
                data = Vec::new();
            }
        }
        let sha256 = hasher
            .finalize()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        Ok(if bytes <= limit {
            Content::Read { sha256, data }
        } else {
            Content::TooLarge { sha256, bytes }
        })
    })();
    outcome.unwrap_or_else(|error| Content::Failed(error.kind().to_string()))
}

/// Lists everything under `root` in a stable order, as paths relative to it with `/`
/// separators. Symbolic links are reported, never followed: a link could point outside
/// the evidence or back into it.
fn walk(root: &Path) -> Vec<(String, Found)> {
    let mut found = Vec::new();
    let mut pending = vec![(String::new(), root.to_owned())];
    while let Some((prefix, directory)) = pending.pop() {
        let entries =
            fs::read_dir(&directory).and_then(Iterator::collect::<std::io::Result<Vec<_>>>);
        let mut entries = match entries {
            Ok(entries) => entries,
            Err(error) => {
                let detail = format!("Folder could not be listed: {}.", error.kind());
                found.push((prefix, Found::Skipped(GapKind::Unreadable, detail)));
                continue;
            }
        };
        entries.sort_by_key(fs::DirEntry::file_name);
        for entry in entries {
            let name = visible(&entry.file_name().to_string_lossy());
            let logical = if prefix.is_empty() {
                name
            } else {
                format!("{prefix}/{name}")
            };
            match entry.file_type() {
                Ok(kind) if kind.is_symlink() => found.push((
                    logical,
                    Found::Skipped(
                        GapKind::Unsupported,
                        "Symbolic link was not followed.".to_owned(),
                    ),
                )),
                Ok(kind) if kind.is_dir() => pending.push((logical, entry.path())),
                Ok(kind) if kind.is_file() => found.push((logical, Found::File(entry.path()))),
                Ok(_) => found.push((
                    logical,
                    Found::Skipped(
                        GapKind::Unsupported,
                        "Not a regular file; it was not read.".to_owned(),
                    ),
                )),
                Err(error) => found.push((
                    logical,
                    Found::Skipped(
                        GapKind::Unreadable,
                        format!("Entry could not be examined: {}.", error.kind()),
                    ),
                )),
            }
        }
    }
    found.sort_by(|left, right| left.0.cmp(&right.0));
    // Names that are not valid text are shown with stand-in characters, so two files can
    // end up with one name. Each file must keep its own entry in the case.
    let mut seen: HashSet<String> = HashSet::new();
    for (logical, _) in &mut found {
        let mut copy = 2;
        let original = logical.clone();
        while !seen.insert(logical.clone()) {
            *logical = format!("{original} (name collision {copy})");
            copy += 1;
        }
    }
    found
}
