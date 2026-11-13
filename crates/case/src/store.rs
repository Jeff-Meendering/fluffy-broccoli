//! The case database.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use rollcall_model::{ElementKind, GapKind, Method, Observation};
use rusqlite::{Connection, OptionalExtension, params};

const SCHEMA: &str = include_str!("schema.sql");
const SCHEMA_VERSION: i64 = 1;

/// Identifies the reading and detection logic that produced a document's records.
/// A document ingested by a different engine is read again rather than reused.
pub const ENGINE: &str = concat!("rollcall ", env!("CARGO_PKG_VERSION"), " / case schema 1");

pub struct Case {
    pub(crate) connection: Connection,
    path: PathBuf,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Counts {
    pub documents: u64,
    pub records: u64,
    pub gaps: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredDocument {
    pub path: String,
    pub sha256: Option<String>,
    pub bytes: u64,
    /// `read` when the content was extracted, `not_read` otherwise.
    pub status: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredRecord {
    pub id: i64,
    pub path: String,
    pub sha256: Option<String>,
    pub scope: Option<String>,
    pub row: u32,
    pub relation: Option<String>,
    pub observations: Vec<Observation>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredGap {
    pub path: String,
    pub scope: Option<String>,
    pub kind: GapKind,
    pub detail: String,
}

impl Case {
    /// Opens the case at `path`, creating it when it does not exist yet.
    pub fn create_or_open(path: &Path) -> Result<Self> {
        if path.exists() {
            return Self::open_existing(path);
        }
        create_private_file(path)
            .with_context(|| format!("could not create case file {}", path.display()))?;
        let connection = Connection::open(path)?;
        connection.execute_batch("PRAGMA foreign_keys = ON; BEGIN;")?;
        connection.execute_batch(SCHEMA)?;
        connection.pragma_update(None, "user_version", SCHEMA_VERSION)?;
        connection.execute_batch("COMMIT;")?;
        Ok(Self {
            connection,
            path: path.to_owned(),
        })
    }

    /// Opens a case that must already exist.
    pub fn open_existing(path: &Path) -> Result<Self> {
        if !path.is_file() {
            bail!("no case file at {}", path.display());
        }
        let connection = Connection::open(path)
            .with_context(|| format!("could not open case file {}", path.display()))?;
        let version: i64 = connection
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .with_context(|| format!("{} is not a rollcall case", path.display()))?;
        if version != SCHEMA_VERSION {
            bail!(
                "{} is not a rollcall case this version can open (schema {version}, expected {SCHEMA_VERSION})",
                path.display()
            );
        }
        connection.execute_batch("PRAGMA foreign_keys = ON;")?;
        Ok(Self {
            connection,
            path: path.to_owned(),
        })
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn counts(&self) -> Result<Counts> {
        let count = |table: &str| -> Result<u64> {
            let value: i64 =
                self.connection
                    .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                        row.get(0)
                    })?;
            Ok(u64::try_from(value).unwrap_or(0))
        };
        Ok(Counts {
            documents: count("documents")?,
            records: count("records")?,
            gaps: count("gaps")?,
        })
    }

    pub fn documents(&self) -> Result<Vec<StoredDocument>> {
        let mut statement = self
            .connection
            .prepare("SELECT path, sha256, bytes, status FROM documents ORDER BY path")?;
        let rows = statement.query_map([], |row| {
            Ok(StoredDocument {
                path: row.get(0)?,
                sha256: row.get(1)?,
                bytes: u64::try_from(row.get::<_, i64>(2)?).unwrap_or(0),
                status: row.get(3)?,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    pub fn gaps(&self) -> Result<Vec<StoredGap>> {
        let mut statement = self.connection.prepare(
            "SELECT path, scope, kind, detail FROM gaps ORDER BY path, scope IS NOT NULL, scope, id",
        )?;
        let rows = statement.query_map([], |row| {
            let kind: String = row.get(2)?;
            Ok(StoredGap {
                path: row.get(0)?,
                scope: row.get(1)?,
                kind: GapKind::parse(&kind).unwrap_or(GapKind::Unreadable),
                detail: row.get(3)?,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    /// Visits every person record in a stable order: by file, sheet, row, then relation.
    ///
    /// Records are streamed, so a case larger than memory can still be exported.
    pub fn for_each_record(&self, mut visit: impl FnMut(StoredRecord) -> Result<()>) -> Result<()> {
        let mut statement = self.connection.prepare(
            "SELECT r.id, d.path, d.sha256, r.scope, r.row, r.relation,
                    o.kind, o.raw, o.normalized, o.valid, o.col, o.header, o.method
             FROM records r
             JOIN documents d ON d.id = r.document_id
             LEFT JOIN observations o ON o.record_id = r.id
             ORDER BY d.path, r.scope IS NOT NULL, r.scope, r.row, r.relation IS NOT NULL,
                      r.relation, r.id, o.id",
        )?;
        let mut rows = statement.query([])?;
        let mut current: Option<StoredRecord> = None;
        while let Some(row) = rows.next()? {
            let id: i64 = row.get(0)?;
            if current.as_ref().is_some_and(|record| record.id != id)
                && let Some(finished) = current.take()
            {
                visit(finished)?;
            }
            let record = match &mut current {
                Some(record) => record,
                empty => empty.insert(StoredRecord {
                    id,
                    path: row.get(1)?,
                    sha256: row.get(2)?,
                    scope: row.get(3)?,
                    row: row.get(4)?,
                    relation: row.get(5)?,
                    observations: Vec::new(),
                }),
            };
            let kind: Option<String> = row.get(6)?;
            let Some(kind) = kind.as_deref().and_then(ElementKind::parse) else {
                continue;
            };
            let method: String = row.get(12)?;
            record.observations.push(Observation {
                kind,
                raw: row.get(7)?,
                normalized: row.get(8)?,
                valid: row.get(9)?,
                column: row.get(10)?,
                header: row.get(11)?,
                method: Method::parse(&method).unwrap_or(Method::Header),
            });
        }
        if let Some(finished) = current {
            visit(finished)?;
        }
        Ok(())
    }

    pub(crate) fn meta(&self, key: &str) -> Result<Option<String>> {
        Ok(self
            .connection
            .query_row(
                "SELECT value FROM meta WHERE key = ?1",
                params![key],
                |row| row.get(0),
            )
            .optional()?)
    }
}

#[cfg(unix)]
fn create_private_file(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    // A case holds personal data: readable and writable by its owner only.
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map(drop)
}

#[cfg(not(unix))]
fn create_private_file(path: &Path) -> std::io::Result<()> {
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map(drop)
}
