//! The case database.

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use rollcall_model::{ElementKind, GapKind, Method, Observation, Unit};
use rusqlite::{Connection, OptionalExtension, params};
use sha2::{Digest, Sha256};

const SCHEMA: &str = include_str!("schema.sql");
const SCHEMA_VERSION: i64 = 3;

/// Identifies the reading and detection logic that produced a document's records.
/// A document ingested by a different engine is read again rather than reused.
pub const ENGINE: &str = concat!("rollcall ", env!("CARGO_PKG_VERSION"), " / case schema 3");

pub struct Case {
    pub(crate) connection: Connection,
    path: PathBuf,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Counts {
    pub documents: u64,
    pub records: u64,
    pub persons: u64,
    pub suggestions: u64,
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
    /// The person this record was resolved to.
    pub person: i64,
    pub fingerprint: String,
    pub path: String,
    pub sha256: Option<String>,
    pub scope: Option<String>,
    pub row: u32,
    /// What `row` counts: rows of a table or lines of text.
    pub unit: Unit,
    pub relation: Option<String>,
    pub observations: Vec<Observation>,
}

impl StoredRecord {
    /// Where the record came from, as a person would cite it.
    #[must_use]
    pub fn source(&self) -> String {
        let sheet = self
            .scope
            .as_deref()
            .map(|scope| format!(" [{scope}]"))
            .unwrap_or_default();
        // Rows and lines are stored zero-based; people count them from one.
        format!(
            "{}{sheet} {} {}",
            self.path,
            self.unit.as_str(),
            u64::from(self.row) + 1
        )
    }
}

/// One affected person: every record resolved to them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredPerson {
    pub id: i64,
    pub records: Vec<StoredRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredGap {
    pub path: String,
    pub scope: Option<String>,
    pub kind: GapKind,
    pub detail: String,
}

const RECORD_COLUMNS: &str = "SELECT r.id, d.path, d.sha256, r.scope, r.row, r.relation,
        o.kind, o.raw, o.normalized, o.valid, o.col, o.header, o.method,
        r.fingerprint, COALESCE(m.person_id, r.id) AS person, r.unit
 FROM records r
 JOIN documents d ON d.id = r.document_id
 LEFT JOIN membership m ON m.record_id = r.id
 LEFT JOIN observations o ON o.record_id = r.id";
const SOURCE_ORDER: &str = "d.path, r.scope IS NOT NULL, r.scope, r.row, r.relation IS NOT NULL,
        r.relation, r.id, o.id";

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
        let case = Self {
            connection,
            path: path.to_owned(),
        };
        case.append_audit("case-created", &format!("Case created by {ENGINE}."))?;
        Ok(case)
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
                "{} cannot be opened by this version (case schema {version}, expected \
                 {SCHEMA_VERSION}); ingest the evidence into a new case",
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
        let count = |query: &str| -> Result<u64> {
            let value: i64 = self.connection.query_row(query, [], |row| row.get(0))?;
            Ok(u64::try_from(value).unwrap_or(0))
        };
        Ok(Counts {
            documents: count("SELECT COUNT(*) FROM documents")?,
            records: count("SELECT COUNT(*) FROM records")?,
            persons: count("SELECT COUNT(DISTINCT person_id) FROM membership")?,
            suggestions: count("SELECT COUNT(*) FROM suggestions")?,
            gaps: count("SELECT COUNT(*) FROM gaps")?,
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
    pub fn for_each_record(&self, visit: impl FnMut(StoredRecord) -> Result<()>) -> Result<()> {
        self.visit_records(
            &format!("{RECORD_COLUMNS} ORDER BY {SOURCE_ORDER}"),
            None,
            visit,
        )
    }

    /// Visits every person with all of their records, in order of person identifier.
    pub fn for_each_person(&self, mut visit: impl FnMut(StoredPerson) -> Result<()>) -> Result<()> {
        let mut current: Option<StoredPerson> = None;
        self.visit_records(
            &format!("{RECORD_COLUMNS} ORDER BY person, {SOURCE_ORDER}"),
            None,
            |record| {
                if current
                    .as_ref()
                    .is_some_and(|person| person.id != record.person)
                    && let Some(finished) = current.take()
                {
                    visit(finished)?;
                }
                current
                    .get_or_insert_with(|| StoredPerson {
                        id: record.person,
                        records: Vec::new(),
                    })
                    .records
                    .push(record);
                Ok(())
            },
        )?;
        current.map_or(Ok(()), visit)
    }

    /// One person by identifier, or `None` when no record resolves to it.
    pub fn person(&self, id: i64) -> Result<Option<StoredPerson>> {
        let mut records = Vec::new();
        let query = format!(
            "{RECORD_COLUMNS} WHERE COALESCE(m.person_id, r.id) = ?1 ORDER BY {SOURCE_ORDER}"
        );
        self.visit_records(&query, Some(id), |record| {
            records.push(record);
            Ok(())
        })?;
        Ok((!records.is_empty()).then_some(StoredPerson { id, records }))
    }

    fn visit_records(
        &self,
        query: &str,
        person: Option<i64>,
        mut visit: impl FnMut(StoredRecord) -> Result<()>,
    ) -> Result<()> {
        let mut statement = self.connection.prepare(query)?;
        let mut rows = match person {
            Some(person) => statement.query(params![person])?,
            None => statement.query([])?,
        };
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
                    person: row.get(14)?,
                    fingerprint: row.get(13)?,
                    path: row.get(1)?,
                    sha256: row.get(2)?,
                    scope: row.get(3)?,
                    row: row.get(4)?,
                    unit: Unit::parse(&row.get::<_, String>(15)?).unwrap_or(Unit::Row),
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
        current.map_or(Ok(()), visit)
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

    /// Adds an entry to the audit log, chained to the entry before it.
    pub(crate) fn append_audit(&self, kind: &str, detail: &str) -> Result<()> {
        let previous: String = self
            .connection
            .query_row(
                "SELECT hash FROM audit ORDER BY id DESC LIMIT 1",
                [],
                |row| row.get(0),
            )
            .optional()?
            .unwrap_or_default();
        let at = now();
        let detail = single_line(detail);
        let hash = audit_hash(&previous, at, kind, &detail);
        self.connection.execute(
            "INSERT INTO audit(at, kind, detail, previous, hash) VALUES(?1, ?2, ?3, ?4, ?5)",
            params![at, kind, detail, previous, hash],
        )?;
        Ok(())
    }
}

/// Seconds since 1970-01-01 UTC.
pub(crate) fn now() -> i64 {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs());
    i64::try_from(seconds).unwrap_or(i64::MAX)
}

pub(crate) fn sha256_hex(data: &[u8]) -> String {
    Sha256::digest(data)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

pub(crate) fn audit_hash(previous: &str, at: i64, kind: &str, detail: &str) -> String {
    sha256_hex(format!("{previous}\n{at}\n{kind}\n{detail}").as_bytes())
}

/// Free text from a person, made safe to store as one line of a log.
pub(crate) fn single_line(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
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
