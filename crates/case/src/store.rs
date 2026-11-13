use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use pii_explorer_core::hash::sha256_hex;
use pii_explorer_core::{
    AttentionItem, Finding, ScanEvent, ScanOptions, ScanSummary, SourceRecord,
};
use rusqlite::{Connection, OpenFlags, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

const APPLICATION_ID: i64 = 0x50494945;

pub struct CaseStore {
    pub(crate) connection: Connection,
    path: PathBuf,
}

#[derive(Debug, Clone, Serialize)]
pub struct CaseSummary {
    pub run_id: i64,
    pub status: String,
    pub discovered: u64,
    pub completed: u64,
    pub reused: u64,
    pub findings: u64,
    pub attention: u64,
    pub elapsed_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewStatus {
    Unreviewed,
    Confirmed,
    FalsePositive,
    NeedsReview,
}

impl ReviewStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unreviewed => "unreviewed",
            Self::Confirmed => "confirmed",
            Self::FalsePositive => "false_positive",
            Self::NeedsReview => "needs_review",
        }
    }
}

#[derive(Debug, Serialize)]
pub struct ReviewedFinding {
    pub id: i64,
    pub finding: Finding,
    pub status: String,
    pub note: String,
}

#[derive(Debug, Serialize)]
pub struct FindingPage {
    pub summary: CaseSummary,
    pub findings: Vec<ReviewedFinding>,
    pub next_after: Option<i64>,
}

impl CaseStore {
    pub fn create(path: &Path, root: &Path) -> Result<Self> {
        let root = root.canonicalize().context("resolve evidence root")?;
        pii_explorer_core::storage::create_private_file(path)
            .context("create a new private case file")?;
        let store = Self::connect(path, false)?;
        store.connection.execute_batch(include_str!("schema.sql"))?;
        store
            .connection
            .pragma_update(None, "application_id", APPLICATION_ID)?;
        store.connection.pragma_update(None, "user_version", 1)?;
        store.connection.execute(
            "INSERT INTO meta(key,value) VALUES('root',?1)",
            [root.to_string_lossy().as_ref()],
        )?;
        Ok(store)
    }

    pub fn open(path: &Path, read_only: bool) -> Result<Self> {
        let metadata = std::fs::symlink_metadata(path).context("inspect case file")?;
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            bail!("case must be a regular file, not a link");
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if metadata.permissions().mode() & 0o077 != 0 {
                bail!(
                    "case permissions allow group/other access; set mode 0600 before opening sensitive case data"
                );
            }
        }
        let store = Self::connect(path, read_only)?;
        let application: i64 =
            store
                .connection
                .pragma_query_value(None, "application_id", |row| row.get(0))?;
        let version: i64 = store
            .connection
            .pragma_query_value(None, "user_version", |row| row.get(0))?;
        if application != APPLICATION_ID || version != 1 {
            bail!("unsupported case database or schema version");
        }
        Ok(store)
    }

    fn connect(path: &Path, read_only: bool) -> Result<Self> {
        let flags = if read_only {
            OpenFlags::SQLITE_OPEN_READ_ONLY
        } else {
            OpenFlags::SQLITE_OPEN_READ_WRITE
        };
        let connection =
            Connection::open_with_flags(path, flags | OpenFlags::SQLITE_OPEN_NO_MUTEX)?;
        connection.busy_timeout(Duration::from_secs(5))?;
        connection.execute_batch("PRAGMA foreign_keys=ON; PRAGMA trusted_schema=OFF; PRAGMA temp_store=MEMORY; PRAGMA cache_size=-8192;")?;
        if !read_only {
            connection.execute_batch(
                "PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL; PRAGMA secure_delete=ON;",
            )?;
        }
        Ok(Self {
            connection,
            path: path.to_path_buf(),
        })
    }

    pub(crate) fn capture_lock(&self) -> Result<File> {
        let mut name = self.path.as_os_str().to_os_string();
        name.push(".scan-lock");
        let path = PathBuf::from(name);
        match pii_explorer_core::storage::create_private_file(&path) {
            Ok(file) => {
                file.try_lock()
                    .context("another scan is already writing this case")?;
                Ok(file)
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                if !std::fs::symlink_metadata(&path)?.is_file() {
                    bail!("case lock must be a regular file");
                }
                let file = std::fs::OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open(path)?;
                file.try_lock()
                    .context("another scan is already writing this case")?;
                Ok(file)
            }
            Err(error) => Err(error.into()),
        }
    }

    pub(crate) fn begin_run(
        &mut self,
        root: &Path,
        options: &ScanOptions,
        engine: &Value,
    ) -> Result<(i64, String)> {
        let root = root.canonicalize().context("resolve evidence root")?;
        let stored_root: String =
            self.connection
                .query_row("SELECT value FROM meta WHERE key='root'", [], |row| {
                    row.get(0)
                })?;
        if stored_root != root.to_string_lossy() {
            bail!("case evidence root differs; use a new case for a different root");
        }
        let config = json!({"options": options, "engine": engine});
        let hash = sha256_hex(serde_json::to_string(&config)?.as_bytes());
        let transaction = self.connection.transaction()?;
        transaction.execute(
            "UPDATE runs SET status='interrupted' WHERE status='in_progress'",
            [],
        )?;
        transaction.execute("INSERT INTO runs(started,status,config_hash,options_json,engine_json) VALUES(?1,'in_progress',?2,?3,?4)", params![now(), hash, serde_json::to_string(options)?, serde_json::to_string(engine)?])?;
        let id = transaction.last_insert_rowid();
        append_audit(
            &transaction,
            &json!({"event":"scan_started","run_id":id,"config_hash":hash,"time":now()}),
        )?;
        transaction.commit()?;
        Ok((id, hash))
    }

    pub(crate) fn reserve_many<'a>(
        &mut self,
        run: i64,
        resources: impl IntoIterator<Item = &'a str>,
    ) -> Result<()> {
        let transaction = self.connection.transaction()?;
        {
            let mut insert = transaction.prepare(
                "INSERT INTO run_resources(run_id,resource_id,status) VALUES(?1,?2,'pending')",
            )?;
            for resource in resources {
                insert.execute(params![run, resource])?;
            }
        }
        transaction.commit()?;
        Ok(())
    }

    pub(crate) fn start_resource(
        &mut self,
        run: i64,
        resource: &str,
        config: &str,
        digest: Option<&str>,
        refresh: bool,
    ) -> Result<Option<i64>> {
        let transaction = self.connection.transaction()?;
        if !refresh && let Some(digest) = digest {
            let cached: Option<i64> = transaction.query_row("SELECT s.id FROM snapshots s WHERE resource_id=?1 AND config_hash=?2 AND source_sha256=?3 AND finished=1 AND cancelled=0 AND NOT EXISTS(SELECT 1 FROM attention a WHERE a.snapshot_id=s.id) ORDER BY s.id DESC LIMIT 1", params![resource, config, digest], |row| row.get(0)).optional()?;
            if let Some(id) = cached {
                transaction.execute("UPDATE run_resources SET snapshot_id=?1,status='complete',reused=1 WHERE run_id=?2 AND resource_id=?3", params![id, run, resource])?;
                transaction.commit()?;
                return Ok(None);
            }
        }
        transaction.execute(
            "INSERT INTO snapshots(resource_id,config_hash) VALUES(?1,?2)",
            params![resource, config],
        )?;
        let id = transaction.last_insert_rowid();
        transaction.execute("UPDATE run_resources SET snapshot_id=?1,status='running' WHERE run_id=?2 AND resource_id=?3", params![id, run, resource])?;
        transaction.commit()?;
        Ok(Some(id))
    }

    pub(crate) fn record(&mut self, snapshot: i64, event: ScanEvent) -> Result<()> {
        let transaction = self.connection.transaction()?;
        match event {
            ScanEvent::Findings(findings) => {
                let mut insert = transaction.prepare("INSERT OR IGNORE INTO findings(snapshot_id,occurrence_key,type,value_sha256,confidence,payload,payload_sha256) VALUES(?1,?2,?3,?4,?5,?6,?7)")?;
                for finding in findings {
                    let payload = serde_json::to_string(&finding)?;
                    let key = sha256_hex(
                        serde_json::to_vec(&(finding.occurrence_key(), &finding.value))?.as_slice(),
                    );
                    insert.execute(params![
                        snapshot,
                        key,
                        finding.entity_type.as_str(),
                        sha256_hex(finding.value.as_bytes()),
                        finding.confidence,
                        payload,
                        sha256_hex(payload.as_bytes())
                    ])?;
                }
            }
            ScanEvent::Attention(attention) => {
                for item in attention {
                    transaction.execute(
                        "INSERT INTO attention(snapshot_id,payload) VALUES(?1,?2)",
                        params![snapshot, serde_json::to_string(&item)?],
                    )?;
                }
            }
            ScanEvent::Sources(sources) => {
                if sources.len() != 1 {
                    bail!("one root source record is required per resource");
                }
                let source = &sources[0];
                transaction.execute(
                    "UPDATE snapshots SET source_sha256=?1,source_json=?2 WHERE id=?3",
                    params![source.sha256, serde_json::to_string(source)?, snapshot],
                )?;
            }
            ScanEvent::Progress(_) => {}
        }
        transaction.commit()?;
        Ok(())
    }

    pub(crate) fn finish_resource(
        &mut self,
        run: i64,
        snapshot: i64,
        summary: &ScanSummary,
    ) -> Result<()> {
        let transaction = self.connection.transaction()?;
        transaction.execute(
            "UPDATE snapshots SET finished=1,cancelled=?1 WHERE id=?2",
            params![
                summary.cancelled
                    || summary.completed != summary.discovered
                    || summary.limit_reached.is_some(),
                snapshot
            ],
        )?;
        transaction.execute(
            "UPDATE run_resources SET status=?1 WHERE run_id=?2 AND snapshot_id=?3",
            params![
                if summary.cancelled {
                    "cancelled"
                } else {
                    "complete"
                },
                run,
                snapshot
            ],
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub(crate) fn run_attention(&self, run: i64, item: &AttentionItem) -> Result<()> {
        self.connection.execute(
            "INSERT INTO run_attention(run_id,payload) VALUES(?1,?2)",
            params![run, serde_json::to_string(item)?],
        )?;
        Ok(())
    }

    pub(crate) fn finish_run(
        &mut self,
        run: i64,
        cancelled: bool,
        elapsed: u64,
    ) -> Result<CaseSummary> {
        let transaction = self.connection.transaction()?;
        transaction.execute(
            "UPDATE runs SET status=?1,finished=?2,elapsed_ms=?3 WHERE id=?4",
            params![
                if cancelled { "cancelled" } else { "complete" },
                now(),
                i64::try_from(elapsed)?,
                run
            ],
        )?;
        append_audit(
            &transaction,
            &json!({"event":"scan_finished","run_id":run,"cancelled":cancelled,"time":now()}),
        )?;
        transaction.commit()?;
        self.summary(Some(run))
    }

    pub fn latest_run(&self) -> Result<i64> {
        self.connection
            .query_row("SELECT id FROM runs ORDER BY id DESC LIMIT 1", [], |row| {
                row.get(0)
            })
            .context("case has no scan runs")
    }

    pub fn summary(&self, run: Option<i64>) -> Result<CaseSummary> {
        let id = run.map_or_else(|| self.latest_run(), Ok)?;
        let (status, elapsed): (String, i64) = self.connection.query_row(
            "SELECT status,elapsed_ms FROM runs WHERE id=?1",
            [id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        let (discovered, completed, reused): (i64,i64,i64) = self.connection.query_row("SELECT count(*),coalesce(sum(status='complete'),0),coalesce(sum(reused),0) FROM run_resources WHERE run_id=?1", [id], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?)))?;
        let findings: i64 = self.connection.query_row("SELECT count(*) FROM findings f JOIN run_resources r ON r.snapshot_id=f.snapshot_id WHERE r.run_id=?1", [id], |row| row.get(0))?;
        let attention: i64 = self.connection.query_row("SELECT (SELECT count(*) FROM attention a JOIN run_resources r ON r.snapshot_id=a.snapshot_id WHERE r.run_id=?1)+(SELECT count(*) FROM run_attention WHERE run_id=?1)", [id], |row| row.get(0))?;
        Ok(CaseSummary {
            run_id: id,
            status,
            discovered: u64::try_from(discovered)?,
            completed: u64::try_from(completed)?,
            reused: u64::try_from(reused)?,
            findings: u64::try_from(findings)?,
            attention: u64::try_from(attention)?,
            elapsed_ms: u64::try_from(elapsed)?,
        })
    }

    pub fn runs(&self) -> Result<Vec<Value>> {
        let mut statement = self.connection.prepare("SELECT id,status,started,finished,config_hash,elapsed_ms FROM runs ORDER BY id DESC LIMIT 1000")?;
        let mut rows = statement.query([])?;
        let mut result = Vec::new();
        while let Some(row) = rows.next()? {
            result.push(json!({"id":row.get::<_,i64>(0)?,"status":row.get::<_,String>(1)?,"started":row.get::<_,i64>(2)?,"finished":row.get::<_,Option<i64>>(3)?,"config_hash":row.get::<_,String>(4)?,"elapsed_ms":row.get::<_,i64>(5)?}));
        }
        Ok(result)
    }

    pub fn findings(
        &self,
        run: Option<i64>,
        after: i64,
        limit: usize,
        status: Option<ReviewStatus>,
        entity: Option<&str>,
    ) -> Result<FindingPage> {
        if !(1..=1000).contains(&limit) || after < 0 {
            bail!("finding page requires a limit of 1–1000 and a nonnegative cursor");
        }
        let summary = self.summary(run)?;
        let mut statement = self.connection.prepare("SELECT f.id,f.payload,coalesce(v.status,'unreviewed'),coalesce(v.note,'') FROM findings f JOIN run_resources r ON r.snapshot_id=f.snapshot_id LEFT JOIN reviews v ON v.finding_id=f.id WHERE r.run_id=?1 AND f.id>?2 AND (?3 IS NULL OR coalesce(v.status,'unreviewed')=?3) AND (?4 IS NULL OR f.type=?4) ORDER BY f.id LIMIT ?5")?;
        let mut rows = statement.query(params![
            summary.run_id,
            after,
            status.map(ReviewStatus::as_str),
            entity,
            i64::try_from(limit + 1)?
        ])?;
        let mut findings = Vec::new();
        while let Some(row) = rows.next()? {
            findings.push(ReviewedFinding {
                id: row.get(0)?,
                finding: serde_json::from_str(&row.get::<_, String>(1)?)?,
                status: row.get(2)?,
                note: row.get(3)?,
            });
        }
        let next_after = if findings.len() > limit {
            findings.pop();
            findings.last().map(|finding| finding.id)
        } else {
            None
        };
        Ok(FindingPage {
            summary,
            findings,
            next_after,
        })
    }

    pub fn review(
        &mut self,
        finding: i64,
        status: ReviewStatus,
        note: &str,
        reviewer: &str,
    ) -> Result<()> {
        if note.len() > 16_384 || reviewer.len() > 256 || reviewer.chars().any(char::is_control) {
            bail!("review note or reviewer exceeds its limit");
        }
        let transaction = self.connection.transaction()?;
        let finished: bool = transaction.query_row("SELECT s.finished FROM findings f JOIN snapshots s ON s.id=f.snapshot_id WHERE f.id=?1", [finding], |row| row.get(0)).context("finding does not exist")?;
        if !finished {
            bail!("wait for this resource checkpoint before reviewing its findings");
        }
        transaction.execute("INSERT INTO reviews(finding_id,status,note,reviewer,updated) VALUES(?1,?2,?3,?4,?5) ON CONFLICT(finding_id) DO UPDATE SET status=excluded.status,note=excluded.note,reviewer=excluded.reviewer,updated=excluded.updated", params![finding,status.as_str(),note,reviewer,now()])?;
        append_audit(
            &transaction,
            &json!({"event":"review","finding_id":finding,"status":status,"note":note,"reviewer":reviewer,"time":now()}),
        )?;
        transaction.commit()?;
        Ok(())
    }

    /// Export row by row. Original findings are always retained; review decisions are additive.
    pub fn export_jsonl(&self, run: Option<i64>, writer: &mut dyn Write) -> Result<()> {
        let summary = self.summary(run)?;
        let (options, engine): (String, String) = self.connection.query_row(
            "SELECT options_json,engine_json FROM runs WHERE id=?1",
            [summary.run_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        line(
            writer,
            &json!({"kind":"settings","settings":serde_json::from_str::<Value>(&options)?,"engine":serde_json::from_str::<Value>(&engine)?,"case_run":summary.run_id}),
        )?;
        let mut resources = self.connection.prepare("SELECT snapshot_id FROM run_resources WHERE run_id=?1 AND snapshot_id IS NOT NULL ORDER BY resource_id")?;
        let mut resource_rows = resources.query([summary.run_id])?;
        let mut findings = self.connection.prepare("SELECT f.payload,f.id,coalesce(v.status,'unreviewed'),coalesce(v.note,'') FROM findings f LEFT JOIN reviews v ON v.finding_id=f.id WHERE f.snapshot_id=?1 ORDER BY f.occurrence_key")?;
        while let Some(resource) = resource_rows.next()? {
            let mut rows = findings.query([resource.get::<_, i64>(0)?])?;
            while let Some(row) = rows.next()? {
                line(
                    writer,
                    &json!({"kind":"finding","finding":serde_json::from_str::<Value>(&row.get::<_,String>(0)?)?,"review":{"id":row.get::<_,i64>(1)?,"status":row.get::<_,String>(2)?,"note":row.get::<_,String>(3)?}}),
                )?;
            }
        }
        let mut statement = self.connection.prepare("SELECT payload FROM run_attention WHERE run_id=?1 UNION ALL SELECT a.payload FROM attention a JOIN run_resources r ON r.snapshot_id=a.snapshot_id WHERE r.run_id=?1")?;
        let mut rows = statement.query([summary.run_id])?;
        while let Some(row) = rows.next()? {
            line(
                writer,
                &json!({"kind":"attention","attention":serde_json::from_str::<Value>(&row.get::<_,String>(0)?)?}),
            )?;
        }
        let mut statement = self.connection.prepare("SELECT s.source_json FROM snapshots s JOIN run_resources r ON r.snapshot_id=s.id WHERE r.run_id=?1 AND s.source_json IS NOT NULL ORDER BY r.resource_id")?;
        let mut rows = statement.query([summary.run_id])?;
        while let Some(row) = rows.next()? {
            line(
                writer,
                &json!({"kind":"source","source":serde_json::from_str::<SourceRecord>(&row.get::<_,String>(0)?)?}),
            )?;
        }
        line(
            writer,
            &json!({"kind":"summary","summary":ScanSummary {discovered:summary.discovered,completed:summary.completed,findings:usize::try_from(summary.findings)?,attention:usize::try_from(summary.attention)?,cancelled:summary.status!="complete",limit_reached:None,elapsed_ms:summary.elapsed_ms}}),
        )?;
        writer.flush()?;
        Ok(())
    }

    /// Verify internal consistency, not authenticity: an attacker can rewrite an unsigned case.
    pub fn integrity(&self) -> Result<Value> {
        let check: String = self
            .connection
            .query_row("PRAGMA integrity_check", [], |row| row.get(0))?;
        if check != "ok" {
            bail!("SQLite integrity check failed");
        }
        if self
            .connection
            .prepare("PRAGMA foreign_key_check")?
            .query([])?
            .next()?
            .is_some()
        {
            bail!("case contains inconsistent references");
        }
        let mut previous = String::new();
        let mut count = 0_u64;
        let mut statement = self.connection.prepare(
            "SELECT previous_sha256,event_json,sha256,kind,finding_id FROM audit ORDER BY id",
        )?;
        let mut rows = statement.query([])?;
        while let Some(row) = rows.next()? {
            let parent: String = row.get(0)?;
            let event: String = row.get(1)?;
            let digest: String = row.get(2)?;
            if parent != previous || digest != audit_hash(&previous, &event)? {
                bail!("case audit chain is inconsistent");
            }
            let parsed: Value = serde_json::from_str(&event)?;
            if parsed.get("event").and_then(Value::as_str)
                != Some(row.get::<_, String>(3)?.as_str())
                || parsed.get("finding_id").and_then(Value::as_i64)
                    != row.get::<_, Option<i64>>(4)?
            {
                bail!("case audit index differs from its event");
            }
            previous = digest;
            count += 1;
        }
        let mut statement = self
            .connection
            .prepare("SELECT payload,payload_sha256 FROM findings")?;
        let mut rows = statement.query([])?;
        let mut findings = 0_u64;
        while let Some(row) = rows.next()? {
            let payload: String = row.get(0)?;
            if sha256_hex(payload.as_bytes()) != row.get::<_, String>(1)? {
                bail!("a stored finding failed its integrity check");
            }
            serde_json::from_str::<Finding>(&payload)?;
            findings += 1;
        }
        let missing_review: bool = self.connection.query_row("SELECT EXISTS(SELECT 1 FROM audit a LEFT JOIN reviews r ON r.finding_id=a.finding_id WHERE a.kind='review' AND r.finding_id IS NULL)",[],|row|row.get(0))?;
        if missing_review {
            bail!("a review recorded in the audit trail is missing");
        }
        let mut statement = self.connection.prepare("SELECT r.finding_id,r.status,r.note,r.reviewer,r.updated,(SELECT event_json FROM audit WHERE kind='review' AND finding_id=r.finding_id ORDER BY id DESC LIMIT 1) FROM reviews r")?;
        let mut rows = statement.query([])?;
        while let Some(row) = rows.next()? {
            let event: Option<String> = row.get(5)?;
            let event: Value = serde_json::from_str(
                event
                    .as_deref()
                    .context("review is missing its audit event")?,
            )?;
            if event["finding_id"] != row.get::<_, i64>(0)?
                || event["status"] != row.get::<_, String>(1)?
                || event["note"] != row.get::<_, String>(2)?
                || event["reviewer"] != row.get::<_, String>(3)?
                || event["time"] != row.get::<_, i64>(4)?
            {
                bail!("a review decision differs from its audit event");
            }
        }
        Ok(
            json!({"sqlite":"ok","audit_events":count,"audit_head_sha256":previous,"stored_findings":findings,"interpretation":"Internal consistency only; unsigned records do not prove authenticity or chain of custody."}),
        )
    }
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |time| time.as_secs().min(i64::MAX as u64) as i64)
}
fn line(writer: &mut dyn Write, value: &Value) -> Result<()> {
    serde_json::to_writer(&mut *writer, value)?;
    writer.write_all(b"\n")?;
    Ok(())
}
fn audit_hash(previous: &str, event: &str) -> Result<String> {
    Ok(sha256_hex(&serde_json::to_vec(&(previous, event))?))
}
fn append_audit(connection: &Connection, event: &Value) -> Result<()> {
    let previous: String = connection
        .query_row(
            "SELECT sha256 FROM audit ORDER BY id DESC LIMIT 1",
            [],
            |row| row.get(0),
        )
        .optional()?
        .unwrap_or_default();
    let kind = event
        .get("event")
        .and_then(Value::as_str)
        .context("audit event kind")?;
    let finding = event.get("finding_id").and_then(Value::as_i64);
    let event = serde_json::to_string(event)?;
    connection.execute(
        "INSERT INTO audit(kind,finding_id,previous_sha256,event_json,sha256) VALUES(?1,?2,?3,?4,?5)",
        params![kind,finding,previous,event,audit_hash(&previous, &event)?],
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use pii_explorer_core::Scanner;
    use std::sync::{Arc, atomic::AtomicBool};

    #[test]
    fn capture_lock_excludes_a_second_writer_and_is_released_on_drop() {
        let directory = tempfile::tempdir().expect("directory");
        let path = directory.path().join("case.piicase");
        let first = CaseStore::create(&path, directory.path()).expect("case");
        let second = CaseStore::open(&path, false).expect("second connection");
        let guard = first.capture_lock().expect("first lock");
        assert!(second.capture_lock().is_err());
        drop(guard);
        second.capture_lock().expect("released lock");
    }

    #[test]
    fn incomplete_snapshot_is_never_reused_after_an_unfinished_capture() {
        let directory = tempfile::tempdir().expect("directory");
        let root = directory.path().join("evidence");
        std::fs::create_dir(&root).expect("root");
        std::fs::write(root.join("a.txt"), "a@example.com").expect("a");
        std::fs::write(root.join("b.txt"), "b@example.com").expect("b");
        let path = directory.path().join("case.piicase");
        let options = ScanOptions {
            detect_names: false,
            ocr: false,
            workers: 2,
            ..ScanOptions::default()
        };
        let engine = json!({"test_engine":1});
        let mut store = CaseStore::create(&path, &root).expect("case");
        let (run, config) = store
            .begin_run(&root, &options, &engine)
            .expect("start run");
        let scanner = Scanner::new(options.clone()).expect("scanner");
        for name in ["a.txt", "b.txt"] {
            store.reserve_many(run, [name]).expect("reserve");
            let snapshot = store
                .start_resource(run, name, &config, None, false)
                .expect("snapshot")
                .expect("new snapshot");
            let result = scanner
                .scan(root.join(name), Arc::new(AtomicBool::new(false)))
                .expect("scan");
            store
                .record(snapshot, ScanEvent::Findings(result.findings))
                .expect("findings");
            store
                .record(snapshot, ScanEvent::Sources(result.sources))
                .expect("source");
            if name == "a.txt" {
                store
                    .finish_resource(run, snapshot, &result.summary)
                    .expect("complete a");
            }
        }
        drop(store);
        let summary = crate::scan_case(
            Scanner::new(options).expect("scanner"),
            &root,
            &path,
            crate::CaseScanOptions {
                resume: true,
                refresh: false,
                engine,
            },
            Arc::new(AtomicBool::new(false)),
        )
        .expect("resume");
        assert_eq!(
            (summary.reused, summary.completed, summary.findings),
            (1, 2, 2)
        );
        let store = CaseStore::open(&path, true).expect("reopen");
        assert_eq!(
            store.summary(Some(run)).expect("earlier run").status,
            "interrupted"
        );
        store.integrity().expect("case integrity");
    }
}
