//! People: resolving records into persons, a reviewer's rulings, and the audit log.

use std::collections::HashMap;

use anyhow::{Context, Result, bail};
use rollcall_resolve::{Constraint, Profile, resolve};
use rusqlite::{OptionalExtension, params};

use crate::store::{Case, audit_hash, now, single_line};

/// The state of a case after its records were grouped into persons.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ResolveSummary {
    pub persons: u64,
    /// Open questions for a reviewer.
    pub suggestions: u64,
    /// Rulings about records that are no longer in the case, because their file
    /// changed or was removed. They are kept, and apply again if the file returns.
    pub inactive_decisions: u64,
}

/// A pair of records that may be one person.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredSuggestion {
    pub id: i64,
    pub record_a: i64,
    pub record_b: i64,
    pub person_a: i64,
    pub person_b: i64,
    /// 0 to 100; higher is more likely the same person.
    pub score: u8,
    pub reason: String,
}

/// Why two records were merged into one person.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredLink {
    pub record_a: i64,
    pub record_b: i64,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredDecision {
    pub id: i64,
    /// True for "the same person", false for "different people".
    pub same: bool,
    pub reviewer: String,
    pub note: String,
    /// Seconds since 1970-01-01 UTC.
    pub decided_at: i64,
    /// The two records ruled on, or `None` when they are no longer in the case.
    pub records: Option<(i64, i64)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditEntry {
    pub id: i64,
    /// Seconds since 1970-01-01 UTC.
    pub at: i64,
    pub kind: String,
    pub detail: String,
    pub hash: String,
}

/// The result of re-computing the audit log's hash chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditCheck {
    pub entries: u64,
    /// The first entry that does not follow from the one before it, if any.
    pub broken_at: Option<i64>,
    /// Hash of the last entry. Recorded somewhere outside the case, it also shows
    /// whether entries were later removed from the end of the log.
    pub head: String,
}

impl Case {
    /// Groups the case's records into persons, applying every ruling on record.
    pub fn resolve(&mut self) -> Result<ResolveSummary> {
        let mut profiles = Vec::new();
        let mut by_fingerprint: HashMap<String, i64> = HashMap::new();
        self.for_each_record(|record| {
            let values = record
                .observations
                .iter()
                .filter(|observation| observation.valid)
                .map(|observation| (observation.kind, observation.normalized.as_str()));
            profiles.push(Profile::new(record.id, values));
            by_fingerprint.insert(record.fingerprint, record.id);
            Ok(())
        })?;

        let mut summary = ResolveSummary::default();
        let mut constraints = Vec::new();
        {
            let mut statement = self.connection.prepare(
                "SELECT fingerprint_a, fingerprint_b, verdict FROM decisions ORDER BY id",
            )?;
            let mut rows = statement.query([])?;
            while let Some(row) = rows.next()? {
                let (a, b, verdict): (String, String, String) =
                    (row.get(0)?, row.get(1)?, row.get(2)?);
                match (by_fingerprint.get(&a), by_fingerprint.get(&b)) {
                    (Some(&a), Some(&b)) => constraints.push(Constraint {
                        a,
                        b,
                        same: verdict == "same",
                    }),
                    _ => summary.inactive_decisions += 1,
                }
            }
        }

        let resolution = resolve(&profiles, &constraints);
        let transaction = self.connection.transaction()?;
        transaction
            .execute_batch("DELETE FROM membership; DELETE FROM links; DELETE FROM suggestions;")?;
        {
            let mut member = transaction
                .prepare("INSERT INTO membership(record_id, person_id) VALUES(?1, ?2)")?;
            for records in &resolution.persons {
                for record in records {
                    member.execute(params![record, records[0]])?;
                }
            }
            let mut link = transaction
                .prepare("INSERT INTO links(record_a, record_b, reason) VALUES(?1, ?2, ?3)")?;
            for found in &resolution.links {
                link.execute(params![found.a, found.b, found.reason.describe()])?;
            }
            let mut suggestion = transaction.prepare(
                "INSERT INTO suggestions(record_a, record_b, score, reason) VALUES(?1, ?2, ?3, ?4)",
            )?;
            for found in &resolution.suggestions {
                suggestion.execute(params![
                    found.a,
                    found.b,
                    found.score,
                    found.reason.describe()
                ])?;
            }
        }
        transaction.commit()?;
        summary.persons = resolution.persons.len() as u64;
        summary.suggestions = resolution.suggestions.len() as u64;
        Ok(summary)
    }

    /// Open questions, most likely matches first.
    pub fn suggestions(&self) -> Result<Vec<StoredSuggestion>> {
        let mut statement = self.connection.prepare(
            "SELECT s.id, s.record_a, s.record_b, a.person_id, b.person_id, s.score, s.reason
             FROM suggestions s
             JOIN membership a ON a.record_id = s.record_a
             JOIN membership b ON b.record_id = s.record_b
             ORDER BY s.score DESC, s.id",
        )?;
        let rows = statement.query_map([], |row| {
            Ok(StoredSuggestion {
                id: row.get(0)?,
                record_a: row.get(1)?,
                record_b: row.get(2)?,
                person_a: row.get(3)?,
                person_b: row.get(4)?,
                score: row.get(5)?,
                reason: row.get(6)?,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    /// The merges that made up one person.
    pub fn links_of(&self, person: i64) -> Result<Vec<StoredLink>> {
        let mut statement = self.connection.prepare(
            "SELECT l.record_a, l.record_b, l.reason FROM links l
             JOIN membership m ON m.record_id = l.record_a
             WHERE m.person_id = ?1 ORDER BY l.id",
        )?;
        let rows = statement.query_map(params![person], |row| {
            Ok(StoredLink {
                record_a: row.get(0)?,
                record_b: row.get(1)?,
                reason: row.get(2)?,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    /// Records a ruling that two records are, or are not, the same person, then
    /// resolves the case again. A later ruling on the same pair replaces the earlier.
    pub fn decide(
        &mut self,
        a: i64,
        b: i64,
        same: bool,
        reviewer: &str,
        note: &str,
    ) -> Result<ResolveSummary> {
        if a == b {
            bail!("a ruling needs two different records");
        }
        let fingerprint = |record: i64| -> Result<String> {
            self.connection
                .query_row(
                    "SELECT fingerprint FROM records WHERE id = ?1",
                    params![record],
                    |row| row.get(0),
                )
                .optional()?
                .with_context(|| format!("there is no record {record} in this case"))
        };
        let (mut first, mut second) = (fingerprint(a)?, fingerprint(b)?);
        if first > second {
            std::mem::swap(&mut first, &mut second);
        }
        let (reviewer, note) = (single_line(reviewer), single_line(note));
        let verdict = if same { "same" } else { "different" };
        self.connection.execute(
            "INSERT INTO decisions(fingerprint_a, fingerprint_b, verdict, reviewer, note, decided_at)
             VALUES(?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(fingerprint_a, fingerprint_b) DO UPDATE SET
                 verdict = excluded.verdict, reviewer = excluded.reviewer,
                 note = excluded.note, decided_at = excluded.decided_at",
            params![first, second, verdict, reviewer, note, now()],
        )?;
        let ruling = if same {
            "the same person"
        } else {
            "different people"
        };
        self.append_audit(
            "decision",
            &format!(
                "{reviewer} ruled records {a} and {b} {ruling}. Note: {}. Fingerprints {first} and {second}.",
                if note.is_empty() { "none" } else { &note }
            ),
        )?;
        self.resolve()
    }

    /// Rules on an open suggestion: accept it (`same`) or reject it.
    pub fn decide_suggestion(
        &mut self,
        suggestion: i64,
        same: bool,
        reviewer: &str,
        note: &str,
    ) -> Result<ResolveSummary> {
        let pair: Option<(i64, i64)> = self
            .connection
            .query_row(
                "SELECT record_a, record_b FROM suggestions WHERE id = ?1",
                params![suggestion],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        let (a, b) = pair.with_context(|| {
            format!(
                "there is no open suggestion {suggestion}; list them with `rollcall review list`"
            )
        })?;
        self.decide(a, b, same, reviewer, note)
    }

    /// Withdraws a ruling, then resolves the case again.
    pub fn undo_decision(&mut self, decision: i64, reviewer: &str) -> Result<ResolveSummary> {
        let removed = self
            .connection
            .execute("DELETE FROM decisions WHERE id = ?1", params![decision])?;
        if removed == 0 {
            bail!("there is no ruling {decision}; list them with `rollcall review rulings`");
        }
        self.append_audit(
            "undo",
            &format!("{} withdrew ruling {decision}.", single_line(reviewer)),
        )?;
        self.resolve()
    }

    pub fn decisions(&self) -> Result<Vec<StoredDecision>> {
        let mut statement = self.connection.prepare(
            "SELECT d.id, d.verdict, d.reviewer, d.note, d.decided_at,
                    (SELECT MIN(id) FROM records WHERE fingerprint = d.fingerprint_a),
                    (SELECT MIN(id) FROM records WHERE fingerprint = d.fingerprint_b)
             FROM decisions d ORDER BY d.id",
        )?;
        let rows = statement.query_map([], |row| {
            let verdict: String = row.get(1)?;
            let (a, b): (Option<i64>, Option<i64>) = (row.get(5)?, row.get(6)?);
            Ok(StoredDecision {
                id: row.get(0)?,
                same: verdict == "same",
                reviewer: row.get(2)?,
                note: row.get(3)?,
                decided_at: row.get(4)?,
                records: a.zip(b).map(|(a, b)| (a.min(b), a.max(b))),
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }

    /// Notes in the audit log that a list was written, with the hash of its bytes.
    pub fn record_export(&self, description: &str) -> Result<()> {
        self.append_audit("export", description)
    }

    pub fn audit_log(&self) -> Result<Vec<AuditEntry>> {
        Ok(self
            .audit_rows()?
            .into_iter()
            .map(|(entry, _)| entry)
            .collect())
    }

    /// Re-computes the hash chain of the audit log.
    ///
    /// A broken chain shows that an entry was altered, inserted or removed. An intact
    /// chain does not prove the log is authentic: someone able to rewrite the case
    /// file can rebuild the chain. Keep a copy of the head hash elsewhere.
    pub fn verify_audit(&self) -> Result<AuditCheck> {
        let rows = self.audit_rows()?;
        let mut check = AuditCheck {
            entries: rows.len() as u64,
            broken_at: None,
            head: String::new(),
        };
        // Entries are numbered from one without gaps; a missing number is a removed entry.
        for (expected_id, (entry, previous)) in (1_i64..).zip(rows) {
            let follows = entry.id == expected_id
                && previous == check.head
                && entry.hash == audit_hash(&previous, entry.at, &entry.kind, &entry.detail);
            if !follows {
                check.broken_at = Some(entry.id);
                break;
            }
            check.head = entry.hash;
        }
        Ok(check)
    }

    fn audit_rows(&self) -> Result<Vec<(AuditEntry, String)>> {
        let mut statement = self
            .connection
            .prepare("SELECT id, at, kind, detail, hash, previous FROM audit ORDER BY id")?;
        let rows = statement.query_map([], |row| {
            Ok((
                AuditEntry {
                    id: row.get(0)?,
                    at: row.get(1)?,
                    kind: row.get(2)?,
                    detail: row.get(3)?,
                    hash: row.get(4)?,
                },
                row.get(5)?,
            ))
        })?;
        Ok(rows.collect::<rusqlite::Result<_>>()?)
    }
}
