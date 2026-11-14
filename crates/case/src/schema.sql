CREATE TABLE meta(
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
) STRICT;

CREATE TABLE documents(
    id INTEGER PRIMARY KEY,
    path TEXT NOT NULL UNIQUE,
    sha256 TEXT,
    bytes INTEGER NOT NULL,
    engine TEXT NOT NULL,
    status TEXT NOT NULL,
    last_seen_run INTEGER NOT NULL
) STRICT;

CREATE TABLE records(
    id INTEGER PRIMARY KEY,
    document_id INTEGER NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
    scope TEXT,
    row INTEGER NOT NULL,
    -- What `row` counts: 'row' of a table or 'line' of text.
    unit TEXT NOT NULL,
    relation TEXT,
    -- Identifies this record by where it came from and the exact bytes of its file,
    -- so a reviewer's rulings survive re-ingest but not a change to the evidence.
    fingerprint TEXT NOT NULL
) STRICT;
CREATE INDEX records_document ON records(document_id);
CREATE INDEX records_fingerprint ON records(fingerprint);

CREATE TABLE observations(
    id INTEGER PRIMARY KEY,
    record_id INTEGER NOT NULL REFERENCES records(id) ON DELETE CASCADE,
    kind TEXT NOT NULL,
    raw TEXT NOT NULL,
    normalized TEXT NOT NULL,
    valid INTEGER NOT NULL,
    col INTEGER NOT NULL,
    header TEXT,
    method TEXT NOT NULL
) STRICT;
CREATE INDEX observations_record ON observations(record_id);

CREATE TABLE gaps(
    id INTEGER PRIMARY KEY,
    document_id INTEGER REFERENCES documents(id) ON DELETE CASCADE,
    path TEXT NOT NULL,
    scope TEXT,
    kind TEXT NOT NULL,
    detail TEXT NOT NULL
) STRICT;
CREATE INDEX gaps_document ON gaps(document_id);

-- Which person each record belongs to. Rebuilt whenever the case is resolved; a
-- person is identified by the smallest record identifier in its group.
CREATE TABLE membership(
    record_id INTEGER PRIMARY KEY REFERENCES records(id) ON DELETE CASCADE,
    person_id INTEGER NOT NULL
) STRICT;
CREATE INDEX membership_person ON membership(person_id);

-- Why records were merged into one person. Rebuilt with membership.
CREATE TABLE links(
    id INTEGER PRIMARY KEY,
    record_a INTEGER NOT NULL,
    record_b INTEGER NOT NULL,
    reason TEXT NOT NULL
) STRICT;

-- Pairs of records that may be one person: open questions for a reviewer.
CREATE TABLE suggestions(
    id INTEGER PRIMARY KEY,
    record_a INTEGER NOT NULL,
    record_b INTEGER NOT NULL,
    score INTEGER NOT NULL,
    reason TEXT NOT NULL
) STRICT;

-- A reviewer's rulings. Keyed by record fingerprints, not identifiers, so they
-- outlive re-ingest. `verdict` is 'same' or 'different'.
CREATE TABLE decisions(
    id INTEGER PRIMARY KEY,
    fingerprint_a TEXT NOT NULL,
    fingerprint_b TEXT NOT NULL,
    verdict TEXT NOT NULL,
    reviewer TEXT NOT NULL,
    note TEXT NOT NULL,
    decided_at INTEGER NOT NULL,
    UNIQUE(fingerprint_a, fingerprint_b)
) STRICT;

-- Append-only history. Each entry's hash covers the previous entry's hash, so an
-- altered or removed entry breaks the chain from that point on.
CREATE TABLE audit(
    id INTEGER PRIMARY KEY,
    at INTEGER NOT NULL,
    kind TEXT NOT NULL,
    detail TEXT NOT NULL,
    previous TEXT NOT NULL,
    hash TEXT NOT NULL
) STRICT;
