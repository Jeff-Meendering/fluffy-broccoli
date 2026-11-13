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
    relation TEXT
) STRICT;
CREATE INDEX records_document ON records(document_id);

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
