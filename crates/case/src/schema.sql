CREATE TABLE meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE runs(id INTEGER PRIMARY KEY, started INTEGER NOT NULL, finished INTEGER,
 status TEXT NOT NULL, config_hash TEXT NOT NULL, options_json TEXT NOT NULL, engine_json TEXT NOT NULL, elapsed_ms INTEGER NOT NULL DEFAULT 0);
CREATE TABLE snapshots(id INTEGER PRIMARY KEY, resource_id TEXT NOT NULL, config_hash TEXT NOT NULL,
 source_sha256 TEXT, source_json TEXT, finished INTEGER NOT NULL DEFAULT 0, cancelled INTEGER NOT NULL DEFAULT 0);
CREATE INDEX snapshot_cache ON snapshots(resource_id,config_hash,source_sha256,finished,cancelled);
CREATE TABLE run_resources(run_id INTEGER NOT NULL REFERENCES runs(id), resource_id TEXT NOT NULL,
 snapshot_id INTEGER REFERENCES snapshots(id), status TEXT NOT NULL, reused INTEGER NOT NULL DEFAULT 0, PRIMARY KEY(run_id,resource_id));
CREATE INDEX resource_snapshot ON run_resources(snapshot_id,run_id);
CREATE TABLE findings(id INTEGER PRIMARY KEY, snapshot_id INTEGER NOT NULL REFERENCES snapshots(id),
 occurrence_key TEXT NOT NULL, type TEXT NOT NULL, value_sha256 TEXT NOT NULL, confidence REAL NOT NULL,
 payload TEXT NOT NULL, payload_sha256 TEXT NOT NULL, UNIQUE(snapshot_id,occurrence_key));
CREATE INDEX finding_type ON findings(type,snapshot_id,id);
CREATE TABLE attention(id INTEGER PRIMARY KEY, snapshot_id INTEGER NOT NULL REFERENCES snapshots(id),payload TEXT NOT NULL);
CREATE INDEX attention_snapshot ON attention(snapshot_id);
CREATE TABLE run_attention(id INTEGER PRIMARY KEY,run_id INTEGER NOT NULL REFERENCES runs(id),payload TEXT NOT NULL);
CREATE TABLE reviews(finding_id INTEGER PRIMARY KEY REFERENCES findings(id),status TEXT NOT NULL,
 note TEXT NOT NULL,reviewer TEXT NOT NULL,updated INTEGER NOT NULL);
CREATE TABLE audit(id INTEGER PRIMARY KEY,kind TEXT NOT NULL,finding_id INTEGER REFERENCES findings(id),previous_sha256 TEXT NOT NULL,event_json TEXT NOT NULL,sha256 TEXT NOT NULL);
CREATE INDEX audit_review ON audit(kind,finding_id,id);
