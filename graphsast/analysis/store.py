"""Persistent findings store.

All findings from every scan run are stored in a `findings` table inside
graph.db.  Scan runs are tracked in `scan_runs`.  A join table
`run_findings` links findings to the runs that saw them.

Key design decisions
────────────────────
Fingerprint = sha256(rule_id + file_path + line_start)
  • Model-independent identity — same bug at same location = same row.
  • Changing the model doesn't invalidate existing verdicts.

Staleness = file_hash mismatch
  • At LLM analysis time, the file's SHA-256 is stored.
  • On the next scan, if the current file hash differs, the verdict is
    considered stale and the LLM re-analyses the finding.
  • Unchanged file + existing verdict → no LLM call.

Run comparison
  • new     — in current run but not in the previous run
  • fixed   — in previous run but not in current run (Semgrep no longer flags)
  • recurring — in both runs
"""

from __future__ import annotations

import hashlib
import logging
import sqlite3
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

_DDL = """
CREATE TABLE IF NOT EXISTS scan_runs (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at      TEXT    NOT NULL DEFAULT (datetime('now')),
    finished_at     TEXT,
    target          TEXT    NOT NULL,
    semgrep_config  TEXT    NOT NULL DEFAULT 'auto',
    model           TEXT,
    semgrep_total   INTEGER DEFAULT 0,
    deduplicated    INTEGER DEFAULT 0,
    new_findings    INTEGER DEFAULT 0,
    recurring       INTEGER DEFAULT 0,
    cache_hits      INTEGER DEFAULT 0,
    llm_analysed    INTEGER DEFAULT 0,
    confirmed       INTEGER DEFAULT 0,
    false_positives INTEGER DEFAULT 0,
    needs_review    INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS findings (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    fingerprint   TEXT    NOT NULL UNIQUE,
    rule_id       TEXT    NOT NULL,
    title         TEXT    NOT NULL,
    message       TEXT    NOT NULL DEFAULT '',
    severity      TEXT    NOT NULL,
    file_path     TEXT    NOT NULL,
    line_start    INTEGER NOT NULL,
    line_end      INTEGER NOT NULL DEFAULT 0,
    cwe_id        TEXT    NOT NULL DEFAULT '',
    snippet       TEXT    NOT NULL DEFAULT '',
    llm_verdict      TEXT,
    llm_severity     TEXT,
    llm_reasoning    TEXT,
    llm_description  TEXT,
    llm_poc          TEXT,
    llm_cvss_score   REAL,
    llm_cvss_vector  TEXT,
    llm_model        TEXT,
    analysed_at   TEXT,
    file_hash     TEXT,
    first_seen_at TEXT    NOT NULL DEFAULT (datetime('now')),
    last_seen_at  TEXT    NOT NULL DEFAULT (datetime('now')),
    first_run_id  INTEGER,
    last_run_id   INTEGER,
    status        TEXT    NOT NULL DEFAULT 'open',
    source        TEXT    NOT NULL DEFAULT 'semgrep'
);

CREATE TABLE IF NOT EXISTS run_findings (
    run_id     INTEGER NOT NULL,
    finding_id INTEGER NOT NULL,
    PRIMARY KEY (run_id, finding_id)
);

CREATE INDEX IF NOT EXISTS idx_findings_fingerprint ON findings(fingerprint);
CREATE INDEX IF NOT EXISTS idx_findings_file        ON findings(file_path);
CREATE INDEX IF NOT EXISTS idx_run_findings_run     ON run_findings(run_id);
"""


class FindingStore:
    """Read/write interface to the persistent findings tables in graph.db."""

    def __init__(self, db_path: Path) -> None:
        self._conn = sqlite3.connect(str(db_path))
        self._conn.row_factory = sqlite3.Row
        self._ensure_schema()

    # ── Run lifecycle ──────────────────────────────────────────────────────────

    def start_run(self, target: str, semgrep_config: str, model: Optional[str]) -> int:
        """Insert a new scan_run row and return its id."""
        cur = self._conn.execute(
            "INSERT INTO scan_runs (target, semgrep_config, model) VALUES (?,?,?)",
            (str(target), semgrep_config, model),
        )
        self._conn.commit()
        return cur.lastrowid  # type: ignore[return-value]

    def finish_run(self, run_id: int, summary: dict) -> None:
        """Fill in counters and finished_at for a completed run."""
        self._conn.execute(
            """UPDATE scan_runs SET
                   finished_at     = datetime('now'),
                   semgrep_total   = ?,
                   deduplicated    = ?,
                   new_findings    = ?,
                   recurring       = ?,
                   cache_hits      = ?,
                   llm_analysed    = ?,
                   confirmed       = ?,
                   false_positives = ?,
                   needs_review    = ?
               WHERE id = ?""",
            (
                summary.get("semgrep_findings", 0),
                summary.get("deduplicated", 0),
                summary.get("new_findings", 0),
                summary.get("recurring", 0),
                summary.get("cache_hits", 0),
                summary.get("llm_analysed", 0),
                summary.get("confirmed", 0),
                summary.get("false_positives", 0),
                summary.get("needs_review", 0),
                run_id,
            ),
        )
        self._conn.commit()

    # ── Finding upsert ─────────────────────────────────────────────────────────

    def upsert_finding(
        self,
        f: "Finding",  # type: ignore[name-defined]
        run_id: int,
        source: str = "semgrep",
    ) -> tuple[int, bool]:
        """Insert or update a finding.  Link it to *run_id*.

        Returns (finding_id, is_new).
        """
        fingerprint = self.make_fingerprint(f.rule_id, f.file_path, f.line_start)
        existing = self._conn.execute(
            "SELECT id FROM findings WHERE fingerprint = ?", (fingerprint,)
        ).fetchone()

        if existing:
            finding_id: int = existing["id"]
            is_new = False
            self._conn.execute(
                """UPDATE findings
                   SET last_seen_at     = datetime('now'),
                       last_run_id      = ?,
                       snippet          = ?
                   WHERE id = ?""",
                (run_id, f.snippet, finding_id),
            )
            # Persist new LLM enrichment fields if present on this Finding
            if f.llm_verdict is not None:
                fhash = self._file_hash(f.file_path)
                self._conn.execute(
                    """UPDATE findings
                       SET llm_verdict     = ?,
                           llm_severity    = ?,
                           llm_reasoning   = ?,
                           llm_description = ?,
                           llm_poc         = ?,
                           llm_cvss_score  = ?,
                           llm_cvss_vector = ?,
                           analysed_at     = datetime('now'),
                           file_hash       = ?
                       WHERE id = ?""",
                    (
                        f.llm_verdict, f.llm_severity, f.llm_reasoning,
                        f.llm_description, f.llm_poc,
                        f.llm_cvss_score, f.llm_cvss_vector,
                        fhash, finding_id,
                    ),
                )
        else:
            is_new = True
            cur = self._conn.execute(
                """INSERT INTO findings
                       (fingerprint, rule_id, title, message, severity,
                        file_path, line_start, line_end, cwe_id, snippet,
                        llm_verdict, llm_severity, llm_reasoning,
                        llm_description, llm_poc, llm_cvss_score, llm_cvss_vector,
                        first_run_id, last_run_id, source)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    fingerprint, f.rule_id, f.title, f.message, f.severity,
                    f.file_path, f.line_start, f.line_end, f.cwe_id, f.snippet,
                    f.llm_verdict, f.llm_severity, f.llm_reasoning,
                    f.llm_description, f.llm_poc, f.llm_cvss_score, f.llm_cvss_vector,
                    run_id, run_id, source,
                ),
            )
            finding_id = cur.lastrowid  # type: ignore[assignment]

        self._conn.execute(
            "INSERT OR IGNORE INTO run_findings (run_id, finding_id) VALUES (?,?)",
            (run_id, finding_id),
        )
        self._conn.commit()
        return finding_id, is_new

    # ── Verdict cache ──────────────────────────────────────────────────────────

    def get_verdict(self, rule_id: str, file_path: str, line_start: int) -> Optional[dict]:
        """Return a stored verdict if the source file hasn't changed, else None."""
        fingerprint = self.make_fingerprint(rule_id, file_path, line_start)
        row = self._conn.execute(
            """SELECT llm_verdict, llm_severity, llm_reasoning,
                      llm_description, llm_poc, llm_cvss_score, llm_cvss_vector,
                      file_hash
               FROM findings
               WHERE fingerprint = ? AND llm_verdict IS NOT NULL""",
            (fingerprint,),
        ).fetchone()
        if row is None:
            return None
        current_hash = self._file_hash(file_path)
        if row["file_hash"] and row["file_hash"] != current_hash:
            logger.debug("Stale verdict for %s:%s (file changed)", file_path, line_start)
            return None
        return {
            "verdict":     row["llm_verdict"],
            "severity":    row["llm_severity"],
            "reasoning":   row["llm_reasoning"],
            "description": row["llm_description"],
            "poc":         row["llm_poc"],
            "cvss_score":  row["llm_cvss_score"],
            "cvss_vector": row["llm_cvss_vector"],
        }

    def set_verdict(
        self,
        rule_id: str,
        file_path: str,
        line_start: int,
        verdict: dict,
        model: str,
    ) -> None:
        """Persist an LLM verdict for a finding."""
        fingerprint = self.make_fingerprint(rule_id, file_path, line_start)
        fhash = self._file_hash(file_path)
        self._conn.execute(
            """UPDATE findings
               SET llm_verdict      = ?,
                   llm_severity     = ?,
                   llm_reasoning    = ?,
                   llm_description  = ?,
                   llm_poc          = ?,
                   llm_cvss_score   = ?,
                   llm_cvss_vector  = ?,
                   llm_model        = ?,
                   analysed_at      = datetime('now'),
                   file_hash        = ?
               WHERE fingerprint = ?""",
            (
                verdict["verdict"], verdict["severity"], verdict["reasoning"],
                verdict.get("description"), verdict.get("poc"),
                verdict.get("cvss_score"), verdict.get("cvss_vector"),
                model, fhash, fingerprint,
            ),
        )
        self._conn.commit()

    # ── Querying ───────────────────────────────────────────────────────────────

    def get_run_findings(self, run_id: int) -> list[dict]:
        """All findings seen in *run_id*, ordered by severity then location."""
        rows = self._conn.execute(
            """SELECT f.*
               FROM findings f
               JOIN run_findings rf ON rf.finding_id = f.id
               WHERE rf.run_id = ?
               ORDER BY
                   CASE f.severity
                       WHEN 'CRITICAL' THEN 1
                       WHEN 'HIGH'     THEN 2
                       WHEN 'MEDIUM'   THEN 3
                       WHEN 'LOW'      THEN 4
                       ELSE 5
                   END,
                   f.file_path, f.line_start""",
            (run_id,),
        ).fetchall()
        return [dict(r) for r in rows]

    def compare_with_previous(self, run_id: int) -> dict:
        """Diff *run_id* against the immediately preceding run.

        Returns::

            {
                "new":       [...],   # first time seen
                "fixed":     [...],   # in prev run, gone now
                "recurring": [...],   # in both runs
                "prev_run_id": int | None,
            }
        """
        prev = self._conn.execute(
            "SELECT id FROM scan_runs WHERE id < ? ORDER BY id DESC LIMIT 1",
            (run_id,),
        ).fetchone()

        current_ids = self._run_finding_ids(run_id)

        if prev is None:
            return {
                "new":        self._fetch_by_ids(current_ids),
                "fixed":      [],
                "recurring":  [],
                "prev_run_id": None,
            }

        prev_id = prev["id"]
        prev_ids = self._run_finding_ids(prev_id)

        return {
            "new":        self._fetch_by_ids(current_ids - prev_ids),
            "fixed":      self._fetch_by_ids(prev_ids - current_ids),
            "recurring":  self._fetch_by_ids(current_ids & prev_ids),
            "prev_run_id": prev_id,
        }

    def get_all_findings(self, source: Optional[str] = None) -> list[dict]:
        """All findings in the DB, optionally filtered by source ('semgrep'|'hunter').

        Ordered by severity then location. Use this for a combined view across
        all runs rather than a single-run snapshot.
        """
        if source:
            rows = self._conn.execute(
                """SELECT * FROM findings
                   WHERE source = ?
                   ORDER BY
                       CASE severity
                           WHEN 'CRITICAL' THEN 1
                           WHEN 'HIGH'     THEN 2
                           WHEN 'MEDIUM'   THEN 3
                           WHEN 'LOW'      THEN 4
                           ELSE 5
                       END,
                       file_path, line_start""",
                (source,),
            ).fetchall()
        else:
            rows = self._conn.execute(
                """SELECT * FROM findings
                   ORDER BY
                       CASE severity
                           WHEN 'CRITICAL' THEN 1
                           WHEN 'HIGH'     THEN 2
                           WHEN 'MEDIUM'   THEN 3
                           WHEN 'LOW'      THEN 4
                           ELSE 5
                       END,
                       file_path, line_start""",
            ).fetchall()
        return [dict(r) for r in rows]

    def list_runs(self) -> list[dict]:
        """All scan runs, newest first."""
        rows = self._conn.execute(
            "SELECT * FROM scan_runs ORDER BY id DESC"
        ).fetchall()
        return [dict(r) for r in rows]

    def get_run(self, run_id: int) -> Optional[dict]:
        row = self._conn.execute(
            "SELECT * FROM scan_runs WHERE id = ?", (run_id,)
        ).fetchone()
        return dict(row) if row else None

    # ── Helpers ────────────────────────────────────────────────────────────────

    @staticmethod
    def make_fingerprint(rule_id: str, file_path: str, line_start: int) -> str:
        raw = f"{rule_id}:{file_path}:{line_start}"
        return hashlib.sha256(raw.encode()).hexdigest()

    @staticmethod
    def _file_hash(file_path: str) -> str:
        try:
            return hashlib.sha256(Path(file_path).read_bytes()).hexdigest()[:16]
        except OSError:
            return "missing"

    def _run_finding_ids(self, run_id: int) -> set[int]:
        rows = self._conn.execute(
            "SELECT finding_id FROM run_findings WHERE run_id = ?", (run_id,)
        ).fetchall()
        return {r["finding_id"] for r in rows}

    def _fetch_by_ids(self, ids: set[int]) -> list[dict]:
        if not ids:
            return []
        placeholders = ",".join("?" * len(ids))
        rows = self._conn.execute(
            f"SELECT * FROM findings WHERE id IN ({placeholders})",  # nosec B608
            list(ids),
        ).fetchall()
        return [dict(r) for r in rows]

    def _ensure_schema(self) -> None:
        for stmt in _DDL.strip().split(";"):
            stmt = stmt.strip()
            if stmt:
                self._conn.execute(stmt)
        self._conn.commit()
        self._migrate()

    def _migrate(self) -> None:
        """Add columns that were introduced after initial schema creation."""
        # Each entry: (table, column, definition)
        migrations = [
            ("scan_runs", "target",          "TEXT NOT NULL DEFAULT ''"),
            ("scan_runs", "semgrep_config",  "TEXT NOT NULL DEFAULT 'auto'"),
            ("scan_runs", "deduplicated",    "INTEGER DEFAULT 0"),
            ("scan_runs", "cache_hits",      "INTEGER DEFAULT 0"),
            ("scan_runs", "llm_analysed",    "INTEGER DEFAULT 0"),
            ("scan_runs", "confirmed",       "INTEGER DEFAULT 0"),
            ("scan_runs", "false_positives", "INTEGER DEFAULT 0"),
            ("scan_runs", "needs_review",    "INTEGER DEFAULT 0"),
            ("findings",  "cwe_id",          "TEXT NOT NULL DEFAULT ''"),
            ("findings",  "snippet",         "TEXT NOT NULL DEFAULT ''"),
            ("findings",  "llm_model",       "TEXT"),
            ("findings",  "analysed_at",     "TEXT"),
            ("findings",  "file_hash",       "TEXT"),
            ("findings",  "first_run_id",    "INTEGER"),
            ("findings",  "last_run_id",     "INTEGER"),
            ("findings",  "status",           "TEXT NOT NULL DEFAULT 'open'"),
            ("findings",  "source",            "TEXT NOT NULL DEFAULT 'semgrep'"),
            ("findings",  "llm_description",   "TEXT"),
            ("findings",  "llm_poc",           "TEXT"),
            ("findings",  "llm_cvss_score",    "REAL"),
            ("findings",  "llm_cvss_vector",   "TEXT"),
        ]
        existing: dict[str, set[str]] = {}
        for table, col, defn in migrations:
            if table not in existing:
                rows = self._conn.execute(f"PRAGMA table_info({table})").fetchall()
                existing[table] = {r["name"] for r in rows}
            if col not in existing[table]:
                self._conn.execute(f"ALTER TABLE {table} ADD COLUMN {col} {defn}")
                existing[table].add(col)
                logger.debug("Migrated: added %s.%s", table, col)
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> "FindingStore":
        return self

    def __exit__(self, *_) -> None:
        self.close()
