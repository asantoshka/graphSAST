"""GraphSAST security schema migrations (v7+).

Extends the base code-review-graph schema with security-specific tables.
These are applied on top of the base v1–v6 migrations.
"""

from __future__ import annotations

import logging
import sqlite3

logger = logging.getLogger(__name__)

GRAPHSAST_SCHEMA_KEY = "graphsast_schema_version"
LATEST_VERSION = 9


def get_graphsast_version(conn: sqlite3.Connection) -> int:
    try:
        row = conn.execute(
            "SELECT value FROM metadata WHERE key = ?", (GRAPHSAST_SCHEMA_KEY,)
        ).fetchone()
        return int(row[0] if row else 0)
    except sqlite3.OperationalError:
        return 0


def _set_graphsast_version(conn: sqlite3.Connection, version: int) -> None:
    conn.execute(
        "INSERT OR REPLACE INTO metadata (key, value) VALUES (?, ?)",
        (GRAPHSAST_SCHEMA_KEY, str(version)),
    )


def _migrate_v7(conn: sqlite3.Connection) -> None:
    """v7: Add security columns to nodes, plus four new security tables."""

    # --- Extend nodes table ---
    for col, typedef in [
        ("is_entry_point", "INTEGER DEFAULT 0"),
        ("is_user_controlled", "INTEGER DEFAULT 0"),
    ]:
        try:
            conn.execute(f"ALTER TABLE nodes ADD COLUMN {col} {typedef}")
            logger.info("Migration v7: added '%s' to nodes", col)
        except sqlite3.OperationalError:
            pass  # column already exists

    # --- call_arguments: AST argument structure per sink call ---
    conn.execute("""
        CREATE TABLE IF NOT EXISTS call_arguments (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            source_qn       TEXT NOT NULL,
            target_qn       TEXT NOT NULL,
            file_path       TEXT NOT NULL,
            line            INTEGER NOT NULL,
            arg_position    INTEGER NOT NULL,
            arg_type        TEXT NOT NULL,
            is_concatenated INTEGER NOT NULL DEFAULT 0,
            is_parameterised INTEGER NOT NULL DEFAULT 0,
            contains_var    INTEGER NOT NULL DEFAULT 0,
            raw_ast_type    TEXT
        )
    """)
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_callargs_target ON call_arguments(target_qn)"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_callargs_source ON call_arguments(source_qn)"
    )

    # --- taint_annotations: SOURCE / SINK / SANITIZER tags per node ---
    conn.execute("""
        CREATE TABLE IF NOT EXISTS taint_annotations (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            node_qn         TEXT NOT NULL,
            annotation_type TEXT NOT NULL,
            vuln_class_id   TEXT,
            cwe_id          TEXT,
            source_ref      TEXT
        )
    """)
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_taint_node ON taint_annotations(node_qn)"
    )
    conn.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_taint_unique "
        "ON taint_annotations(node_qn, annotation_type, vuln_class_id)"
    )

    # --- missing_checks: absent security functions per entry point ---
    conn.execute("""
        CREATE TABLE IF NOT EXISTS missing_checks (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            entry_point_qn  TEXT NOT NULL,
            missing_type    TEXT NOT NULL,
            check_patterns  TEXT NOT NULL DEFAULT '[]'
        )
    """)
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_missing_ep ON missing_checks(entry_point_qn)"
    )

    # --- scan_runs: reproducibility metadata ---
    conn.execute("""
        CREATE TABLE IF NOT EXISTS scan_runs (
            id              TEXT PRIMARY KEY,
            timestamp       TEXT NOT NULL,
            vuln_db_hash    TEXT,
            graphsast_ver   TEXT,
            target_path     TEXT
        )
    """)

    logger.info("Migration v7: security tables created")


def _migrate_v8(conn: sqlite3.Connection) -> None:
    """v8: LLM finding tables for Phase 1A and Phase 1B."""

    # Phase 1A — autonomous LLM exploration per entry point
    conn.execute("""
        CREATE TABLE IF NOT EXISTS phase1a_findings (
            id              TEXT PRIMARY KEY,
            scan_run_id     TEXT,
            entry_point_qn  TEXT NOT NULL,
            suspected_vuln  TEXT,
            suggested_cwe   TEXT,
            affected_nodes  TEXT DEFAULT '[]',
            reasoning       TEXT,
            confidence      TEXT DEFAULT 'LOW',
            source_code_seen TEXT DEFAULT '[]',
            turns_used      INTEGER DEFAULT 0,
            model           TEXT,
            timestamp       TEXT
        )
    """)
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_p1a_ep ON phase1a_findings(entry_point_qn)"
    )

    # Phase 1B — ReAct validation of graph-identified suspect paths
    conn.execute("""
        CREATE TABLE IF NOT EXISTS phase1b_findings (
            id              TEXT PRIMARY KEY,
            scan_run_id     TEXT,
            qualified_name  TEXT NOT NULL,
            vuln_class_id   TEXT,
            suspect_path    TEXT DEFAULT '{}',
            verdict         TEXT NOT NULL,
            confidence      TEXT DEFAULT 'LOW',
            method          TEXT,
            cwe_id          TEXT,
            severity        TEXT,
            reasoning       TEXT,
            source_seen     TEXT DEFAULT '[]',
            turns_used      INTEGER DEFAULT 0,
            taint_path      TEXT,
            model           TEXT,
            timestamp       TEXT
        )
    """)
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_p1b_qn ON phase1b_findings(qualified_name)"
    )

    logger.info("Migration v8: LLM finding tables created")


def _migrate_v9(conn: sqlite3.Connection) -> None:
    """v9: Phase 1 LLM finding cache (skip re-analysis when code unchanged)."""
    conn.execute("""
        CREATE TABLE IF NOT EXISTS phase1_cache (
            cache_key   TEXT PRIMARY KEY,
            phase       TEXT NOT NULL,
            payload     TEXT NOT NULL,
            cached_at   TEXT NOT NULL
        )
    """)
    logger.info("Migration v9: phase1_cache table created")


def run_graphsast_migrations(conn: sqlite3.Connection) -> None:
    """Apply pending GraphSAST security migrations."""
    current = get_graphsast_version(conn)
    if current >= LATEST_VERSION:
        return

    logger.info("GraphSAST schema %d -> %d", current, LATEST_VERSION)

    if current < 7:
        conn.execute("BEGIN IMMEDIATE")
        try:
            _migrate_v7(conn)
            _set_graphsast_version(conn, 7)
            conn.commit()
        except BaseException:
            conn.rollback()
            raise

    if current < 8:
        conn.execute("BEGIN IMMEDIATE")
        try:
            _migrate_v8(conn)
            _set_graphsast_version(conn, 8)
            conn.commit()
        except BaseException:
            conn.rollback()
            raise

    if current < 9:
        conn.execute("BEGIN IMMEDIATE")
        try:
            _migrate_v9(conn)
            _set_graphsast_version(conn, 9)
            conn.commit()
        except BaseException:
            conn.rollback()
            raise
