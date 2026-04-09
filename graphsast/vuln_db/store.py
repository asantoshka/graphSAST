"""VulnStore — SQLite adapter for vulns.db."""

from __future__ import annotations

import json
import logging
import sqlite3
from pathlib import Path
from typing import Any

from .schema import SCHEMA_SQL

logger = logging.getLogger(__name__)


class VulnStore:
    """Read/write interface for the vulnerability pattern database (vulns.db)."""

    def __init__(self, db_path: str | Path) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._init_schema()

    def _init_schema(self) -> None:
        self._conn.executescript(SCHEMA_SQL)
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> "VulnStore":
        return self

    def __exit__(self, *_) -> None:
        self.close()

    # ------------------------------------------------------------------
    # vuln_classes
    # ------------------------------------------------------------------

    def upsert_vuln_class(self, vc: dict[str, Any]) -> None:
        self._conn.execute(
            """INSERT OR REPLACE INTO vuln_classes
               (id, cwe_id, owasp_cat, name, description, severity, language, source)
               VALUES (:id, :cwe_id, :owasp_cat, :name, :description, :severity, :language, :source)""",
            {
                "id": vc["id"],
                "cwe_id": vc.get("cwe_id", ""),
                "owasp_cat": vc.get("owasp_cat", ""),
                "name": vc["name"],
                "description": vc.get("description", ""),
                "severity": vc.get("severity", "MEDIUM"),
                "language": vc.get("language", "any"),
                "source": vc.get("source", "custom"),
            },
        )

    def get_vuln_class(self, vc_id: str) -> dict | None:
        row = self._conn.execute(
            "SELECT * FROM vuln_classes WHERE id = ?", (vc_id,)
        ).fetchone()
        return dict(row) if row else None

    def get_all_vuln_classes(self) -> list[dict]:
        rows = self._conn.execute("SELECT * FROM vuln_classes").fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # detectors
    # ------------------------------------------------------------------

    def upsert_detector(self, det: dict[str, Any]) -> None:
        self._conn.execute(
            """INSERT OR REPLACE INTO detectors
               (id, vuln_class_id, detector_type, content, language, confidence)
               VALUES (:id, :vuln_class_id, :detector_type, :content, :language, :confidence)""",
            {
                "id": det["id"],
                "vuln_class_id": det["vuln_class_id"],
                "detector_type": det.get("detector_type", "taint_signature"),
                "content": det.get("content", ""),
                "language": det.get("language", "any"),
                "confidence": det.get("confidence", "MEDIUM"),
            },
        )

    def get_detectors_for_class(self, vuln_class_id: str) -> list[dict]:
        rows = self._conn.execute(
            "SELECT * FROM detectors WHERE vuln_class_id = ?", (vuln_class_id,)
        ).fetchall()
        return [dict(r) for r in rows]

    def get_detectors_by_type(self, detector_type: str) -> list[dict]:
        rows = self._conn.execute(
            "SELECT * FROM detectors WHERE detector_type = ?", (detector_type,)
        ).fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # taint_signatures
    # ------------------------------------------------------------------

    def upsert_taint_signature(self, sig: dict[str, Any]) -> None:
        cwe_ids = sig.get("cwe_ids", [])
        if isinstance(cwe_ids, list):
            cwe_ids = json.dumps(cwe_ids)
        self._conn.execute(
            """INSERT OR REPLACE INTO taint_signatures
               (id, name, qualified_pattern, language, sig_type,
                cwe_ids, vuln_class_id, description, source)
               VALUES (:id, :name, :qualified_pattern, :language, :sig_type,
                       :cwe_ids, :vuln_class_id, :description, :source)""",
            {
                "id": sig["id"],
                "name": sig["name"],
                "qualified_pattern": sig["qualified_pattern"],
                "language": sig.get("language", "any"),
                "sig_type": sig["sig_type"],
                "cwe_ids": cwe_ids,
                "vuln_class_id": sig.get("vuln_class_id", ""),
                "description": sig.get("description", ""),
                "source": sig.get("source", "custom"),
            },
        )

    def get_all_taint_signatures(self) -> list[dict]:
        rows = self._conn.execute("SELECT * FROM taint_signatures").fetchall()
        result = []
        for r in rows:
            d = dict(r)
            try:
                d["cwe_ids"] = json.loads(d["cwe_ids"])
            except Exception:
                d["cwe_ids"] = []
            result.append(d)
        return result

    def get_taint_signatures_by_type(self, sig_type: str) -> list[dict]:
        rows = self._conn.execute(
            "SELECT * FROM taint_signatures WHERE sig_type = ?", (sig_type,)
        ).fetchall()
        result = []
        for r in rows:
            d = dict(r)
            try:
                d["cwe_ids"] = json.loads(d["cwe_ids"])
            except Exception:
                d["cwe_ids"] = []
            result.append(d)
        return result

    def is_known_sink(self, pattern: str) -> bool:
        row = self._conn.execute(
            "SELECT 1 FROM taint_signatures WHERE sig_type = 'SINK' AND qualified_pattern = ?",
            (pattern,),
        ).fetchone()
        return row is not None

    def is_known_source(self, pattern: str) -> bool:
        row = self._conn.execute(
            "SELECT 1 FROM taint_signatures WHERE sig_type = 'SOURCE' AND qualified_pattern = ?",
            (pattern,),
        ).fetchone()
        return row is not None

    # ------------------------------------------------------------------
    # arg_node_types
    # ------------------------------------------------------------------

    def upsert_arg_node_type(self, row: dict) -> None:
        self._conn.execute(
            """INSERT OR REPLACE INTO arg_node_types
               (id, language, node_type, arg_type, is_concatenated, is_parameterised,
                contains_var, child_type_check, child_text_prefix, operator_text, notes)
               VALUES (:id, :language, :node_type, :arg_type, :is_concatenated,
                       :is_parameterised, :contains_var, :child_type_check,
                       :child_text_prefix, :operator_text, :notes)""",
            {
                "id": row["id"],
                "language": row["language"],
                "node_type": row["node_type"],
                "arg_type": row["arg_type"],
                "is_concatenated": int(row.get("is_concatenated", 0)),
                "is_parameterised": int(row.get("is_parameterised", 0)),
                "contains_var": int(row.get("contains_var", 0)),
                "child_type_check": row.get("child_type_check"),
                "child_text_prefix": row.get("child_text_prefix"),
                "operator_text": row.get("operator_text"),
                "notes": row.get("notes"),
            },
        )

    def get_arg_node_types(self, language: str) -> list[dict]:
        rows = self._conn.execute(
            "SELECT * FROM arg_node_types WHERE language = ?", (language,)
        ).fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # entry_point_patterns
    # ------------------------------------------------------------------

    def upsert_entry_point_pattern(self, row: dict) -> None:
        self._conn.execute(
            """INSERT OR REPLACE INTO entry_point_patterns
               (id, language, pattern, match_type, notes)
               VALUES (:id, :language, :pattern, :match_type, :notes)""",
            {
                "id": row["id"],
                "language": row["language"],
                "pattern": row["pattern"],
                "match_type": row.get("match_type", "substring"),
                "notes": row.get("notes"),
            },
        )

    def get_entry_point_patterns(self, language: str) -> list[dict]:
        rows = self._conn.execute(
            "SELECT * FROM entry_point_patterns WHERE language = ?", (language,)
        ).fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # language_capabilities
    # ------------------------------------------------------------------

    def upsert_capability(self, row: dict) -> None:
        self._conn.execute(
            """INSERT OR REPLACE INTO language_capabilities
               (id, language, capability, description, status)
               VALUES (:id, :language, :capability, :description, :status)""",
            {
                "id": row["id"],
                "language": row["language"],
                "capability": row["capability"],
                "description": row["description"],
                "status": row.get("status", "supported"),
            },
        )

    def get_capabilities(self, language: str | None = None) -> list[dict]:
        if language:
            rows = self._conn.execute(
                "SELECT * FROM language_capabilities WHERE language = ? ORDER BY language, capability",
                (language,),
            ).fetchall()
        else:
            rows = self._conn.execute(
                "SELECT * FROM language_capabilities ORDER BY language, capability"
            ).fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def stats(self) -> dict[str, int]:
        return {
            "vuln_classes": self._conn.execute(
                "SELECT count(*) FROM vuln_classes"
            ).fetchone()[0],
            "detectors": self._conn.execute(
                "SELECT count(*) FROM detectors"
            ).fetchone()[0],
            "taint_signatures": self._conn.execute(
                "SELECT count(*) FROM taint_signatures"
            ).fetchone()[0],
        }

    def commit(self) -> None:
        self._conn.commit()
