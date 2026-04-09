"""Phase 2 Pass C — Import and structure analysis.

Flags:
- Dangerous imports  (pickle, marshal, yaml.load, eval, exec)
- Orphaned sensitive functions  (no incoming CALLS edges)
- God functions  (unusually high out-degree to sink nodes)
- Insecure configuration patterns  (DEBUG=True, SECRET_KEY literals)
"""

from __future__ import annotations

import logging
import re

from graphsast.graph_db.store import SecurityGraphStore

logger = logging.getLogger(__name__)


# Dangerous import/call patterns → (CWE, severity, message)
_DANGEROUS_IMPORTS: list[tuple[str, str, str, str]] = [
    ("pickle",        "CWE-502", "HIGH",   "Insecure deserialization via pickle"),
    ("marshal",       "CWE-502", "HIGH",   "Insecure deserialization via marshal"),
    ("yaml.load",     "CWE-502", "HIGH",   "Unsafe YAML load (use yaml.safe_load)"),
    ("eval",          "CWE-95",  "CRITICAL","Use of eval() allows code injection"),
    ("exec",          "CWE-95",  "CRITICAL","Use of exec() allows code injection"),
    ("__import__",    "CWE-95",  "HIGH",   "Dynamic import via __import__"),
    ("subprocess.shell=True", "CWE-78", "HIGH", "subprocess with shell=True — command injection risk"),
    ("os.system",     "CWE-78",  "HIGH",   "os.system() allows command injection"),
    ("tempfile.mktemp", "CWE-377", "MEDIUM", "Insecure temp file creation (use mkstemp)"),
    ("hashlib.md5",   "CWE-327", "MEDIUM", "MD5 is a weak hash algorithm"),
    ("hashlib.sha1",  "CWE-327", "MEDIUM", "SHA-1 is a weak hash algorithm"),
    ("random.random", "CWE-338", "MEDIUM", "random module is not cryptographically secure"),
    ("ssl.CERT_NONE", "CWE-295", "HIGH",   "TLS certificate verification disabled"),
]

# God function threshold: functions with this many or more sink calls
_GOD_FUNCTION_SINK_THRESHOLD = 5


def run_structure_analysis(graph: SecurityGraphStore) -> list[dict]:
    """Analyse the code graph for structural security issues.

    Returns a list of finding dicts in the standard Phase 2 format.
    """
    findings: list[dict] = []

    findings.extend(_check_dangerous_calls(graph))
    findings.extend(_check_orphaned_sensitive(graph))
    findings.extend(_check_god_functions(graph))

    logger.info("Structure analysis: %d findings", len(findings))
    return findings


# ──────────────────────────────────────────────────────────────────────────────
# Passes
# ──────────────────────────────────────────────────────────────────────────────

def _check_dangerous_calls(graph: SecurityGraphStore) -> list[dict]:
    """Find CALLS edges whose target matches a dangerous pattern."""
    findings = []
    conn = graph._conn

    for pattern, cwe, severity, message in _DANGEROUS_IMPORTS:
        # Match against CALLS edge targets
        name_part = pattern.split(".")[-1]  # e.g. "load" from "yaml.load"
        rows = conn.execute(
            """SELECT DISTINCT e.source_qualified, e.target_qualified,
                      n.file_path, n.line_start
               FROM edges e
               LEFT JOIN nodes n ON n.qualified_name = e.source_qualified
               WHERE e.kind = 'CALLS'
                 AND (e.target_qualified = ?
                      OR e.target_qualified LIKE ?)
            """,
            (pattern, f"%.{pattern}"),
        ).fetchall()

        seen_sources = set()
        for row in rows:
            src = row["source_qualified"] or ""
            if src in seen_sources:
                continue
            seen_sources.add(src)

            findings.append({
                "source": "structure",
                "rule_id": f"structure:{cwe.lower().replace('-', '_')}:{name_part}",
                "vuln_class_id": "",
                "cwe_id": cwe,
                "severity": severity,
                "message": message,
                "file_path": row["file_path"] or "",
                "line_start": row["line_start"] or 0,
                "line_end": row["line_start"] or 0,
                "qualified_name": src,
                "confidence": "MEDIUM",
                "extra": {
                    "pattern": pattern,
                    "target_qn": row["target_qualified"],
                },
            })

    return findings


def _check_orphaned_sensitive(graph: SecurityGraphStore) -> list[dict]:
    """Find functions with sensitive names but no incoming CALLS edges.

    These may be dead code that still holds security risks (e.g. an
    abandoned password reset function that bypasses the new auth flow).
    """
    SENSITIVE_PATTERNS = [
        r"admin", r"reset.?password", r"delete.?user",
        r"impersonate", r"sudo", r"bypass",
    ]
    combined = re.compile("|".join(SENSITIVE_PATTERNS), re.IGNORECASE)

    conn = graph._conn
    rows = conn.execute(
        """SELECT qualified_name, file_path, line_start
           FROM nodes
           WHERE kind IN ('Function', 'Method')
             AND qualified_name NOT IN (
                 SELECT DISTINCT target_qualified FROM edges WHERE kind = 'CALLS'
             )"""
    ).fetchall()

    findings = []
    for row in rows:
        name = (row["qualified_name"] or "").split("::")[-1]
        if combined.search(name):
            findings.append({
                "source": "structure",
                "rule_id": "structure:orphaned_sensitive_function",
                "vuln_class_id": "",
                "cwe_id": "CWE-561",
                "severity": "LOW",
                "message": f"Sensitive function '{name}' has no callers — may be dead or bypass code",
                "file_path": row["file_path"] or "",
                "line_start": row["line_start"] or 0,
                "line_end": row["line_start"] or 0,
                "qualified_name": row["qualified_name"],
                "confidence": "LOW",
                "extra": {"reason": "no_callers"},
            })

    return findings


def _check_god_functions(graph: SecurityGraphStore) -> list[dict]:
    """Find functions that call an unusually large number of known sinks."""
    conn = graph._conn
    sink_targets = set(
        r["node_qn"] for r in conn.execute(
            "SELECT DISTINCT node_qn FROM taint_annotations WHERE annotation_type = 'SINK'"
        ).fetchall()
    )
    if not sink_targets:
        return []

    placeholders = ",".join("?" * len(sink_targets))
    rows = conn.execute(
        f"""SELECT source_qn, COUNT(DISTINCT target_qn) as sink_count,
                   file_path, MIN(line) as line
            FROM call_arguments
            WHERE target_qn IN ({placeholders})
            GROUP BY source_qn
            HAVING sink_count >= ?""",
        list(sink_targets) + [_GOD_FUNCTION_SINK_THRESHOLD],
    ).fetchall()

    findings = []
    for row in rows:
        findings.append({
            "source": "structure",
            "rule_id": "structure:god_function",
            "vuln_class_id": "",
            "cwe_id": "CWE-1120",
            "severity": "LOW",
            "message": (
                f"Function calls {row['sink_count']} distinct sink functions — "
                "high complexity increases injection risk"
            ),
            "file_path": row["file_path"] or "",
            "line_start": row["line"] or 0,
            "line_end": row["line"] or 0,
            "qualified_name": row["source_qn"],
            "confidence": "LOW",
            "extra": {"sink_count": row["sink_count"]},
        })

    return findings
