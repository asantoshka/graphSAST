"""Phase 2 Pass A — Semgrep pattern runner.

Extracts semgrep-type detectors from vulns.db, writes them to a temp
directory, runs `semgrep --config ... --json`, and maps each finding
back to a qualified_name via line numbers from graph.db.
"""

from __future__ import annotations

import json
import logging
import subprocess
import tempfile
from pathlib import Path
from typing import Any

import yaml

from graphsast.graph_db.store import SecurityGraphStore
from graphsast.vuln_db.store import VulnStore

logger = logging.getLogger(__name__)

# How many rules to bundle into a single temp file (avoids too many args)
_RULES_PER_FILE = 200


def run_semgrep(
    graph: SecurityGraphStore,
    vuln_db: VulnStore,
    target: Path,
    language: str | None = None,
    max_rules: int = 0,
) -> list[dict]:
    """Run Semgrep detectors from vulns.db against target.

    Returns a list of finding dicts:
        {
            source: "semgrep",
            rule_id: str,
            vuln_class_id: str,
            cwe_id: str,
            severity: str,
            message: str,
            file_path: str,
            line_start: int,
            line_end: int,
            qualified_name: str | None,  # mapped from graph
            confidence: str,
        }
    """
    # Pull semgrep detectors from vulns.db
    detectors = _load_semgrep_detectors(vuln_db, language=language, max_rules=max_rules)
    if not detectors:
        logger.info("No semgrep detectors found in vulns.db")
        return []

    logger.info("Running semgrep with %d detectors against %s", len(detectors), target)

    with tempfile.TemporaryDirectory(prefix="graphsast_semgrep_") as tmpdir:
        rule_files = _write_rule_files(detectors, Path(tmpdir))
        raw_findings = _run_semgrep_cli(target, Path(tmpdir))

    # Map findings to qualified names
    findings = []
    for raw in raw_findings:
        finding = _map_finding(graph, vuln_db, raw)
        if finding:
            findings.append(finding)

    logger.info("Semgrep: %d raw findings → %d mapped", len(raw_findings), len(findings))
    return findings


# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────

def _load_semgrep_detectors(
    vuln_db: VulnStore,
    language: str | None,
    max_rules: int,
) -> list[dict]:
    """Load (detector_row, vuln_class_row) pairs from vulns.db."""
    conn = vuln_db._conn

    query = """
        SELECT d.id as det_id, d.content, d.confidence,
               v.id as vc_id, v.cwe_id, v.severity, v.language
        FROM detectors d
        JOIN vuln_classes v ON d.vuln_class_id = v.id
        WHERE d.detector_type = 'semgrep'
    """
    params: list[Any] = []
    if language:
        query += " AND (v.language = ? OR v.language = 'any')"
        params.append(language)
    if max_rules > 0:
        query += f" LIMIT {int(max_rules)}"

    rows = conn.execute(query, params).fetchall()
    return [dict(r) for r in rows]


def _write_rule_files(detectors: list[dict], tmpdir: Path) -> list[Path]:
    """Write detectors into batched YAML rule files. Returns list of file paths."""
    files = []
    for i in range(0, len(detectors), _RULES_PER_FILE):
        batch = detectors[i : i + _RULES_PER_FILE]
        rules = []
        for det in batch:
            try:
                parsed = yaml.safe_load(det["content"])
                if parsed and isinstance(parsed, dict) and "rules" in parsed:
                    rules.extend(parsed["rules"])
            except Exception as exc:
                logger.debug("Failed to parse detector %s: %s", det["det_id"], exc)

        if rules:
            rule_file = tmpdir / f"batch_{i // _RULES_PER_FILE:04d}.yaml"
            with rule_file.open("w", encoding="utf-8") as f:
                yaml.dump({"rules": rules}, f, default_flow_style=False, allow_unicode=True)
            files.append(rule_file)

    return files


def _run_semgrep_cli(target: Path, rules_dir: Path) -> list[dict]:
    """Run semgrep CLI and return parsed findings list."""
    # Check that semgrep is available
    try:
        subprocess.run(
            ["semgrep", "--version"],
            capture_output=True,
            check=True,
            timeout=10,
        )
    except (subprocess.CalledProcessError, FileNotFoundError):
        logger.warning("semgrep not found — skipping Pass A")
        return []

    cmd = [
        "semgrep",
        "--config", str(rules_dir),
        "--json",
        "--no-git-ignore",
        "--quiet",
        str(target),
    ]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            timeout=300,  # 5-minute timeout
        )
        # semgrep exits 1 when findings are found — that is expected
        output = result.stdout.decode("utf-8", errors="replace")
        if not output.strip():
            return []
        data = json.loads(output)
        return data.get("results", [])
    except subprocess.TimeoutExpired:
        logger.error("semgrep timed out after 5 minutes")
        return []
    except json.JSONDecodeError as exc:
        logger.error("Failed to parse semgrep output: %s", exc)
        return []
    except Exception as exc:
        logger.error("semgrep failed: %s", exc)
        return []


def _map_finding(
    graph: SecurityGraphStore,
    vuln_db: VulnStore,
    raw: dict,
) -> dict | None:
    """Map a raw semgrep result to a GraphSAST finding dict."""
    check_id = raw.get("check_id", "")
    file_path = raw.get("path", "")
    start = raw.get("start", {})
    end = raw.get("end", {})
    line_start = start.get("line", 0)
    line_end = end.get("line", line_start)
    message = raw.get("extra", {}).get("message", "")
    severity = raw.get("extra", {}).get("severity", "MEDIUM")

    # Look up vuln_class via rule id (strip "semgrep-" prefix if present)
    vc_id = f"semgrep-{check_id}"
    vc_row = vuln_db._conn.execute(
        "SELECT cwe_id, severity FROM vuln_classes WHERE id = ?", (vc_id,)
    ).fetchone()

    cwe_id = ""
    if vc_row:
        cwe_id = vc_row["cwe_id"] or ""
        severity = vc_row["severity"] or severity

    # Map to qualified name from graph using file_path + line_number
    qn = _line_to_qn(graph, file_path, line_start)

    return {
        "source": "semgrep",
        "rule_id": check_id,
        "vuln_class_id": vc_id,
        "cwe_id": cwe_id,
        "severity": _normalise_severity(severity),
        "message": message[:500],
        "file_path": file_path,
        "line_start": line_start,
        "line_end": line_end,
        "qualified_name": qn,
        "confidence": "MEDIUM",
    }


def _line_to_qn(graph: SecurityGraphStore, file_path: str, line: int) -> str | None:
    """Find the function node that contains the given line in file_path."""
    row = graph._conn.execute(
        """SELECT qualified_name FROM nodes
           WHERE file_path = ?
             AND kind IN ('Function', 'Method')
             AND line_start <= ?
             AND (line_end IS NULL OR line_end >= ?)
           ORDER BY line_start DESC
           LIMIT 1""",
        (file_path, line, line),
    ).fetchone()
    if row:
        return row["qualified_name"]

    # Fall back: any node at exactly that line
    row = graph._conn.execute(
        """SELECT qualified_name FROM nodes
           WHERE file_path = ? AND line_start = ?
           LIMIT 1""",
        (file_path, line),
    ).fetchone()
    return row["qualified_name"] if row else None


def _normalise_severity(raw: str) -> str:
    mapping = {
        "CRITICAL": "CRITICAL",
        "ERROR": "HIGH",
        "HIGH": "HIGH",
        "WARNING": "MEDIUM",
        "MEDIUM": "MEDIUM",
        "INFO": "LOW",
        "LOW": "LOW",
    }
    return mapping.get((raw or "").upper(), "MEDIUM")
