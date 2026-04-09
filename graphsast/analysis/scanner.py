"""Top-level scanner — orchestrates Phase 2 + Phase 3.

Usage:
    from graphsast.analysis.scanner import Scanner
    scanner = Scanner(graph, vuln_db)
    findings = scanner.scan(target)
"""

from __future__ import annotations

import logging
import time
import uuid
from pathlib import Path

from graphsast.graph_db.store import SecurityGraphStore
from graphsast.vuln_db.store import VulnStore
from graphsast.analysis.phase2.taint_queries import run_taint_queries
from graphsast.analysis.phase2.structure import run_structure_analysis
from graphsast.analysis.phase3.correlator import correlate, Finding

logger = logging.getLogger(__name__)


class Scanner:
    """Orchestrates Phase 2 passes and Phase 3 correlation."""

    def __init__(
        self,
        graph: SecurityGraphStore,
        vuln_db: VulnStore | None = None,
        run_semgrep: bool = True,
        language: str | None = None,
        max_semgrep_rules: int = 0,
    ) -> None:
        self.graph = graph
        self.vuln_db = vuln_db
        self.run_semgrep_pass = run_semgrep and vuln_db is not None
        self.language = language
        self.max_semgrep_rules = max_semgrep_rules

    def scan(self, target: Path) -> tuple[list[Finding], dict]:
        """Run all Phase 2 passes and return (findings, summary).

        ``summary`` is a dict with timing and per-pass counts.
        """
        start = time.time()
        scan_run_id = str(uuid.uuid4())[:8]
        target = target.resolve()

        all_raw: list[dict] = []

        # Pass B — graph taint queries (always)
        taint_findings = run_taint_queries(self.graph)
        all_raw.extend(taint_findings)
        logger.info("Pass B (taint): %d findings", len(taint_findings))

        # Pass C — structure analysis (always)
        structure_findings = run_structure_analysis(self.graph)
        all_raw.extend(structure_findings)
        logger.info("Pass C (structure): %d findings", len(structure_findings))

        # Pass A — Semgrep (optional)
        semgrep_count = 0
        if self.run_semgrep_pass:
            try:
                from graphsast.analysis.phase2.semgrep_runner import run_semgrep
                semgrep_findings = run_semgrep(
                    self.graph,
                    self.vuln_db,
                    target,
                    language=self.language,
                    max_rules=self.max_semgrep_rules,
                )
                all_raw.extend(semgrep_findings)
                semgrep_count = len(semgrep_findings)
                logger.info("Pass A (semgrep): %d findings", semgrep_count)
            except Exception as exc:
                logger.warning("Semgrep pass failed: %s", exc)

        # Phase 3 — correlate
        findings = correlate(all_raw)

        elapsed = time.time() - start
        summary = {
            "scan_run_id": scan_run_id,
            "target": str(target),
            "elapsed_seconds": round(elapsed, 2),
            "pass_b_taint": len(taint_findings),
            "pass_c_structure": len(structure_findings),
            "pass_a_semgrep": semgrep_count,
            "raw_total": len(all_raw),
            "findings_after_correlation": len(findings),
            "by_severity": _count_by_severity(findings),
        }
        return findings, summary


def _count_by_severity(findings: list[Finding]) -> dict:
    counts: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    return counts
