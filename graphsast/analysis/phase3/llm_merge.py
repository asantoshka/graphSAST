"""Merge Phase 1A / 1B LLM results into the correlated findings list.

Three operations:
  1. Phase 1A injection — the LLM discovered a vulnerability autonomously.
     If it matches an existing finding → boost confidence + add "llm_1a" source.
     If it doesn't match → synthesise a new Finding.

  2. Phase 1B annotation — the LLM validated a specific suspect path.
     CONFIRMED   → add "llm_1b" source, boost confidence.
     FALSE_POSITIVE → mark is_suppressed=True (filtered from output unless
                      --show-suppressed is set).
     UNCERTAIN   → add note to extra, no confidence change.

  3. Conflict resolution — if Phase 1A says CONFIRMED but Phase 1B says
     FALSE_POSITIVE for the same qualified name, Phase 1A wins.
     Rationale: Phase 1A reads actual source code; Phase 1B micro-task on
     an uncertain case delegates to a small model that can flip.
"""

from __future__ import annotations

import logging
import uuid
from typing import Any

from graphsast.analysis.phase3.correlator import Finding

logger = logging.getLogger(__name__)

_SEV_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}


def merge_llm_results(
    findings: list[Finding],
    p1a_results: list[dict],
    p1b_results: list[dict],
) -> list[Finding]:
    """Return a new findings list with LLM evidence merged in.

    Args:
        findings:    Correlated Phase 2 findings.
        p1a_results: Phase 1A result dicts (from run_phase1a).
        p1b_results: Phase 1B result dicts (from run_phase1b).

    Returns:
        Updated list — same ordering, with new LLM-synthesised findings
        appended at the end.  is_suppressed findings are retained but
        sorted to the bottom.
    """
    # ── Build lookup: qualified_name → list[Finding] ──────────────────────────
    by_qn: dict[str, list[Finding]] = {}
    for f in findings:
        if f.qualified_name:
            by_qn.setdefault(f.qualified_name, []).append(f)

    new_findings: list[Finding] = []

    # ── Step 1: apply Phase 1A ────────────────────────────────────────────────
    p1a_confirmed_qns: set[str] = set()

    for p1a in p1a_results:
        qn          = p1a.get("entry_point_qn", "")
        suspected   = p1a.get("suspected_vuln", "")
        cwe         = p1a.get("suggested_cwe", "")
        confidence  = p1a.get("confidence", "LOW")
        reasoning   = p1a.get("reasoning", "")

        if not suspected:
            continue  # LLM found nothing here

        p1a_confirmed_qns.add(qn)

        # Try to match an existing Phase 2 finding
        candidates = by_qn.get(qn, [])
        matched = _best_match(candidates, cwe)

        if matched:
            if "llm_1a" not in matched.sources:
                matched.sources.append("llm_1a")
            matched.llm_verdict    = "CONFIRMED"
            matched.llm_confidence = confidence
            matched.llm_reasoning  = reasoning
            matched.llm_method     = "phase1a"
            # Upgrade confidence if LLM is more certain
            if _SEV_ORDER.get(confidence, 0) > _SEV_ORDER.get(matched.confidence, 0):
                matched.confidence = confidence
            logger.debug("Phase 1A boosted existing finding for %s", qn)
        else:
            # Synthesise a new finding from Phase 1A only
            new_f = _synthesise_finding(qn, suspected, cwe, confidence, reasoning, p1a)
            new_findings.append(new_f)
            # Add to lookup so Phase 1B can reference it
            by_qn.setdefault(qn, []).append(new_f)
            logger.debug("Phase 1A synthesised new finding for %s: %s", qn, suspected[:60])

    # ── Step 2: apply Phase 1B ────────────────────────────────────────────────
    for p1b in p1b_results:
        qn       = p1b.get("qualified_name", "")
        verdict  = p1b.get("verdict", "UNCERTAIN")
        conf     = p1b.get("confidence", "LOW")
        method   = p1b.get("method", "")
        reasoning = p1b.get("reasoning", "")
        cwe      = p1b.get("cwe_id", "")

        candidates = by_qn.get(qn, [])
        matched = _best_match(candidates, cwe)

        if not matched:
            logger.debug("Phase 1B: no finding to annotate for %s", qn)
            continue

        matched.llm_method = method

        if verdict == "CONFIRMED":
            if "llm_1b" not in matched.sources:
                matched.sources.append("llm_1b")
            matched.llm_verdict    = "CONFIRMED"
            matched.llm_confidence = conf
            matched.llm_reasoning  = reasoning
            if _SEV_ORDER.get(conf, 0) > _SEV_ORDER.get(matched.confidence, 0):
                matched.confidence = conf

        elif verdict == "FALSE_POSITIVE":
            # Conflict resolution: if Phase 1A already confirmed this, 1A wins
            if qn in p1a_confirmed_qns:
                logger.info(
                    "Conflict: Phase 1A CONFIRMED but Phase 1B FALSE_POSITIVE for %s — "
                    "Phase 1A wins",
                    qn,
                )
                matched.extra["llm_1b_disagreement"] = (
                    f"Phase 1B ({method}) said FALSE_POSITIVE but Phase 1A overrides: {reasoning[:200]}"
                )
            else:
                matched.is_suppressed  = True
                matched.llm_verdict    = "FALSE_POSITIVE"
                matched.llm_confidence = conf
                matched.llm_reasoning  = reasoning
                logger.info("Phase 1B suppressed finding for %s (%s)", qn, method)

        else:  # UNCERTAIN
            matched.extra["llm_1b_uncertain"] = reasoning[:200]

    # ── Combine and re-sort ───────────────────────────────────────────────────
    all_findings = findings + new_findings

    # Sort: active (not suppressed) first, then by severity desc
    all_findings.sort(key=lambda f: (
        f.is_suppressed,                            # False < True
        -_SEV_ORDER.get(f.severity, 0),
        -_SEV_ORDER.get(f.confidence, 0),
    ))

    active     = [f for f in all_findings if not f.is_suppressed]
    suppressed = [f for f in all_findings if f.is_suppressed]

    logger.info(
        "LLM merge: %d active findings, %d suppressed (false positives), "
        "%d new from Phase 1A",
        len(active), len(suppressed), len(new_findings),
    )
    return active + suppressed


# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────

def _best_match(candidates: list[Finding], cwe: str) -> Finding | None:
    """Pick the best matching finding from candidates.

    Prefers exact CWE match; falls back to first candidate.
    """
    if not candidates:
        return None
    if cwe:
        for c in candidates:
            if c.cwe_id == cwe:
                return c
    return candidates[0]


def _synthesise_finding(
    qn: str,
    suspected_vuln: str,
    cwe: str,
    confidence: str,
    reasoning: str,
    p1a: dict[str, Any],
) -> Finding:
    """Create a Finding from a Phase 1A result that has no Phase 2 match."""
    # Infer file path / line from the qn string if it contains "::"
    file_path = ""
    line = 0
    if "::" in qn:
        file_path = qn.split("::")[0]

    severity = _confidence_to_severity(confidence)

    return Finding(
        id=f"llm1a:{str(uuid.uuid4())[:8]}",
        cwe_id=cwe or "",
        severity=severity,
        confidence=confidence,
        title=_cwe_title(cwe) or suspected_vuln[:60],
        message=suspected_vuln,
        file_path=file_path,
        line_start=line,
        line_end=line,
        qualified_name=qn,
        sources=["llm_1a"],
        llm_verdict="CONFIRMED",
        llm_confidence=confidence,
        llm_reasoning=reasoning,
        llm_method="phase1a",
        extra={
            "affected_nodes": p1a.get("affected_nodes", "[]"),
        },
    )


def _confidence_to_severity(confidence: str) -> str:
    return {"HIGH": "HIGH", "MEDIUM": "MEDIUM", "LOW": "LOW"}.get(confidence, "MEDIUM")


_CWE_TITLES = {
    "CWE-89":  "SQL Injection",
    "CWE-78":  "OS Command Injection",
    "CWE-79":  "Cross-Site Scripting (XSS)",
    "CWE-94":  "Code Injection",
    "CWE-95":  "Eval Injection",
    "CWE-22":  "Path Traversal",
    "CWE-502": "Insecure Deserialization",
    "CWE-918": "Server-Side Request Forgery (SSRF)",
}

def _cwe_title(cwe: str) -> str:
    return _CWE_TITLES.get(cwe, "")
