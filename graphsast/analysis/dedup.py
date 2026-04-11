"""Semgrep finding deduplication.

When multiple Semgrep rules fire on the same code location for the same
vulnerability class (same CWE), they represent one issue — not several.
Running the LLM on each duplicate wastes time and produces redundant verdicts.

Strategy
────────
Two raw findings are considered duplicates when ALL of:
  • Same file_path
  • Overlapping line ranges  (max(start_a, start_b) <= min(end_a, end_b))
  • Same normalised CWE ID  (non-empty)

From each duplicate cluster the finding with the highest severity is kept.
Ties are broken by preferring the finding whose rule_id is longest (more
specific rules tend to have longer IDs).
"""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)

_SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}


def deduplicate(raw_findings: list[dict]) -> tuple[list[dict], int]:
    """Remove duplicate findings and return (deduplicated, n_removed).

    Args:
        raw_findings: List of raw Semgrep finding dicts.

    Returns:
        Tuple of (deduplicated list, number of findings removed).
    """
    if not raw_findings:
        return [], 0

    # Annotate each finding with normalised fields for comparison
    annotated = [_annotate(r) for r in raw_findings]

    # Group by (file_path, normalised_cwe) — only deduplicate when CWE is known
    groups: dict[tuple[str, str], list[dict]] = {}
    no_cwe: list[dict] = []

    for ann in annotated:
        cwe = ann["_cwe"]
        if not cwe:
            no_cwe.append(ann)
            continue
        key = (ann["_file"], cwe)
        groups.setdefault(key, []).append(ann)

    kept: list[dict] = list(no_cwe)

    for findings_in_group in groups.values():
        kept.extend(_merge_overlapping(findings_in_group))

    # Strip annotation keys, preserve original order (stable sort by file+line)
    result = sorted(
        [_strip(f) for f in kept],
        key=lambda r: (r.get("path", ""), r.get("start", {}).get("line", 0)),
    )

    n_removed = len(raw_findings) - len(result)
    return result, n_removed


# ── Helpers ────────────────────────────────────────────────────────────────────

def _annotate(raw: dict) -> dict:
    """Add _file, _start, _end, _cwe, _sev_rank, _rule_len to raw dict (non-destructive)."""
    extra = raw.get("extra", {})
    meta  = extra.get("metadata", {})
    start = raw.get("start", {})
    end   = raw.get("end", {})

    cwe_raw = meta.get("cwe", "")
    if isinstance(cwe_raw, list):
        cwe_raw = cwe_raw[0] if cwe_raw else ""
    cwe = _normalise_cwe(str(cwe_raw))

    sev_raw = (extra.get("severity") or "MEDIUM").upper()
    sev_rank = _SEVERITY_RANK.get(sev_raw, _SEVERITY_RANK.get("MEDIUM", 2))

    ann = dict(raw)
    ann["_file"]     = raw.get("path", "")
    ann["_start"]    = start.get("line", 0)
    ann["_end"]      = end.get("line", start.get("line", 0))
    ann["_cwe"]      = cwe
    ann["_sev_rank"] = sev_rank
    ann["_rule_len"] = len(raw.get("check_id", ""))
    return ann


def _merge_overlapping(findings: list[dict]) -> list[dict]:
    """Cluster overlapping findings and keep the best from each cluster."""
    if len(findings) == 1:
        return findings

    # Sort by start line for a single O(n) sweep
    findings = sorted(findings, key=lambda f: f["_start"])
    clusters: list[list[dict]] = []
    current: list[dict] = [findings[0]]

    for f in findings[1:]:
        # Overlapping if f starts before or at the end of the current cluster
        cluster_end = max(x["_end"] for x in current)
        if f["_start"] <= cluster_end + 1:   # +1: adjacent lines count as overlap
            current.append(f)
        else:
            clusters.append(current)
            current = [f]
    clusters.append(current)

    return [_best(c) for c in clusters]


def _best(cluster: list[dict]) -> dict:
    """Return the highest-severity (then longest rule_id) finding from a cluster."""
    return max(cluster, key=lambda f: (f["_sev_rank"], f["_rule_len"]))


def _strip(ann: dict) -> dict:
    """Remove annotation keys added by _annotate."""
    return {k: v for k, v in ann.items() if not k.startswith("_")}


def _normalise_cwe(raw: str) -> str:
    """'CWE-089' → 'CWE-89', 'cwe-89' → 'CWE-89', '' → ''."""
    raw = raw.strip()
    if not raw:
        return ""
    upper = raw.upper()
    if upper.startswith("CWE-"):
        try:
            return f"CWE-{int(upper[4:])}"
        except ValueError:
            pass
    return upper
