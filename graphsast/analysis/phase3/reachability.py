"""Reachability-based severity adjustment.

Adjusts severity of findings based on how reachable the vulnerable entry
point is from an attacker's perspective:

  test_file       → force LOW  (test/fixture/mock paths are not prod code)
  auth_protected  → downgrade one severity level  (requires valid session)
  public          → keep original severity

Reachability is determined by:
  1. File path heuristics (test detection)
  2. Graph missing-check data: if an entry point has NO missing auth_check
     record it is likely protected by authentication.
"""

from __future__ import annotations

import logging

from graphsast.analysis.phase3.correlator import Finding
from graphsast.graph_db.store import SecurityGraphStore

logger = logging.getLogger(__name__)

# Path fragments that signal test / non-production code
_TEST_PATH_FRAGMENTS = (
    "/test/", "/tests/", "/test_", "test_",
    "/spec/", "/specs/",
    "/fixture/", "/fixtures/",
    "/mock/", "/mocks/",
    "/conftest",
)

_SEV_DOWNGRADE = {
    "CRITICAL": "HIGH",
    "HIGH":     "MEDIUM",
    "MEDIUM":   "LOW",
    "LOW":      "LOW",
}


def apply_reachability(
    findings: list[Finding],
    graph: SecurityGraphStore,
    target: "Path | None" = None,
) -> list[Finding]:
    """Adjust severity in-place for each finding based on reachability.

    Args:
        findings: list of correlated Finding objects (mutated in-place).
        graph:    SecurityGraphStore for missing-check queries.
        target:   Scan root directory.  When given, the test-file check is
                  applied to the path *relative* to the target so that scanning
                  a fixture directory (e.g. tests/fixtures/myapp) doesn't
                  accidentally flag every file as a test file.

    Returns the same list (mutated).
    """
    for f in findings:
        if f.is_suppressed:
            continue
        _adjust(f, graph, target)
    return findings


# ──────────────────────────────────────────────────────────────────────────────

def _adjust(finding: Finding, graph: SecurityGraphStore, target: "Path | None" = None) -> None:
    """Mutate finding.severity based on reachability context."""
    from pathlib import Path as _Path
    # ── Test file ─────────────────────────────────────────────────────────────
    # Use path relative to scan target so that scanning inside tests/fixtures/
    # doesn't flag every file as a test file.
    abs_path = finding.file_path or ""
    if target:
        try:
            rel = _Path(abs_path).relative_to(target).as_posix()
        except ValueError:
            rel = abs_path
    else:
        rel = abs_path
    fp_lower = rel.lower().replace("\\", "/")
    if any(frag in fp_lower for frag in _TEST_PATH_FRAGMENTS):
        if finding.severity != "LOW":
            logger.debug(
                "Reachability: test file %s — downgrading %s → LOW",
                finding.file_path, finding.severity,
            )
            finding.severity = "LOW"
        finding.extra["reachability"] = "test_file"
        return

    # ── Auth protection check ─────────────────────────────────────────────────
    qn = finding.qualified_name
    if not qn:
        finding.extra["reachability"] = "unknown"
        return

    try:
        missing = graph.get_missing_checks(qn)
    except Exception:
        finding.extra["reachability"] = "unknown"
        return

    missing_types = {m.missing_type for m in (missing or [])}

    # The missing_type for auth checks is stored as "auth" or "auth_check"
    if missing_types & {"auth", "auth_check"}:
        # Auth is explicitly ABSENT → publicly accessible
        finding.extra["reachability"] = "public"
    else:
        # No missing-auth record for this entry point.
        # Two possibilities:
        #   a) Auth IS present in the call chain → protected
        #   b) This entry point wasn't analysed for auth (e.g. non-HTTP helper)
        #
        # Use a secondary heuristic: is the node tagged as an entry_point in
        # the graph?  If it is an entry_point but has no auth record at all, be
        # conservative and mark as unknown.  Only downgrade when we have
        # explicit evidence that auth_check patterns ARE reachable from this
        # entry point (i.e. there are no missing records AND the node IS an
        # entry_point).
        is_ep = _is_entry_point(qn, graph)
        if is_ep:
            orig = finding.severity
            finding.severity = _SEV_DOWNGRADE.get(orig, orig)
            finding.extra["reachability"] = "auth_protected"
            if finding.severity != orig:
                logger.debug(
                    "Reachability: %s auth-protected — %s → %s",
                    qn, orig, finding.severity,
                )
        else:
            finding.extra["reachability"] = "unknown"


def _is_entry_point(qn: str, graph: SecurityGraphStore) -> bool:
    """Return True if qn is recorded as an entry_point in the nodes table."""
    try:
        row = graph._conn.execute(
            "SELECT 1 FROM nodes WHERE qualified_name = ? AND is_entry_point = 1 LIMIT 1",
            (qn,),
        ).fetchone()
        return row is not None
    except Exception:
        return False
