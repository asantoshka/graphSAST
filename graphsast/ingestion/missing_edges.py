"""Missing security check detector.

For every entry point in the graph, runs a bounded BFS through its call chain
and records which security functions are absent (auth, rate limiting, CSRF, etc.).
"""

from __future__ import annotations

import logging
from collections import deque

from graphsast.graph_db.store import MissingCheck, SecurityGraphStore

logger = logging.getLogger(__name__)

# Security function name patterns we look for in call chains.
# Keys are the missing_type label; values are lists of function name patterns.
SECURITY_FUNCTION_PATTERNS: dict[str, list[str]] = {
    "auth": [
        "login_required", "auth_required", "authenticate", "is_authenticated",
        "require_auth", "check_auth", "verify_token", "jwt_required",
        "token_required", "permission_required", "authorization_required",
        "@login_required", "@auth_required",
    ],
    "rate_limit": [
        "rate_limit", "ratelimit", "throttle", "limiter", "rate_limiter",
        "RateLimit", "RateLimiter",
    ],
    "csrf": [
        "csrf_protect", "csrf_exempt", "verify_csrf", "check_csrf",
        "validate_csrf", "csrf_token", "CSRFProtect",
    ],
    "validation": [
        "validate", "schema.load", "is_valid", "clean", "sanitize",
        "validator", "validate_input", "check_input",
    ],
}

# BFS depth limit: how many hops into the call chain we search
MAX_BFS_DEPTH = 6


class MissingCheckDetector:
    """Detects absent security checks in entry point call chains."""

    def __init__(self, graph: SecurityGraphStore) -> None:
        self.graph = graph

    def detect_all(self) -> int:
        """Run detection for all entry points. Returns number of findings."""
        entry_points = self.graph.get_entry_points()
        if not entry_points:
            logger.info("MissingCheckDetector: no entry points found")
            return 0

        count = 0
        for ep_qn in entry_points:
            reached = self._bfs_call_chain(ep_qn)
            for missing_type, patterns in SECURITY_FUNCTION_PATTERNS.items():
                if not _any_pattern_in_chain(patterns, reached):
                    mc = MissingCheck(
                        entry_point_qn=ep_qn,
                        missing_type=missing_type,
                        check_patterns=patterns,
                    )
                    self.graph.upsert_missing_check(mc)
                    count += 1

        self.graph.commit()
        logger.info("MissingCheckDetector: found %d missing check instances", count)
        return count

    def _bfs_call_chain(self, start: str) -> set[str]:
        """Return all function names reachable from start within MAX_BFS_DEPTH."""
        conn = self.graph._conn
        visited: set[str] = {start}
        queue: deque[tuple[str, int]] = deque([(start, 0)])
        names: set[str] = set()

        # Collect the name of the start node
        row = conn.execute(
            "SELECT name FROM nodes WHERE qualified_name = ?", (start,)
        ).fetchone()
        if row:
            names.add(row["name"])

        while queue:
            current, depth = queue.popleft()
            if depth >= MAX_BFS_DEPTH:
                continue

            rows = conn.execute(
                """SELECT e.target_qualified, n.name
                   FROM edges e
                   LEFT JOIN nodes n ON n.qualified_name = e.target_qualified
                   WHERE e.source_qualified = ? AND e.kind = 'CALLS'""",
                (current,),
            ).fetchall()

            for row in rows:
                target = row["target_qualified"]
                name = row["name"] or ""
                if target not in visited:
                    visited.add(target)
                    names.add(name)
                    queue.append((target, depth + 1))

        return names


def _any_pattern_in_chain(patterns: list[str], reached_names: set[str]) -> bool:
    """Check if any security pattern name is present in the reached function names."""
    for pattern in patterns:
        clean = pattern.lstrip("@")
        for name in reached_names:
            if clean.lower() in name.lower():
                return True
    return False
