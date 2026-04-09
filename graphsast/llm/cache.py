"""Phase 1 LLM finding cache.

Avoids re-running expensive LLM analysis when source code hasn't changed.

Cache key = sha256( phase | qualified_name | file_hash | model [| vuln_class] )

A hit is only returned when:
  - The same entry-point / finding location was analysed before
  - The source file hash matches (i.e. the code hasn't changed)
  - The same model was used (different models may give different results)

The cache lives in the graph.db (phase1_cache table, added in migration v9)
so it travels with the project and persists across `graphsast scan` runs.
"""

from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger(__name__)


# ──────────────────────────────────────────────────────────────────────────────
# Key computation
# ──────────────────────────────────────────────────────────────────────────────

def _file_hash(file_path: str) -> str:
    """SHA-256 of file contents.  Returns empty string if file is unreadable."""
    try:
        data = Path(file_path).read_bytes()
        return hashlib.sha256(data).hexdigest()
    except OSError:
        return ""


def make_cache_key(
    phase: str,
    qualified_name: str,
    file_path: str,
    model: str,
    vuln_class_id: str = "",
) -> str:
    """Compute a deterministic cache key.

    Args:
        phase:          "1a" or "1b"
        qualified_name: entry-point or finding QN
        file_path:      absolute path to the source file
        model:          LLM model name (e.g. "llama3.1", "claude-opus-4-6")
        vuln_class_id:  only used for Phase 1B (e.g. "sqli")
    """
    raw = f"{phase}|{qualified_name}|{_file_hash(file_path)}|{model}|{vuln_class_id}"
    return hashlib.sha256(raw.encode()).hexdigest()


# ──────────────────────────────────────────────────────────────────────────────
# Cache read / write (thin wrappers around the DB)
# ──────────────────────────────────────────────────────────────────────────────

def get_cached(conn, cache_key: str) -> dict | None:
    """Return the cached payload dict, or None on miss."""
    try:
        row = conn.execute(
            "SELECT payload FROM phase1_cache WHERE cache_key = ? LIMIT 1",
            (cache_key,),
        ).fetchone()
        if row:
            return json.loads(row[0])
    except Exception as exc:
        logger.debug("Cache read error: %s", exc)
    return None


def set_cached(conn, cache_key: str, phase: str, payload: dict) -> None:
    """Write (or overwrite) a cache entry."""
    try:
        conn.execute(
            """INSERT OR REPLACE INTO phase1_cache
               (cache_key, phase, payload, cached_at)
               VALUES (?, ?, ?, ?)""",
            (
                cache_key,
                phase,
                json.dumps(payload),
                datetime.now(timezone.utc).isoformat(),
            ),
        )
        conn.commit()
    except Exception as exc:
        logger.debug("Cache write error: %s", exc)
