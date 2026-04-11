"""Main scan orchestrator.

Flow:
  1. Build code graph with code_review_graph (full_build + FTS + flows).
  2. Run Semgrep against the target directory.
  3. Deduplicate findings (same location + CWE = one finding).
  4. For each finding:
       a. Upsert into FindingStore (persistent DB).
       b. Look up existing verdict — skip LLM if file unchanged.
       c. Otherwise run LLM analyst and persist the new verdict.
  5. Diff against previous run (new / fixed / recurring).
  6. Return findings + summary.
"""

from __future__ import annotations

import logging
import time
from pathlib import Path
from typing import TYPE_CHECKING, Optional

from graphsast.analysis.dedup import deduplicate
from graphsast.analysis.models import Finding
from graphsast.analysis.semgrep import run_semgrep
from graphsast.analysis.store import FindingStore

if TYPE_CHECKING:
    from graphsast.llm.base import LLMClient

logger = logging.getLogger(__name__)


def scan(
    target: Path,
    graph_db: Path,
    llm_client: Optional["LLMClient"] = None,
    semgrep_config: str = "auto",
    semgrep_timeout: int = 300,
    llm_max_turns: int = 15,
) -> tuple[list[Finding], dict]:
    """Run a full scan of *target*.

    Returns:
        (findings, summary_dict)
    """
    t0 = time.monotonic()
    model_name = getattr(llm_client, "model", None)

    # ── Step 1: Build code graph ───────────────────────────────────────────────
    logger.info("Building code graph for %s → %s", target, graph_db)
    _build_graph(target, graph_db)

    # ── Step 2: Semgrep ────────────────────────────────────────────────────────
    logger.info("Running Semgrep (config=%s) ...", semgrep_config)
    raw_findings = run_semgrep(target, config=semgrep_config, timeout=semgrep_timeout)
    semgrep_total = len(raw_findings)
    logger.info("Semgrep: %d findings", semgrep_total)

    # ── Step 3: Deduplicate ────────────────────────────────────────────────────
    raw_findings, n_dedup = deduplicate(raw_findings)
    if n_dedup:
        logger.info("Deduplicated %d findings (%d unique remain)", n_dedup, len(raw_findings))

    # ── Step 4: Persist + LLM analysis ────────────────────────────────────────
    findings: list[Finding] = []
    n_new = n_recurring = n_cache_hits = n_llm = 0

    with FindingStore(graph_db) as store:
        run_id = store.start_run(str(target), semgrep_config, model_name)

        if llm_client and raw_findings:
            from graphsast.analysis.analyst import analyse_finding
            from graphsast.graph.client import GraphClient

            logger.info(
                "LLM analysis: %d findings, model=%s, max_turns=%d",
                len(raw_findings), model_name, llm_max_turns,
            )

            with GraphClient(graph_db, target) as graph:
                for i, raw in enumerate(raw_findings, 1):
                    f = Finding.from_semgrep(raw)
                    _finding_id, is_new = store.upsert_finding(f, run_id)

                    if is_new:
                        n_new += 1
                    else:
                        n_recurring += 1

                    # Check for a valid cached verdict
                    cached = store.get_verdict(f.rule_id, f.file_path, f.line_start)

                    # Treat cache as stale if enrichment fields are missing (old-schema analysis)
                    cache_has_enrichment = cached and (
                        cached.get("cvss_score") is not None
                        or cached.get("description") is not None
                    )

                    if cache_has_enrichment:
                        logger.info(
                            "  [%d/%d] CACHED  %s @ %s:%s → %s",
                            i, len(raw_findings),
                            f.rule_id, f.file_path, f.line_start, cached["verdict"],
                        )
                        verdict = cached
                        n_cache_hits += 1
                    else:
                        if cached:
                            logger.info(
                                "  [%d/%d] RE-ANALYSE (enrichment missing)  %s @ %s:%s",
                                i, len(raw_findings),
                                f.rule_id, f.file_path, f.line_start,
                            )
                        else:
                            logger.info(
                                "  [%d/%d] ANALYSE %s @ %s:%s",
                                i, len(raw_findings),
                                f.rule_id, f.file_path, f.line_start,
                            )
                        verdict = analyse_finding(
                            raw, llm_client, graph, max_turns=llm_max_turns,
                        )
                        store.set_verdict(
                            f.rule_id, f.file_path, f.line_start,
                            verdict, model_name or "unknown",
                        )
                        n_llm += 1

                    f.llm_verdict      = verdict["verdict"]
                    f.llm_severity     = verdict["severity"]
                    f.llm_reasoning    = verdict["reasoning"]
                    f.llm_description  = verdict.get("description")
                    f.llm_poc          = verdict.get("poc")
                    f.llm_cvss_score   = verdict.get("cvss_score")
                    f.llm_cvss_vector  = verdict.get("cvss_vector")
                    findings.append(f)

        else:
            # No LLM — just persist findings for history tracking
            for raw in raw_findings:
                f = Finding.from_semgrep(raw)
                _finding_id, is_new = store.upsert_finding(f, run_id)
                n_new += int(is_new)
                n_recurring += int(not is_new)
                findings.append(f)

        # ── Step 5: Diff against previous run ─────────────────────────────────
        diff = store.compare_with_previous(run_id)
        n_fixed = len(diff["fixed"])

        elapsed = round(time.monotonic() - t0, 2)

        summary: dict = {
            "run_id":          run_id,
            "semgrep_findings": semgrep_total,
            "deduplicated":    n_dedup,
            "new_findings":    n_new,
            "recurring":       n_recurring,
            "fixed":           n_fixed,
            "cache_hits":      n_cache_hits,
            "llm_analysed":    n_llm,
            "confirmed":       sum(1 for f in findings if f.llm_verdict == "CONFIRMED"),
            "false_positives": sum(1 for f in findings if f.llm_verdict == "FALSE_POSITIVE"),
            "needs_review":    sum(1 for f in findings if f.llm_verdict == "NEEDS_REVIEW"),
            "elapsed_seconds": elapsed,
        }

        store.finish_run(run_id, summary)

    return findings, summary


# ── Graph build helper ─────────────────────────────────────────────────────────

def _build_graph(target: Path, graph_db: Path) -> None:
    """Build (or rebuild) the code graph using code_review_graph.

    Post-processing steps after core build:
      1. FTS5 index  — enables fast search_nodes() queries.
      2. Flow tracing — computes execution flows so get_flows() works.
    """
    from code_review_graph.flows import store_flows, trace_flows
    from code_review_graph.graph import GraphStore
    from code_review_graph.incremental import full_build
    from code_review_graph.search import rebuild_fts_index

    graph_db.parent.mkdir(parents=True, exist_ok=True)
    store = GraphStore(str(graph_db))
    store._conn.isolation_level = None   # autocommit — avoids nested-tx conflict
    try:
        result = full_build(target, store)
        logger.info(
            "Graph built: %d files, %d nodes, %d edges",
            result.get("files_parsed", 0),
            result.get("total_nodes", 0),
            result.get("total_edges", 0),
        )

        try:
            n = rebuild_fts_index(store)
            logger.info("FTS index: %d nodes indexed", n)
        except Exception as exc:
            logger.warning("FTS index failed (falling back to LIKE search): %s", exc)

        try:
            flows = trace_flows(store)
            stored = store_flows(store, flows)
            logger.info("Flow tracing: %d flows stored", stored)
        except Exception as exc:
            logger.warning("Flow tracing failed (get_flows will be empty): %s", exc)

    finally:
        store.close()
