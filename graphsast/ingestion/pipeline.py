"""Ingestion pipeline — builds / updates the security-annotated code graph.

Orchestrates four passes per file:
  1. Structural extraction (base code-review-graph parser)
  2. AST argument structure (ArgInspector)
  3. Taint annotation (TaintMarker, after all files are parsed)
  4. Missing check detection (MissingCheckDetector, after taint annotation)
"""

from __future__ import annotations

import hashlib
import logging
import time
from pathlib import Path
from typing import Optional

from code_review_graph.parser import CodeParser

from graphsast.graph_db.store import SecurityGraphStore
from graphsast.ingestion.arg_inspector import ArgInspector
from graphsast.ingestion.missing_edges import MissingCheckDetector
from graphsast.ingestion.taint_markers import TaintMarker
from graphsast.vuln_db.store import VulnStore

logger = logging.getLogger(__name__)

# File extensions we process
SUPPORTED_EXTENSIONS = {
    ".py", ".js", ".ts", ".tsx", ".jsx", ".go", ".java",
    ".cs", ".rb", ".php", ".kt", ".swift", ".rs",
}

# Paths to skip
SKIP_DIRS = {
    ".git", "__pycache__", "node_modules", ".venv", "venv",
    "env", ".env", "dist", "build", ".mypy_cache", ".pytest_cache",
}


class IngestionPipeline:
    """Runs the full 4-pass ingestion against a target directory."""

    def __init__(
        self,
        graph: SecurityGraphStore,
        vuln_db: Optional[VulnStore] = None,
        incremental: bool = True,
    ) -> None:
        self.graph = graph
        self.vuln_db = vuln_db
        self.incremental = incremental
        self._parser = CodeParser()
        self._arg_inspector = ArgInspector(vuln_db=vuln_db)

    def run(self, target: Path) -> dict:
        """Run all ingestion passes against target directory.

        Returns a summary dict with counts.
        """
        start = time.time()
        target = target.resolve()

        files = self._collect_files(target)
        logger.info("Ingestion: found %d source files in %s", len(files), target)

        parsed = 0
        skipped = 0
        call_arg_records = 0

        # ── Pass 1+2: structural extraction + arg inspection (per file) ──
        for file_path in files:
            try:
                result = self._process_file(file_path)
                if result is None:
                    skipped += 1
                else:
                    parsed += 1
                    call_arg_records += result
            except Exception as exc:
                logger.error("Error processing %s: %s", file_path, exc)

        self.graph.commit()

        # ── Pass 3: taint annotation (whole graph) ──
        taint_count = 0
        ep_count = 0
        if self.vuln_db:
            marker = TaintMarker(self.graph, vuln_db=self.vuln_db)
            taint_count = marker.annotate_all(self.vuln_db)
            ep_count = marker.detect_entry_points()
        else:
            logger.warning("No vuln_db provided — skipping taint annotation pass")

        # ── Pass 4: missing check detection ──
        missing_count = 0
        if ep_count > 0:
            detector = MissingCheckDetector(self.graph)
            missing_count = detector.detect_all()

        elapsed = time.time() - start
        summary = {
            "files_processed": parsed,
            "files_skipped": skipped,
            "call_arg_records": call_arg_records,
            "taint_annotations": taint_count,
            "entry_points": ep_count,
            "missing_checks": missing_count,
            "elapsed_seconds": round(elapsed, 2),
        }
        logger.info("Ingestion complete: %s", summary)
        return summary

    def _collect_files(self, root: Path) -> list[Path]:
        files = []
        for path in root.rglob("*"):
            if not path.is_file():
                continue
            if any(part in SKIP_DIRS for part in path.parts):
                continue
            if path.suffix.lower() not in SUPPORTED_EXTENSIONS:
                continue
            files.append(path)
        return sorted(files)

    def _process_file(self, file_path: Path) -> Optional[int]:
        """Process a single file. Returns number of call_arg records, or None if skipped."""
        try:
            source = file_path.read_bytes()
        except (OSError, PermissionError):
            return None

        fhash = hashlib.sha256(source).hexdigest()

        # Incremental: skip if hash unchanged
        if self.incremental:
            existing = self.graph._conn.execute(
                "SELECT file_hash FROM nodes WHERE file_path = ? AND kind = 'File' LIMIT 1",
                (str(file_path),),
            ).fetchone()
            if existing and existing["file_hash"] == fhash:
                return None

        language = self._parser.detect_language(file_path)
        if not language:
            return None

        # Pass 1: structural extraction via base parser
        nodes, edges = self._parser.parse_bytes(file_path, source)
        self.graph.store_file_nodes_edges(str(file_path), nodes, edges, fhash=fhash)

        # Pass 2: AST argument structure inspection
        calls_edges = [
            (e.source, e.target, e.line)
            for e in edges
            if e.kind == "CALLS"
        ]
        if calls_edges:
            call_args = self._arg_inspector.inspect_file(
                str(file_path), source, language, calls_edges
            )
            if call_args:
                self.graph.delete_call_args_for_file(str(file_path))
                self.graph.upsert_call_args(call_args)
            return len(call_args)

        return 0
