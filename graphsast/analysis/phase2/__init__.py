"""Phase 2 — pattern matching passes."""
from .semgrep_runner import run_semgrep
from .taint_queries import run_taint_queries
from .structure import run_structure_analysis

__all__ = ["run_semgrep", "run_taint_queries", "run_structure_analysis"]

