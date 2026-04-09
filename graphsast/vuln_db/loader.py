"""VulnDB loader — orchestrates all importers."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional

from .store import VulnStore

logger = logging.getLogger(__name__)


def load_all(
    vuln_db: VulnStore,
    project_root: Path,
    sources: list[str] | None = None,
    semgrep_rules_path: Optional[Path] = None,
    semgrep_update: bool = True,
) -> dict:
    """Run all (or selected) loaders and return a summary dict.

    Always loads built-in language rules first so custom rules can override them.

    Recognised source names:
      builtin    — built-in language/arg-node-type rules
      custom     — project-local / home-dir YAML overrides
      semgrep    — semgrep/semgrep-rules OSS registry
      wstg       — OWASP Web Security Testing Guide (embedded, no network)
      lang_sigs  — JS/TypeScript (Node.js/Express) and C# taint signatures
    """
    if sources is None:
        sources = ["builtin", "custom", "semgrep", "wstg", "lang_sigs"]

    results: dict[str, int] = {}

    # Built-in language rules always run first (idempotent)
    if "builtin" in sources or "custom" in sources:
        from graphsast.vuln_db.importers.builtin_lang_rules import load_builtin_lang_rules
        counts = load_builtin_lang_rules(vuln_db)
        results["builtin_lang_rules"] = sum(counts.values())
        logger.info(
            "Built-in lang rules: %d arg_node_types, %d ep_patterns, %d capabilities",
            counts["arg_node_types"], counts["entry_point_patterns"],
            counts["language_capabilities"],
        )

    if "custom" in sources:
        from graphsast.vuln_db.importers.custom import load_custom_rules
        dirs = [
            project_root / ".graphsast" / "custom",
            Path.home() / ".graphsast" / "custom",
        ]
        count = load_custom_rules(vuln_db, dirs)
        results["custom"] = count
        logger.info("Custom loader: %d records", count)

    if "semgrep" in sources:
        from graphsast.vuln_db.importers.semgrep import load_semgrep_rules
        counts = load_semgrep_rules(
            vuln_db,
            rules_path=semgrep_rules_path,
            update=semgrep_update,
        )
        results["semgrep"] = counts["rules_imported"]
        logger.info(
            "Semgrep loader: %d imported, %d skipped",
            counts["rules_imported"], counts["rules_skipped"],
        )

    if "wstg" in sources:
        from graphsast.vuln_db.importers.owasp_wstg import load_owasp_wstg
        counts = load_owasp_wstg(vuln_db)
        results["wstg_vuln_classes"]      = counts["vuln_classes"]
        results["wstg_taint_signatures"]  = counts["taint_signatures"]
        logger.info(
            "OWASP WSTG loader: %d vuln_classes, %d taint_signatures",
            counts["vuln_classes"], counts["taint_signatures"],
        )

    if "lang_sigs" in sources:
        from graphsast.vuln_db.importers.lang_sigs import load_lang_sigs
        counts = load_lang_sigs(vuln_db)
        results["lang_sigs"] = counts["taint_signatures"]
        logger.info(
            "Lang sigs loader: %d taint_signatures (JS/TS/C#)",
            counts["taint_signatures"],
        )

    return results
