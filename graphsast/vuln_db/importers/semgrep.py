"""Semgrep registry importer.

Clones (or updates) the semgrep/semgrep-rules repository and imports all
security rules (those with CWE metadata) into vulns.db.

Each Semgrep rule becomes:
  - One vuln_class row  (id, cwe_id, owasp_cat, name, severity, language)
  - One detector row    (type=semgrep, content=full rule YAML, confidence)

Rules without CWE tags are skipped — they are not security-relevant.

Usage:
  graphsast update-vuln-db --source semgrep
  graphsast update-vuln-db --source semgrep --semgrep-rules-path /path/to/local/clone
"""

from __future__ import annotations

import logging
import os
import re
import subprocess
from pathlib import Path
from typing import Any

import yaml

from graphsast.vuln_db.store import VulnStore

logger = logging.getLogger(__name__)

SEMGREP_RULES_REPO = "https://github.com/semgrep/semgrep-rules"
DEFAULT_CACHE_DIR   = Path.home() / ".graphsast" / "cache" / "semgrep-rules"

# Semgrep severity → GraphSAST severity
_SEVERITY_MAP = {
    "ERROR":   "HIGH",
    "WARNING": "MEDIUM",
    "INFO":    "LOW",
}

# OWASP category extraction: grab the A-code from strings like "A03:2021 - Injection"
_OWASP_RE = re.compile(r"(A\d{2})")


def load_semgrep_rules(
    vuln_db: VulnStore,
    rules_path: Path | None = None,
    update: bool = True,
) -> dict[str, int]:
    """Import Semgrep security rules into vuln_db.

    Args:
        vuln_db: target VulnStore
        rules_path: path to local semgrep-rules clone.
                    Defaults to ~/.graphsast/cache/semgrep-rules.
        update: if True and the repo exists, run `git pull` to refresh it.

    Returns:
        dict with counts: rules_found, rules_imported, rules_skipped
    """
    path = rules_path or DEFAULT_CACHE_DIR

    if not path.exists():
        logger.info("Cloning semgrep-rules to %s ...", path)
        _clone_repo(path)
    elif update:
        logger.info("Updating semgrep-rules at %s ...", path)
        _pull_repo(path)

    yaml_files = list(path.rglob("*.yaml")) + list(path.rglob("*.yml"))
    logger.info("Found %d YAML files in semgrep-rules", len(yaml_files))

    counts = {"rules_found": 0, "rules_imported": 0, "rules_skipped": 0}

    for yaml_file in yaml_files:
        # Skip non-rule files
        if yaml_file.name in ("metadata-schema.yaml.schm", "template.yaml"):
            continue
        try:
            _process_file(vuln_db, yaml_file, counts)
        except Exception as exc:
            logger.debug("Skipping %s: %s", yaml_file.name, exc)

    vuln_db.commit()
    logger.info(
        "Semgrep import complete: %d found, %d imported, %d skipped",
        counts["rules_found"], counts["rules_imported"], counts["rules_skipped"],
    )
    return counts


def _process_file(vuln_db: VulnStore, path: Path, counts: dict) -> None:
    with path.open(encoding="utf-8", errors="replace") as f:
        data = yaml.safe_load(f)

    if not data or not isinstance(data, dict):
        return
    rules = data.get("rules")
    if not rules or not isinstance(rules, list):
        return

    for rule in rules:
        if not isinstance(rule, dict):
            continue
        counts["rules_found"] += 1

        try:
            imported = _import_rule(vuln_db, rule, path)
            if imported:
                counts["rules_imported"] += 1
            else:
                counts["rules_skipped"] += 1
        except Exception as exc:
            logger.debug("Failed to import rule %s: %s", rule.get("id"), exc)
            counts["rules_skipped"] += 1


def _import_rule(vuln_db: VulnStore, rule: dict, source_file: Path) -> bool:
    """Import a single Semgrep rule. Returns True if imported, False if skipped."""
    rule_id = rule.get("id", "").strip()
    if not rule_id:
        return False

    meta = rule.get("metadata") or {}

    # Only import security rules with CWE tags
    cwe_raw = meta.get("cwe")
    if not cwe_raw and meta.get("category") != "security":
        return False

    cwe_ids  = _parse_cwe_list(cwe_raw)
    primary_cwe = cwe_ids[0] if cwe_ids else ""

    languages = rule.get("languages") or ["any"]
    # For multi-language rules, create one entry per language
    # (keeps the language field clean for filtering)
    primary_lang = languages[0] if languages else "any"

    owasp_raw = meta.get("owasp") or []
    owasp_cat = _parse_owasp(owasp_raw)

    severity = _SEVERITY_MAP.get(
        (rule.get("severity") or "WARNING").upper(), "MEDIUM"
    )
    # Boost to CRITICAL for known high-impact CWEs
    if primary_cwe in _CRITICAL_CWES:
        severity = "CRITICAL"

    confidence = _map_confidence(meta.get("confidence", "MEDIUM"))

    # vuln_class (one per rule, keyed on semgrep rule id)
    vc_id = f"semgrep-{rule_id}"
    vuln_db.upsert_vuln_class({
        "id": vc_id,
        "cwe_id": primary_cwe,
        "owasp_cat": owasp_cat,
        "name": _make_name(rule_id, primary_cwe),
        "description": (rule.get("message") or "")[:500],
        "severity": severity,
        "language": primary_lang,
        "source": "semgrep",
    })

    # detector — store the full rule content as YAML so the Phase 2 runner
    # can write it to a temp file and pass it to `semgrep --config`
    rule_yaml = yaml.dump({"rules": [rule]}, default_flow_style=False, allow_unicode=True)
    vuln_db.upsert_detector({
        "id": f"semgrep-det-{rule_id}",
        "vuln_class_id": vc_id,
        "detector_type": "semgrep",
        "content": rule_yaml,
        "language": primary_lang,
        "confidence": confidence,
    })

    return True


# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────

def _parse_cwe_list(raw: Any) -> list[str]:
    """Normalise CWE field to list of 'CWE-XX' strings."""
    if not raw:
        return []
    if isinstance(raw, str):
        raw = [raw]
    result = []
    for item in raw:
        m = re.search(r"CWE-(\d+)", str(item), re.IGNORECASE)
        if m:
            result.append(f"CWE-{m.group(1)}")
    return result


def _parse_owasp(raw: Any) -> str:
    """Extract OWASP category code like 'A03' from a string or list."""
    if not raw:
        return ""
    items = raw if isinstance(raw, list) else [raw]
    for item in items:
        m = _OWASP_RE.search(str(item))
        if m:
            return m.group(1)
    return ""


def _make_name(rule_id: str, cwe_id: str) -> str:
    """Generate a human-readable name from the rule id."""
    # "python.django.security.injection.sql-injection" → "SQL Injection (Django/Python)"
    parts = rule_id.replace("-", " ").replace(".", " ").split()
    # Remove common noise words
    noise = {"python", "java", "javascript", "go", "ruby", "php",
             "security", "vuln", "detect", "semgrep"}
    clean = [p.title() for p in parts if p.lower() not in noise]
    name = " ".join(clean[:6]) if clean else rule_id
    if cwe_id:
        name = f"{name} ({cwe_id})"
    return name[:120]


def _map_confidence(raw: str) -> str:
    mapping = {"HIGH": "HIGH", "MEDIUM": "MEDIUM", "LOW": "LOW"}
    return mapping.get((raw or "").upper(), "MEDIUM")


def _clone_repo(dest: Path) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        ["git", "clone", "--depth=1", SEMGREP_RULES_REPO, str(dest)],
        check=True,
        capture_output=True,
    )


def _pull_repo(path: Path) -> None:
    try:
        subprocess.run(
            ["git", "-C", str(path), "pull", "--ff-only"],
            check=True,
            capture_output=True,
            timeout=60,
        )
    except subprocess.CalledProcessError as exc:
        logger.warning("git pull failed (using existing clone): %s", exc.stderr.decode()[:200])


# High-impact CWEs that should always be CRITICAL regardless of Semgrep severity
_CRITICAL_CWES = {
    "CWE-89",   # SQL Injection
    "CWE-78",   # OS Command Injection
    "CWE-94",   # Code Injection
    "CWE-502",  # Deserialization
    "CWE-918",  # SSRF
    "CWE-611",  # XXE
    "CWE-434",  # Unrestricted File Upload
}
