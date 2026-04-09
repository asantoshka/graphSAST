"""Custom YAML rules importer.

Loads vulnerability classes, detectors, and taint signatures from
.graphsast/custom/*.yaml (and any additional paths passed in).

YAML format example:

  id: sqli-concat-python
  cwe_id: CWE-89
  owasp_cat: A03
  name: SQL Injection via string concatenation
  language: python
  severity: CRITICAL
  description: >
    User-controlled input concatenated directly into a SQL query.

  taint_signatures:
    - id: py-sqli-sink-execute
      name: cursor.execute
      qualified_pattern: "cursor.execute"
      language: python
      sig_type: SINK
      cwe_ids: ["CWE-89"]
      description: psycopg2 / sqlite3 execute sink

  detectors:
    - id: py-sqli-semgrep
      detector_type: semgrep
      language: python
      confidence: HIGH
      content: |
        rules:
          - id: sqli-concat
            pattern: $CURSOR.execute($QUERY + ...)
            languages: [python]
            severity: ERROR
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import yaml

from graphsast.vuln_db.store import VulnStore

logger = logging.getLogger(__name__)


def load_custom_rules(vuln_db: VulnStore, rules_dirs: list[Path]) -> int:
    """Load all YAML files from the given directories into vuln_db.

    Returns the number of records inserted/updated.
    """
    total = 0
    for rules_dir in rules_dirs:
        if not rules_dir.exists():
            continue
        for yaml_file in sorted(rules_dir.glob("**/*.yaml")):
            try:
                count = _load_file(vuln_db, yaml_file)
                total += count
                logger.info("Loaded %d records from %s", count, yaml_file.name)
            except Exception as exc:
                logger.error("Failed to load %s: %s", yaml_file, exc)

    vuln_db.commit()
    return total


def _load_file(vuln_db: VulnStore, path: Path) -> int:
    with path.open() as f:
        data = yaml.safe_load(f)

    if not data:
        return 0

    # Support both a single rule dict and a list of rules
    if isinstance(data, list):
        rules = data
    else:
        rules = [data]

    count = 0
    for rule in rules:
        if not isinstance(rule, dict):
            continue
        count += _load_rule(vuln_db, rule, str(path))

    return count


def _load_rule(vuln_db: VulnStore, rule: dict[str, Any], source_path: str) -> int:
    """Load a single rule definition. Returns records written."""
    count = 0
    rule_id = rule.get("id")
    if not rule_id:
        logger.warning("Rule in %s has no 'id', skipping", source_path)
        return 0

    # Insert vuln_class if this rule defines one
    if rule.get("name"):
        vuln_db.upsert_vuln_class({
            "id": rule_id,
            "cwe_id": rule.get("cwe_id", ""),
            "owasp_cat": rule.get("owasp_cat", ""),
            "name": rule["name"],
            "description": rule.get("description", ""),
            "severity": rule.get("severity", "MEDIUM"),
            "language": rule.get("language", "any"),
            "source": "custom",
        })
        count += 1

    # Load taint_signatures
    for sig in rule.get("taint_signatures", []):
        sig["vuln_class_id"] = sig.get("vuln_class_id", rule_id)
        sig["source"] = "custom"
        vuln_db.upsert_taint_signature(sig)
        count += 1

    # Load detectors
    for det in rule.get("detectors", []):
        det["vuln_class_id"] = det.get("vuln_class_id", rule_id)
        det["source"] = "custom"
        vuln_db.upsert_detector(det)
        count += 1

    # Shorthand: top-level taint_signatures list (flat format)
    for sig in rule.get("sinks", []):
        sig.setdefault("id", f"{rule_id}-sink-{sig.get('name', 'unknown')}")
        sig["sig_type"] = "SINK"
        sig["vuln_class_id"] = rule_id
        sig["source"] = "custom"
        vuln_db.upsert_taint_signature(sig)
        count += 1

    for sig in rule.get("sources", []):
        sig.setdefault("id", f"{rule_id}-source-{sig.get('name', 'unknown')}")
        sig["sig_type"] = "SOURCE"
        sig["vuln_class_id"] = rule_id
        sig["source"] = "custom"
        vuln_db.upsert_taint_signature(sig)
        count += 1

    for sig in rule.get("sanitizers", []):
        sig.setdefault("id", f"{rule_id}-sanitizer-{sig.get('name', 'unknown')}")
        sig["sig_type"] = "SANITIZER"
        sig["vuln_class_id"] = rule_id
        sig["source"] = "custom"
        vuln_db.upsert_taint_signature(sig)
        count += 1

    return count
