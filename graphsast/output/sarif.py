"""SARIF 2.1.0 output formatter.

Produces a valid SARIF JSON document that can be imported into GitHub
Code Scanning, VS Code SARIF Viewer, and other SARIF consumers.

Spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from graphsast.analysis.phase3.correlator import Finding

_TOOL_NAME    = "GraphSAST"
_TOOL_VERSION = "0.1.0"
_TOOL_URI     = "https://github.com/your-org/graphsast"

# Map severity to SARIF level
_SEVERITY_TO_LEVEL = {
    "CRITICAL": "error",
    "HIGH":     "error",
    "MEDIUM":   "warning",
    "LOW":      "note",
    "INFO":     "none",
}

# Map confidence to SARIF rank (0.0 – 1.0)
_CONFIDENCE_TO_RANK = {
    "HIGH":   0.9,
    "MEDIUM": 0.6,
    "LOW":    0.3,
}


def to_sarif(
    findings: list[Finding],
    target: Path,
    scan_run_id: str = "",
) -> dict:
    """Convert correlated findings into a SARIF 2.1.0 document (dict).

    Call ``json.dumps(to_sarif(...), indent=2)`` to serialise.
    """
    rules = _build_rules(findings)
    results = [_finding_to_result(f, target) for f in findings]

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": _TOOL_NAME,
                        "version": _TOOL_VERSION,
                        "informationUri": _TOOL_URI,
                        "rules": rules,
                    }
                },
                "results": results,
                "automationDetails": {
                    "id": scan_run_id or "graphsast/scan",
                },
                "columnKind": "unicodeCodePoints",
            }
        ],
    }


# ──────────────────────────────────────────────────────────────────────────────

def _build_rules(findings: list[Finding]) -> list[dict]:
    """Deduplicated rule descriptors for the driver."""
    seen: dict[str, dict] = {}
    for f in findings:
        rule_id = _rule_id(f)
        if rule_id not in seen:
            seen[rule_id] = {
                "id": rule_id,
                "name": _sanitise_name(f.title),
                "shortDescription": {"text": f.title},
                "fullDescription": {"text": f.message or f.title},
                "defaultConfiguration": {
                    "level": _SEVERITY_TO_LEVEL.get(f.severity, "warning"),
                },
                "properties": {
                    "tags": _tags(f),
                    "precision": f.confidence.lower(),
                },
            }
            if f.cwe_id:
                seen[rule_id]["relationships"] = [
                    {
                        "target": {
                            "id": f.cwe_id,
                            "toolComponent": {"name": "CWE", "guid": _CWE_GUID},
                        },
                        "kinds": ["relevant"],
                    }
                ]
    return list(seen.values())


def _finding_to_result(f: Finding, target: Path) -> dict:
    rule_id = _rule_id(f)
    result: dict[str, Any] = {
        "ruleId": rule_id,
        "level": _SEVERITY_TO_LEVEL.get(f.severity, "warning"),
        "message": {"text": f.message or f.title},
        "rank": _CONFIDENCE_TO_RANK.get(f.confidence, 0.5),
        "properties": {
            "sources": f.sources,
            "severity": f.severity,
            "confidence": f.confidence,
        },
    }

    if f.file_path and f.line_start:
        try:
            rel = Path(f.file_path).relative_to(target)
            uri = rel.as_posix()
        except ValueError:
            uri = f.file_path

        result["locations"] = [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": uri, "uriBaseId": "%SRCROOT%"},
                    "region": {
                        "startLine": max(1, f.line_start),
                        "endLine": max(1, f.line_end or f.line_start),
                    },
                }
            }
        ]

    if f.qualified_name:
        result["logicalLocations"] = [
            {"fullyQualifiedName": f.qualified_name, "kind": "function"}
        ]

    return result


def _rule_id(f: Finding) -> str:
    base = f.cwe_id.replace("-", "_") if f.cwe_id else "UNKNOWN"
    suffix = f.sources[0] if f.sources else "graphsast"
    return f"GSAST/{base}/{suffix.upper()}"


def _sanitise_name(title: str) -> str:
    """PascalCase rule name for SARIF."""
    return "".join(w.title() for w in title.split() if w.isalnum() or w in "()/-")


def _tags(f: Finding) -> list[str]:
    tags = ["security"]
    if f.cwe_id:
        tags.append(f.cwe_id)
    tags.extend(f.sources)
    return tags


# GUID for CWE taxonomy (well-known)
_CWE_GUID = "FFC64C90-42B6-44CE-8BEB-F6B7DAE649E5"
