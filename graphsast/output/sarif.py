"""SARIF 2.1.0 output formatter."""

from __future__ import annotations

from pathlib import Path

from graphsast.analysis.models import Finding

_TOOL_NAME = "GraphSAST"
try:
    from importlib.metadata import version as _pkg_version
    _TOOL_VERSION = _pkg_version("graphsast")
except Exception:
    _TOOL_VERSION = "0.0.0"

_SEV_MAP = {
    "CRITICAL": "error",
    "HIGH":     "error",
    "MEDIUM":   "warning",
    "LOW":      "note",
}


def to_sarif(findings: list[Finding], target: Path) -> dict:
    rules: dict[str, dict] = {}
    results: list[dict] = []

    for f in findings:
        if f.is_false_positive:
            continue

        if f.rule_id not in rules:
            rules[f.rule_id] = {
                "id": f.rule_id,
                "name": f.title,
                "shortDescription": {"text": f.title},
                "fullDescription": {"text": f.message},
                "defaultConfiguration": {
                    "level": _SEV_MAP.get(f.effective_severity, "warning")
                },
                **({"properties": {"tags": [f.cwe_id]}} if f.cwe_id else {}),
            }

        try:
            uri = Path(f.file_path).relative_to(target).as_posix()
        except ValueError:
            uri = f.file_path

        message_text = f.message
        if f.llm_reasoning:
            message_text += f"\n\nLLM analysis: {f.llm_reasoning}"

        results.append({
            "ruleId": f.rule_id,
            "level": _SEV_MAP.get(f.effective_severity, "warning"),
            "message": {"text": message_text},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": uri, "uriBaseId": "%SRCROOT%"},
                    "region": {
                        "startLine": f.line_start or 1,
                        "endLine":   f.line_end or f.line_start or 1,
                    },
                }
            }],
        })

    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": _TOOL_NAME,
                    "version": _TOOL_VERSION,
                    "rules": list(rules.values()),
                }
            },
            "results": results,
        }],
    }
