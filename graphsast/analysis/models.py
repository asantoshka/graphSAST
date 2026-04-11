"""Core data models for GraphSAST findings."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class Finding:
    """A single security finding from Semgrep, optionally enriched by LLM analysis."""

    rule_id: str
    title: str
    message: str
    severity: str           # CRITICAL | HIGH | MEDIUM | LOW
    file_path: str
    line_start: int
    line_end: int
    cwe_id: str = ""
    snippet: str = ""       # code snippet at the finding location

    # LLM-populated fields (None when LLM not run)
    llm_verdict: Optional[str] = None      # CONFIRMED | FALSE_POSITIVE | NEEDS_REVIEW
    llm_severity: Optional[str] = None     # LLM-adjusted severity (may differ from semgrep)
    llm_reasoning: Optional[str] = None
    llm_description: Optional[str] = None  # detailed vulnerability description
    llm_poc: Optional[str] = None          # proof-of-concept / exploit scenario
    llm_cvss_score: Optional[float] = None # CVSS v3.1 base score (0.0–10.0)
    llm_cvss_vector: Optional[str] = None  # e.g. CVSS:3.1/AV:N/AC:L/...

    @property
    def effective_severity(self) -> str:
        """Use LLM severity if available, otherwise semgrep severity."""
        return self.llm_severity or self.severity

    @property
    def is_false_positive(self) -> bool:
        return self.llm_verdict == "FALSE_POSITIVE"

    @classmethod
    def from_semgrep(cls, raw: dict) -> "Finding":
        check_id = raw.get("check_id", "unknown")
        extra = raw.get("extra", {})
        start = raw.get("start", {})
        end = raw.get("end", {})
        meta = extra.get("metadata", {})

        # Derive a human title from the rule id
        title_parts = check_id.split(".")
        title = title_parts[-1].replace("-", " ").replace("_", " ").title()

        severity_raw = (extra.get("severity") or "MEDIUM").upper()
        severity = _normalise_severity(severity_raw)

        cwe_raw = meta.get("cwe", "")
        if isinstance(cwe_raw, list):
            cwe_raw = cwe_raw[0] if cwe_raw else ""
        cwe_id = str(cwe_raw)

        return cls(
            rule_id=check_id,
            title=title,
            message=(extra.get("message") or "")[:500],
            severity=severity,
            file_path=raw.get("path", ""),
            line_start=start.get("line", 0),
            line_end=end.get("line", start.get("line", 0)),
            cwe_id=cwe_id,
            snippet=(extra.get("lines") or "").strip()[:300],
        )


def _normalise_severity(raw: str) -> str:
    return {
        "CRITICAL": "CRITICAL",
        "ERROR":    "HIGH",
        "HIGH":     "HIGH",
        "WARNING":  "MEDIUM",
        "MEDIUM":   "MEDIUM",
        "INFO":     "LOW",
        "LOW":      "LOW",
    }.get(raw.upper(), "MEDIUM")
