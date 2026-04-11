"""Semgrep runner.

Runs semgrep against the target directory and returns structured findings.
No dependency on vuln_db — uses semgrep's own rule registry.
"""

from __future__ import annotations

import json
import logging
import subprocess
import sys
from pathlib import Path

logger = logging.getLogger(__name__)


def _semgrep_exe() -> str:
    """Return the semgrep executable path.

    Prefers the binary next to the running Python interpreter (i.e. the same
    venv), then falls back to whatever is on PATH.
    """
    venv_semgrep = Path(sys.executable).parent / "semgrep"
    if venv_semgrep.exists():
        return str(venv_semgrep)
    return "semgrep"


def run_semgrep(target: Path, config: str = "auto", timeout: int = 300) -> list[dict]:
    """Run semgrep against *target* and return raw finding dicts.

    Args:
        target:  Directory to scan.
        config:  Semgrep config string passed to ``--config``.
                 Use ``"auto"`` for the full registry, ``"p/default"`` for a
                 smaller curated set, or an absolute path to a local rules file.
        timeout: CLI timeout in seconds.

    Returns:
        List of raw semgrep result dicts (``results`` key from semgrep JSON output).
    """
    exe = _semgrep_exe()
    if not _semgrep_available(exe):
        logger.warning("semgrep not found (looked in venv and PATH) — skipping scan")
        return []

    cmd = [
        exe,
        "--config", config,
        "--json",
        "--quiet",
        str(target),
    ]

    logger.info("Running: %s", " ".join(cmd))

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            timeout=timeout,
        )
        # semgrep exits 1 when it finds issues — that is expected and not an error
        stdout = result.stdout.decode("utf-8", errors="replace").strip()
        if not stdout:
            logger.info("semgrep produced no output")
            return []

        data = json.loads(stdout)
        findings = data.get("results", [])
        errors = data.get("errors", [])

        if errors:
            logger.warning("semgrep reported %d errors", len(errors))

        logger.info("semgrep: %d findings", len(findings))
        return findings

    except subprocess.TimeoutExpired:
        logger.error("semgrep timed out after %ds", timeout)
        return []
    except json.JSONDecodeError as exc:
        logger.error("Failed to parse semgrep JSON output: %s", exc)
        return []
    except Exception as exc:
        logger.error("semgrep failed: %s", exc)
        return []


def _semgrep_available(exe: str = "semgrep") -> bool:
    try:
        subprocess.run(
            [exe, "--version"],
            capture_output=True,
            check=True,
            timeout=10,
        )
        return True
    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
        return False
