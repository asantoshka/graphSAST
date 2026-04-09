"""GraphSAST settings loader.

Loads configuration from (highest priority last):
  1. Hardcoded defaults (in this file)
  2. ~/.graphsast/config.toml  (user-level)
  3. <project>/.graphsast/config.toml  (project-level, wins over user)
  4. Environment variables: GRAPHSAST_<SECTION>__<KEY>  (wins over files)
  5. CLI flags (handled in cli/main.py by passing explicit values)

Example config.toml:
  [llm]
  model   = "qwen2.5:14b"
  timeout = 300.0

  [analysis]
  phase1a_max_turns = 10

  [output]
  format = "json"

Usage:
  from graphsast.config import get_settings
  cfg = get_settings(project_root=Path("."))
  print(cfg.llm.model)
"""

from __future__ import annotations

import tomllib
from pathlib import Path
from typing import Optional

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


# ──────────────────────────────────────────────────────────────────────────────
# Sub-sections
# ──────────────────────────────────────────────────────────────────────────────

class LLMSettings(BaseSettings):
    """Ollama / LLM backend settings."""
    model_config = SettingsConfigDict(env_prefix="GRAPHSAST_LLM__")

    backend:  str = Field("ollama", description="LLM backend: 'ollama' or 'claude'")
    base_url: str = Field("http://localhost:11434", description="Ollama server base URL (ollama backend only)")
    model:    str = Field("llama3.1",              description="Model name (ollama: e.g. llama3.1; claude: e.g. claude-opus-4-6)")
    claude_api_key: Optional[str] = Field(None,    description="Anthropic API key (claude backend; falls back to ANTHROPIC_API_KEY env var)")
    timeout:  float = Field(300.0,                 description="Per-request timeout in seconds")
    temperature: float = Field(0.1,                description="Sampling temperature (0.0–1.0)")
    num_ctx:  int = Field(8192,                    description="Context window size (tokens)")
    health_check_timeout: float = Field(5.0,       description="Timeout for Ollama availability probe")
    max_entry_points: int = Field(0,               description="Max entry points for Phase 1A (0 = all)")
    phase1a_max_turns: int = Field(8,              description="Max LLM turns in Phase 1A per entry point")
    phase1b_max_turns_l2: int = Field(5,           description="Max turns for Phase 1B layer-2 validation")
    phase1b_max_turns_l3: int = Field(3,           description="Max turns for Phase 1B layer-3 micro-task")


class VulnDBSettings(BaseSettings):
    """Vulnerability database loader settings."""
    model_config = SettingsConfigDict(env_prefix="GRAPHSAST_VULNDB__")

    sources: list[str] = Field(
        default=["builtin", "custom", "semgrep", "wstg", "lang_sigs"],
        description="Ordered list of loaders to run when updating vulns.db",
    )
    semgrep_rules_repo: str = Field(
        "https://github.com/semgrep/semgrep-rules",
        description="Git remote for the semgrep rules registry",
    )
    semgrep_cache_dir: Optional[Path] = Field(
        None,
        description="Local path for the semgrep-rules clone (None = ~/.graphsast/cache/semgrep-rules)",
    )


class SemgrepSettings(BaseSettings):
    """Semgrep runner settings."""
    model_config = SettingsConfigDict(env_prefix="GRAPHSAST_SEMGREP__")

    rules_per_file: int = Field(200,  description="Rules bundled per temp file (batching)")
    timeout:        int = Field(300,  description="Semgrep CLI execution timeout in seconds")
    message_max_len: int = Field(500, description="Truncate semgrep rule message to this many characters")


class AnalysisSettings(BaseSettings):
    """Core analysis pipeline settings."""
    model_config = SettingsConfigDict(env_prefix="GRAPHSAST_ANALYSIS__")

    taint_max_depth:    int = Field(10, description="Maximum BFS hops when finding source→sink taint paths")
    line_bucket_size:   int = Field(5,  description="Lines window for deduplicating co-located findings")


class OutputSettings(BaseSettings):
    """Report output settings."""
    model_config = SettingsConfigDict(env_prefix="GRAPHSAST_OUTPUT__")

    format: str = Field("markdown", description="Default report format: markdown | json | sarif")


class PathSettings(BaseSettings):
    """Filesystem path settings."""
    model_config = SettingsConfigDict(env_prefix="GRAPHSAST_PATHS__")

    db_subdir: str = Field(".graphsast", description="Subdirectory name created inside the scan target for DBs")


# ──────────────────────────────────────────────────────────────────────────────
# Root settings
# ──────────────────────────────────────────────────────────────────────────────

class GraphSASTSettings(BaseSettings):
    """Root settings object.  Compose via get_settings(project_root=...)."""

    llm:      LLMSettings      = Field(default_factory=LLMSettings)
    vulndb:   VulnDBSettings   = Field(default_factory=VulnDBSettings)
    semgrep:  SemgrepSettings  = Field(default_factory=SemgrepSettings)
    analysis: AnalysisSettings = Field(default_factory=AnalysisSettings)
    output:   OutputSettings   = Field(default_factory=OutputSettings)
    paths:    PathSettings     = Field(default_factory=PathSettings)


# ──────────────────────────────────────────────────────────────────────────────
# TOML file loader helper
# ──────────────────────────────────────────────────────────────────────────────

def _load_toml(path: Path) -> dict:
    """Load a TOML file, returning empty dict if missing or malformed."""
    if not path.exists():
        return {}
    try:
        with open(path, "rb") as f:
            return tomllib.load(f)
    except Exception:
        return {}


def _merge(base: dict, override: dict) -> dict:
    """Deep-merge two dicts (override wins on conflicts)."""
    result = dict(base)
    for key, val in override.items():
        if isinstance(val, dict) and isinstance(result.get(key), dict):
            result[key] = _merge(result[key], val)
        else:
            result[key] = val
    return result


# ──────────────────────────────────────────────────────────────────────────────
# Public API
# ──────────────────────────────────────────────────────────────────────────────

def get_settings(project_root: Path | None = None) -> GraphSASTSettings:
    """Return a GraphSASTSettings instance for the given project root.

    Config is layered:
      defaults → ~/.graphsast/config.toml → <project>/.graphsast/config.toml
      → GRAPHSAST_* env vars

    Args:
        project_root: Path to the project being scanned.  When provided the
                      project-local config.toml is layered on top of the user
                      global one.  Pass None to use defaults + user config only.

    Returns:
        Fully resolved GraphSASTSettings.
    """
    # 1. User-global config
    user_cfg = _load_toml(Path.home() / ".graphsast" / "config.toml")

    # 2. Project-local config (overrides user)
    project_cfg: dict = {}
    if project_root is not None:
        project_cfg = _load_toml(Path(project_root) / ".graphsast" / "config.toml")

    merged = _merge(user_cfg, project_cfg)

    # 3. Build sub-settings from merged TOML, then let env vars win via pydantic-settings
    kwargs: dict = {}

    if "llm" in merged:
        kwargs["llm"] = LLMSettings(**merged["llm"])
    if "vulndb" in merged:
        kwargs["vulndb"] = VulnDBSettings(**merged["vulndb"])
    if "semgrep" in merged:
        kwargs["semgrep"] = SemgrepSettings(**merged["semgrep"])
    if "analysis" in merged:
        kwargs["analysis"] = AnalysisSettings(**merged["analysis"])
    if "output" in merged:
        kwargs["output"] = OutputSettings(**merged["output"])
    if "paths" in merged:
        kwargs["paths"] = PathSettings(**merged["paths"])

    return GraphSASTSettings(**kwargs)
