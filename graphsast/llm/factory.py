"""LLM client factory.

Creates the right LLMClient subclass based on the active configuration.

Usage:
    from graphsast.config import get_settings
    from graphsast.llm.factory import get_llm_client

    cfg = get_settings(project_root=target)
    with get_llm_client(cfg) as llm:
        if llm.is_available():
            results = run_phase1a(graph, llm, ...)
"""

from __future__ import annotations

from graphsast.llm.base import LLMClient


def get_llm_client(cfg: "GraphSASTSettings") -> LLMClient:  # type: ignore[name-defined]
    """Instantiate an LLMClient from the active GraphSASTSettings.

    Args:
        cfg: Resolved GraphSASTSettings (from graphsast.config.get_settings).

    Returns:
        A ready-to-use LLMClient.  Use as a context manager to ensure
        resources are released::

            with get_llm_client(cfg) as client:
                ...

    Raises:
        ValueError: If cfg.llm.backend is not a recognised value.
        ImportError: If the required package is missing for the chosen backend
                     ('anthropic' for claude/bedrock, 'openai' for openai).
    """
    backend = cfg.llm.backend.lower()

    if backend == "ollama":
        from graphsast.llm.ollama_client import OllamaClient
        return OllamaClient(
            base_url=cfg.llm.base_url,
            model=cfg.llm.model,
            timeout=cfg.llm.timeout,
            temperature=cfg.llm.temperature,
            num_ctx=cfg.llm.num_ctx,
            health_check_timeout=cfg.llm.health_check_timeout,
        )

    if backend == "claude":
        from graphsast.llm.claude_client import ClaudeClient
        # model default: use config value if user set it, otherwise fall back
        # to the Claude default so users who only set backend="claude" get
        # claude-opus-4-6 without needing to also set model=.
        from graphsast.llm.claude_client import DEFAULT_MODEL as _CLAUDE_DEFAULT
        model = cfg.llm.model if cfg.llm.model != "llama3.1" else _CLAUDE_DEFAULT
        return ClaudeClient(
            model=model,
            api_key=cfg.llm.claude_api_key,   # None → reads ANTHROPIC_API_KEY
            temperature=cfg.llm.temperature,
            timeout=cfg.llm.timeout,
        )

    if backend == "openai":
        from graphsast.llm.openai_client import OpenAIClient
        from graphsast.llm.openai_client import DEFAULT_MODEL as _OPENAI_DEFAULT
        model = cfg.llm.model if cfg.llm.model != "llama3.1" else _OPENAI_DEFAULT
        return OpenAIClient(
            api_key=cfg.llm.openai_api_key,   # None → reads OPENAI_API_KEY
            model=model,
            temperature=cfg.llm.temperature,
            timeout=cfg.llm.timeout,
        )

    if backend == "bedrock":
        from graphsast.llm.bedrock_client import BedrockClient
        from graphsast.llm.bedrock_client import DEFAULT_MODEL as _BEDROCK_DEFAULT
        model = cfg.llm.model if cfg.llm.model != "llama3.1" else _BEDROCK_DEFAULT
        return BedrockClient(
            model=model,
            aws_region=cfg.llm.bedrock_region,
            aws_access_key=cfg.llm.bedrock_access_key,
            aws_secret_key=cfg.llm.bedrock_secret_key,
            aws_session_token=cfg.llm.bedrock_session_token,
            temperature=cfg.llm.temperature,
            timeout=cfg.llm.timeout,
        )

    raise ValueError(
        f"Unknown LLM backend: '{cfg.llm.backend}'.  "
        "Valid values: 'ollama', 'claude', 'openai', 'bedrock'."
    )
