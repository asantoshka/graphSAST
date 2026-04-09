"""Abstract LLM client interface.

All LLM backends (Ollama, Claude, …) implement this interface so that
Phase 1A / 1B analysis code is backend-agnostic.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Callable


class LLMClient(ABC):
    """Common interface for all LLM backends used by GraphSAST."""

    # ── Health ────────────────────────────────────────────────────────────────

    @abstractmethod
    def is_available(self) -> bool:
        """Return True if the backend is reachable and the configured model is ready."""

    @abstractmethod
    def list_models(self) -> list[str]:
        """Return names of models available on this backend (best-effort)."""

    # ── Core call ─────────────────────────────────────────────────────────────

    @abstractmethod
    def chat(
        self,
        messages: list[dict],
        tools: list[dict] | None = None,
        max_tokens: int = 2048,
    ) -> dict:
        """Single chat completion.

        Args:
            messages:   Conversation history in OpenAI message format.
            tools:      Optional list of tool schemas (OpenAI function format).
            max_tokens: Maximum tokens to generate.

        Returns:
            A response dict in OpenAI-compat format:
            ``{"choices": [{"message": {...}, "finish_reason": "stop"|"tool_calls"}]}``
        """

    # ── Agentic loop ──────────────────────────────────────────────────────────

    @abstractmethod
    def run_loop(
        self,
        messages: list[dict],
        tool_schemas: list[dict],
        tool_executor: Callable[[str, dict], str],
        max_turns: int = 8,
        max_tokens: int = 2048,
    ) -> tuple[list[dict], int]:
        """Run a ReAct tool-use loop until the model stops calling tools.

        Args:
            messages:       Conversation so far (mutated in-place).
            tool_schemas:   OpenAI-format tool definitions.
            tool_executor:  ``fn(tool_name, tool_args_dict) -> result_str``
            max_turns:      Maximum assistant turns before stopping.
            max_tokens:     Max tokens per assistant response.

        Returns:
            ``(updated_messages, turns_used)``
        """

    # ── Context manager ───────────────────────────────────────────────────────

    @abstractmethod
    def close(self) -> None:
        """Release any held resources (HTTP connections, SDK clients, …)."""

    def __enter__(self) -> "LLMClient":
        return self

    def __exit__(self, *_: Any) -> None:
        self.close()
