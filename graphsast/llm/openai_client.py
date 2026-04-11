"""OpenAI backend for GraphSAST LLM analysis.

Implements the same LLMClient interface as OllamaClient / ClaudeClient so
Phase 1A / 1B analysis works with any backend without modification.

Since Ollama already speaks the OpenAI wire format, this client is very close
to OllamaClient but uses the official openai Python SDK directly.

Requires:
  pip install openai>=1.30.0
  OPENAI_API_KEY env var  (or pass api_key= explicitly)
"""

from __future__ import annotations

import json
import logging
from typing import Any, Callable

from graphsast.llm.base import LLMClient

logger = logging.getLogger(__name__)

DEFAULT_MODEL   = "gpt-4o"
DEFAULT_TIMEOUT = 300.0


class OpenAIClient(LLMClient):
    """OpenAI backend.  Drop-in replacement for OllamaClient / ClaudeClient."""

    def __init__(
        self,
        api_key: str | None = None,
        model: str = DEFAULT_MODEL,
        temperature: float = 0.1,
        timeout: float = DEFAULT_TIMEOUT,
    ) -> None:
        """
        Args:
            api_key:     OpenAI API key.  Falls back to OPENAI_API_KEY env var.
            model:       Model ID (default: gpt-4o).
            temperature: Sampling temperature.
            timeout:     HTTP request timeout in seconds.
        """
        try:
            import openai as _openai
        except ImportError as exc:
            raise ImportError(
                "The 'openai' package is required for the OpenAI backend.\n"
                "Install it with:  pip install openai"
            ) from exc

        self.model       = model
        self.temperature = temperature
        self.timeout     = timeout
        self._client = _openai.OpenAI(
            api_key=api_key,   # None → reads OPENAI_API_KEY env var
            timeout=timeout,
        )

    # ── Health ─────────────────────────────────────────────────────────────────

    def is_available(self) -> bool:
        """Return True if the OpenAI API is reachable and the model exists."""
        try:
            self._client.models.retrieve(self.model)
            return True
        except Exception as exc:
            logger.debug("OpenAI unavailable: %s", exc)
            return False

    def list_models(self) -> list[str]:
        """Return available OpenAI model IDs."""
        try:
            return [m.id for m in self._client.models.list()]
        except Exception:
            return [self.model]

    # ── Core call ──────────────────────────────────────────────────────────────

    def chat(
        self,
        messages: list[dict],
        tools: list[dict] | None = None,
        max_tokens: int = 2048,
    ) -> dict:
        """Single chat completion, returned as an OpenAI-compat response dict."""
        kwargs: dict[str, Any] = {
            "model":       self.model,
            "messages":    messages,
            "temperature": self.temperature,
            "max_tokens":  max_tokens,
        }
        if tools:
            kwargs["tools"] = tools

        response = self._client.chat.completions.create(**kwargs)
        return response.model_dump()

    # ── Agentic loop ───────────────────────────────────────────────────────────

    def run_loop(
        self,
        messages: list[dict],
        tool_schemas: list[dict],
        tool_executor: Callable[[str, dict], str],
        max_turns: int = 8,
        max_tokens: int = 2048,
    ) -> tuple[list[dict], int]:
        """Run a ReAct tool-use loop.

        Tool schemas are already in OpenAI format so no conversion is needed.
        """
        import openai as _openai

        turns = 0

        while turns < max_turns:
            try:
                resp = self.chat(messages, tools=tool_schemas, max_tokens=max_tokens)
            except _openai.APIStatusError as exc:
                logger.error("OpenAI API error: %s", exc)
                break
            except _openai.APITimeoutError:
                logger.error("OpenAI request timed out after %ss", self.timeout)
                break

            turns += 1
            choice = resp["choices"][0]
            msg    = choice["message"]
            finish = choice.get("finish_reason", "stop")

            messages.append(msg)

            if finish == "stop":
                break

            tool_calls = msg.get("tool_calls") or []
            if not tool_calls:
                break

            for tc in tool_calls:
                fn   = tc["function"]
                name = fn["name"]
                try:
                    args = json.loads(fn.get("arguments", "{}"))
                except json.JSONDecodeError:
                    args = {}

                logger.debug("LLM tool call: %s(%s)", name, args)
                try:
                    result = tool_executor(name, args)
                except Exception as exc:
                    result = f"Error executing {name}: {exc}"

                messages.append({
                    "role":         "tool",
                    "tool_call_id": tc.get("id", name),
                    "name":         name,
                    "content":      result,
                })

        return messages, turns

    # ── Context manager ────────────────────────────────────────────────────────

    def close(self) -> None:
        """No persistent connection to close for the OpenAI SDK."""

    def __enter__(self) -> "OpenAIClient":  # type: ignore[override]
        return self

    def __exit__(self, *_: Any) -> None:
        self.close()
