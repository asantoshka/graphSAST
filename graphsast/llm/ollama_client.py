"""Ollama API client with tool-use support.

Uses Ollama's OpenAI-compatible endpoint:
  POST http://localhost:11434/v1/chat/completions

Tool-capable models: llama3.1, llama3.2, llama3.3, mistral-nemo,
                     qwen2.5-coder, deepseek-r1, etc.

The client runs a multi-turn ReAct loop:
  1. Send messages + tool schemas to Ollama
  2. If the model calls a tool, execute it locally, append result
  3. Repeat until stop_reason == "stop" or turn limit reached
"""

from __future__ import annotations

import json
import logging
from typing import Any, Callable

import httpx

from graphsast.llm.base import LLMClient

logger = logging.getLogger(__name__)

# Module-level defaults kept for backward compatibility; actual defaults now
# come from GraphSASTSettings (graphsast.config) so they are user-configurable.
DEFAULT_BASE_URL  = "http://localhost:11434"
DEFAULT_MODEL     = "llama3.1"
DEFAULT_TIMEOUT   = 300.0   # seconds per request (qwen2.5:14b can take ~2-3 min)


class OllamaClient(LLMClient):
    """Thin wrapper around Ollama's OpenAI-compat /v1/chat/completions."""

    def __init__(
        self,
        base_url: str = DEFAULT_BASE_URL,
        model: str = DEFAULT_MODEL,
        timeout: float = DEFAULT_TIMEOUT,
        temperature: float = 0.1,
        num_ctx: int = 8192,
        health_check_timeout: float = 5.0,
    ) -> None:
        self.base_url  = base_url.rstrip("/")
        self.model     = model
        self.timeout   = timeout
        self.temperature = temperature
        self.num_ctx   = num_ctx
        self._health_check_timeout = health_check_timeout
        self._http     = httpx.Client(timeout=timeout)

    # ------------------------------------------------------------------
    # Health check
    # ------------------------------------------------------------------

    def is_available(self) -> bool:
        """Return True if Ollama is reachable and the model exists."""
        try:
            r = self._http.get(f"{self.base_url}/api/tags", timeout=self._health_check_timeout)
            if r.status_code != 200:
                return False
            models = [m["name"] for m in r.json().get("models", [])]
            # Accept "llama3.1" matching "llama3.1:latest" etc.
            return any(m.startswith(self.model.split(":")[0]) for m in models)
        except Exception as exc:
            logger.debug("Ollama unavailable: %s", exc)
            return False

    def list_models(self) -> list[str]:
        """Return names of locally available models."""
        try:
            r = self._http.get(f"{self.base_url}/api/tags", timeout=self._health_check_timeout)
            return [m["name"] for m in r.json().get("models", [])]
        except Exception:
            return []

    # ------------------------------------------------------------------
    # Core chat call
    # ------------------------------------------------------------------

    def chat(
        self,
        messages: list[dict],
        tools: list[dict] | None = None,
        max_tokens: int = 2048,
    ) -> dict:
        """Single chat request. Returns the raw OpenAI-compat response dict."""
        payload: dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "temperature": self.temperature,
            "max_tokens": max_tokens,
            "options": {"num_ctx": self.num_ctx},
            "stream": False,
        }
        if tools:
            payload["tools"] = tools

        r = self._http.post(
            f"{self.base_url}/v1/chat/completions",
            json=payload,
        )
        r.raise_for_status()
        return r.json()

    # ------------------------------------------------------------------
    # Agentic loop
    # ------------------------------------------------------------------

    def run_loop(
        self,
        messages: list[dict],
        tool_schemas: list[dict],
        tool_executor: Callable[[str, dict], str],
        max_turns: int = 8,
        max_tokens: int = 2048,
    ) -> tuple[list[dict], int]:
        """Run a ReAct tool-use loop.

        Args:
            messages:       Conversation so far (mutated in-place).
            tool_schemas:   OpenAI-format tool definitions.
            tool_executor:  Callable(tool_name, tool_args) → result_str.
            max_turns:      Maximum assistant turns before stopping.
            max_tokens:     Max tokens per assistant response.

        Returns:
            (updated_messages, turns_used)
        """
        turns = 0

        while turns < max_turns:
            try:
                resp = self.chat(messages, tools=tool_schemas, max_tokens=max_tokens)
            except httpx.HTTPStatusError as exc:
                logger.error("Ollama HTTP error: %s", exc)
                break
            except httpx.TimeoutException:
                logger.error("Ollama request timed out after %ss", self.timeout)
                break

            turns += 1
            choice = resp["choices"][0]
            msg    = choice["message"]
            finish = choice.get("finish_reason", "stop")

            # Append assistant message
            messages.append(msg)

            if finish == "stop" or finish == "end_turn":
                break

            # Handle tool calls
            tool_calls = msg.get("tool_calls") or []
            if not tool_calls:
                break

            # Execute each tool and append results
            for tc in tool_calls:
                fn    = tc["function"]
                name  = fn["name"]
                try:
                    args = json.loads(fn.get("arguments", "{}"))
                except json.JSONDecodeError:
                    args = {}

                logger.info("  → tool call: %s(%s)", name, args)
                try:
                    result = tool_executor(name, args)
                except Exception as exc:
                    result = f"Error executing {name}: {exc}"
                logger.info("  ← result: %s", (result[:120] + "…") if len(result) > 120 else result)

                messages.append({
                    "role": "tool",
                    "tool_call_id": tc.get("id", name),
                    "name": name,
                    "content": result,
                })

        return messages, turns

    def close(self) -> None:
        self._http.close()

    def __enter__(self) -> "OllamaClient":  # type: ignore[override]
        return self

    def __exit__(self, *_: Any) -> None:
        self.close()
