"""Anthropic Claude backend for GraphSAST LLM analysis.

Implements the same LLMClient interface as OllamaClient so Phase 1A / 1B
analysis works with either backend without modification.

Tool-use loop differences vs Ollama:
  - Uses the Anthropic Python SDK (``anthropic`` package) instead of httpx
  - Tool schemas are in Anthropic format (no "type": "function" wrapper)
  - Tool results are sent back as ``{"role": "user", "content": [tool_result]}``
  - Uses adaptive thinking (claude-opus-4-6) for deeper security reasoning
  - Internal message history stays in Anthropic format; responses are
    normalised to OpenAI-compat dicts so the rest of the codebase is unchanged

Requires:
  pip install anthropic
  ANTHROPIC_API_KEY env var  (or pass api_key= explicitly)
"""

from __future__ import annotations

import json
import logging
import uuid
from typing import Any, Callable

from graphsast.llm.base import LLMClient

logger = logging.getLogger(__name__)

DEFAULT_MODEL = "claude-opus-4-6"


# ──────────────────────────────────────────────────────────────────────────────
# Schema conversion helpers
# ──────────────────────────────────────────────────────────────────────────────

def _openai_tool_to_anthropic(tool: dict) -> dict:
    """Convert OpenAI function-calling schema to Anthropic tool format.

    OpenAI:
      {"type": "function", "function": {"name": ..., "description": ..., "parameters": ...}}

    Anthropic:
      {"name": ..., "description": ..., "input_schema": ...}
    """
    fn = tool.get("function", tool)   # handle both wrapped and bare dicts
    return {
        "name":         fn["name"],
        "description":  fn.get("description", ""),
        "input_schema": fn.get("parameters", {"type": "object", "properties": {}}),
    }


def _anthropic_response_to_openai(response: Any) -> dict:
    """Normalise an Anthropic Message object to OpenAI-compat response dict.

    The normalised format is what run_loop() and the callers in phase1a/1b
    expect:
      {"choices": [{"message": {"role": "assistant", "content": ...,
                                "tool_calls": [...]},
                    "finish_reason": "stop"|"tool_calls"}]}
    """
    stop_reason = getattr(response, "stop_reason", "end_turn")

    # Build content text
    text_parts = [b.text for b in response.content if b.type == "text"]
    content_text = "\n".join(text_parts)

    # Build tool_calls list (OpenAI format)
    tool_calls = []
    for block in response.content:
        if block.type == "tool_use":
            tool_calls.append({
                "id":   block.id,
                "type": "function",
                "function": {
                    "name":      block.name,
                    "arguments": json.dumps(block.input),
                },
            })

    finish_reason = "tool_calls" if tool_calls else "stop"
    if stop_reason in ("max_tokens", "stop_sequence"):
        finish_reason = "stop"

    msg: dict = {"role": "assistant", "content": content_text}
    if tool_calls:
        msg["tool_calls"] = tool_calls

    return {"choices": [{"message": msg, "finish_reason": finish_reason}]}


# ──────────────────────────────────────────────────────────────────────────────
# ClaudeClient
# ──────────────────────────────────────────────────────────────────────────────

class ClaudeClient(LLMClient):
    """Anthropic Claude backend. Drop-in replacement for OllamaClient."""

    def __init__(
        self,
        model: str = DEFAULT_MODEL,
        api_key: str | None = None,
        temperature: float = 0.1,
        timeout: float = 300.0,
        thinking: bool = True,
    ) -> None:
        """
        Args:
            model:       Anthropic model ID (default: claude-opus-4-6).
            api_key:     Anthropic API key.  Falls back to ANTHROPIC_API_KEY env var.
            temperature: Sampling temperature.  Ignored when thinking=True
                         (adaptive thinking sets its own effort level).
            timeout:     HTTP request timeout in seconds.
            thinking:    Enable adaptive thinking (recommended for security analysis).
        """
        try:
            import anthropic as _anthropic
        except ImportError as exc:
            raise ImportError(
                "The 'anthropic' package is required for the Claude backend.\n"
                "Install it with:  pip install anthropic"
            ) from exc

        self.model       = model
        self.temperature = temperature
        self.timeout     = timeout
        self.thinking    = thinking
        self._client = _anthropic.Anthropic(
            api_key=api_key,          # None → reads ANTHROPIC_API_KEY env var
            timeout=timeout,
        )

    # ── Health ─────────────────────────────────────────────────────────────────

    def is_available(self) -> bool:
        """Return True if the Anthropic API is reachable with the current key."""
        try:
            # Cheapest possible probe: count tokens on a trivial message
            self._client.messages.count_tokens(
                model=self.model,
                messages=[{"role": "user", "content": "ping"}],
            )
            return True
        except Exception as exc:
            logger.debug("Claude unavailable: %s", exc)
            return False

    def list_models(self) -> list[str]:
        """Return available Claude models (best-effort)."""
        try:
            page = self._client.models.list()
            return [m.id for m in page.data]
        except Exception:
            # Fallback: return the configured model so the CLI doesn't break
            return [self.model]

    # ── Core call ──────────────────────────────────────────────────────────────

    def chat(
        self,
        messages: list[dict],
        tools: list[dict] | None = None,
        max_tokens: int = 2048,
    ) -> dict:
        """Single chat completion, normalised to OpenAI-compat response dict."""
        # Separate system message if present
        system_text = ""
        api_messages = []
        for m in messages:
            if m["role"] == "system":
                system_text = m.get("content", "")
            else:
                api_messages.append(m)

        kwargs: dict[str, Any] = {
            "model":      self.model,
            "max_tokens": max_tokens,
            "messages":   api_messages,
        }
        if system_text:
            kwargs["system"] = system_text
        if tools:
            kwargs["tools"] = [_openai_tool_to_anthropic(t) for t in tools]
        if self.thinking:
            kwargs["thinking"] = {"type": "adaptive"}
        else:
            kwargs["temperature"] = self.temperature

        response = self._client.messages.create(**kwargs)
        return _anthropic_response_to_openai(response)

    # ── Agentic loop ───────────────────────────────────────────────────────────

    def run_loop(
        self,
        messages: list[dict],
        tool_schemas: list[dict],
        tool_executor: Callable[[str, dict], str],
        max_turns: int = 8,
        max_tokens: int = 2048,
    ) -> tuple[list[dict], int]:
        """ReAct tool-use loop against the Anthropic API.

        Keeps an internal Anthropic-format conversation (``_anth_msgs``) and
        mirrors updates back to the caller's ``messages`` list in OpenAI format
        so callers remain backend-agnostic.
        """
        import anthropic as _anthropic

        # Convert OpenAI tool schemas once
        anth_tools = [_openai_tool_to_anthropic(t) for t in tool_schemas]

        # Separate system prompt and build initial Anthropic message list
        system_text = ""
        anth_msgs: list[dict] = []
        for m in messages:
            if m["role"] == "system":
                system_text = m.get("content", "")
            else:
                anth_msgs.append({"role": m["role"], "content": m.get("content", "")})

        turns = 0

        while turns < max_turns:
            kwargs: dict[str, Any] = {
                "model":      self.model,
                "max_tokens": max_tokens,
                "messages":   anth_msgs,
                "tools":      anth_tools,
            }
            if system_text:
                kwargs["system"] = system_text
            if self.thinking:
                kwargs["thinking"] = {"type": "adaptive"}
            else:
                kwargs["temperature"] = self.temperature

            try:
                response = self._client.messages.create(**kwargs)
            except _anthropic.APIStatusError as exc:
                logger.error("Claude API error: %s", exc)
                break
            except _anthropic.APITimeoutError:
                logger.error("Claude request timed out after %ss", self.timeout)
                break

            turns += 1

            # Extract text and tool_use blocks
            text_parts = [b.text for b in response.content if b.type == "text"]
            tool_use_blocks = [b for b in response.content if b.type == "tool_use"]

            content_text = "\n".join(text_parts)

            # Append assistant turn to Anthropic history
            # Use raw content blocks so tool_use is preserved correctly
            anth_msgs.append({"role": "assistant", "content": response.content})

            # Mirror to caller's OpenAI-format list
            oai_msg: dict = {"role": "assistant", "content": content_text}
            if tool_use_blocks:
                oai_msg["tool_calls"] = [
                    {
                        "id": b.id,
                        "type": "function",
                        "function": {
                            "name":      b.name,
                            "arguments": json.dumps(b.input),
                        },
                    }
                    for b in tool_use_blocks
                ]
            messages.append(oai_msg)

            # Stop if no tool calls
            if not tool_use_blocks:
                break
            if response.stop_reason in ("end_turn", "max_tokens", "stop_sequence"):
                if not tool_use_blocks:
                    break

            # Execute tools and build Anthropic tool_result blocks
            tool_result_content: list[dict] = []
            for block in tool_use_blocks:
                try:
                    args = dict(block.input) if block.input else {}
                except Exception:
                    args = {}

                logger.debug("LLM tool call: %s(%s)", block.name, args)
                try:
                    result = tool_executor(block.name, args)
                except Exception as exc:
                    result = f"Error executing {block.name}: {exc}"

                tool_result_content.append({
                    "type":        "tool_result",
                    "tool_use_id": block.id,
                    "content":     result,
                })

                # Mirror to caller's OpenAI-format list
                messages.append({
                    "role":        "tool",
                    "tool_call_id": block.id,
                    "name":        block.name,
                    "content":     result,
                })

            # Append tool results to Anthropic history as a user turn
            anth_msgs.append({"role": "user", "content": tool_result_content})

        return messages, turns

    # ── Context manager ────────────────────────────────────────────────────────

    def close(self) -> None:
        """No persistent connection to close for the Anthropic SDK."""

    def __enter__(self) -> "ClaudeClient":  # type: ignore[override]
        return self
