"""AWS Bedrock backend for GraphSAST LLM analysis.

Uses ``anthropic.AnthropicBedrock`` which provides the exact same API as the
regular Anthropic client but routes requests through AWS Bedrock.  This means
the tool-use loop and message normalisation are identical to ClaudeClient.

Credentials are resolved by the standard AWS credential chain:
  1. Constructor args (aws_access_key / aws_secret_key)
  2. Environment variables: AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY
  3. ~/.aws/credentials  /  ~/.aws/config  (shared credentials file)
  4. EC2 / ECS / EKS IAM role

Requires:
  pip install anthropic boto3
  AWS credentials in any of the locations above

Bedrock model IDs differ from the Anthropic API model IDs:
  anthropic.claude-3-5-sonnet-20241022-v2:0  (latest Claude 3.5 Sonnet)
  anthropic.claude-3-opus-20240229-v1:0
  anthropic.claude-3-haiku-20240307-v1:0
"""

from __future__ import annotations

import json
import logging
from typing import Any, Callable

from graphsast.llm.base import LLMClient

logger = logging.getLogger(__name__)

DEFAULT_MODEL  = "anthropic.claude-3-5-sonnet-20241022-v2:0"
DEFAULT_REGION = "us-east-1"


# ──────────────────────────────────────────────────────────────────────────────
# Schema conversion helpers  (identical to claude_client.py)
# ──────────────────────────────────────────────────────────────────────────────

def _openai_tool_to_anthropic(tool: dict) -> dict:
    fn = tool.get("function", tool)
    return {
        "name":         fn["name"],
        "description":  fn.get("description", ""),
        "input_schema": fn.get("parameters", {"type": "object", "properties": {}}),
    }


def _anthropic_response_to_openai(response: Any) -> dict:
    text_parts = [b.text for b in response.content if b.type == "text"]
    content_text = "\n".join(text_parts)

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
    if getattr(response, "stop_reason", "") in ("max_tokens", "stop_sequence"):
        finish_reason = "stop"

    msg: dict = {"role": "assistant", "content": content_text}
    if tool_calls:
        msg["tool_calls"] = tool_calls

    return {"choices": [{"message": msg, "finish_reason": finish_reason}]}


# ──────────────────────────────────────────────────────────────────────────────
# BedrockClient
# ──────────────────────────────────────────────────────────────────────────────

class BedrockClient(LLMClient):
    """AWS Bedrock backend using anthropic.AnthropicBedrock.

    Drop-in replacement for ClaudeClient when you want to route requests
    through your AWS account instead of the Anthropic API directly.
    """

    def __init__(
        self,
        model: str = DEFAULT_MODEL,
        aws_region: str = DEFAULT_REGION,
        aws_access_key: str | None = None,
        aws_secret_key: str | None = None,
        aws_session_token: str | None = None,
        temperature: float = 0.1,
        timeout: float = 300.0,
    ) -> None:
        """
        Args:
            model:             Bedrock model ID (default: claude-3-5-sonnet).
            aws_region:        AWS region name (default: us-east-1).
            aws_access_key:    AWS access key ID.  Falls back to env / ~/.aws.
            aws_secret_key:    AWS secret access key.  Falls back to env / ~/.aws.
            aws_session_token: Session token for temporary credentials.
            temperature:       Sampling temperature.
            timeout:           HTTP request timeout in seconds.
        """
        try:
            import anthropic as _anthropic
        except ImportError as exc:
            raise ImportError(
                "The 'anthropic' package is required for the Bedrock backend.\n"
                "Install it with:  pip install anthropic boto3"
            ) from exc

        self.model       = model
        self.temperature = temperature
        self.timeout     = timeout

        bedrock_kwargs: dict[str, Any] = {
            "aws_region":  aws_region,
            "timeout":     timeout,
        }
        if aws_access_key:
            bedrock_kwargs["aws_access_key"]    = aws_access_key
        if aws_secret_key:
            bedrock_kwargs["aws_secret_key"]    = aws_secret_key
        if aws_session_token:
            bedrock_kwargs["aws_session_token"] = aws_session_token

        self._client = _anthropic.AnthropicBedrock(**bedrock_kwargs)

    # ── Health ─────────────────────────────────────────────────────────────────

    def is_available(self) -> bool:
        """Return True if Bedrock is reachable and the model can be accessed."""
        try:
            self._client.messages.count_tokens(
                model=self.model,
                messages=[{"role": "user", "content": "ping"}],
            )
            return True
        except Exception as exc:
            logger.debug("Bedrock unavailable: %s", exc)
            return False

    def list_models(self) -> list[str]:
        """Return known Bedrock Claude model IDs (best-effort via boto3)."""
        try:
            import boto3
            bedrock = boto3.client("bedrock", region_name=self._client.aws_region)
            resp = bedrock.list_foundation_models(byProvider="Anthropic")
            return [m["modelId"] for m in resp.get("modelSummaries", [])]
        except Exception:
            return [self.model]

    # ── Core call ──────────────────────────────────────────────────────────────

    def chat(
        self,
        messages: list[dict],
        tools: list[dict] | None = None,
        max_tokens: int = 2048,
    ) -> dict:
        """Single chat completion, normalised to OpenAI-compat response dict."""
        system_text = ""
        api_messages = []
        for m in messages:
            if m["role"] == "system":
                system_text = m.get("content", "")
            else:
                api_messages.append(m)

        kwargs: dict[str, Any] = {
            "model":       self.model,
            "max_tokens":  max_tokens,
            "messages":    api_messages,
            "temperature": self.temperature,
        }
        if system_text:
            kwargs["system"] = system_text
        if tools:
            kwargs["tools"] = [_openai_tool_to_anthropic(t) for t in tools]

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
        """ReAct tool-use loop against the Bedrock Anthropic API."""
        import anthropic as _anthropic

        anth_tools = [_openai_tool_to_anthropic(t) for t in tool_schemas]

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
                "model":       self.model,
                "max_tokens":  max_tokens,
                "messages":    anth_msgs,
                "tools":       anth_tools,
                "temperature": self.temperature,
            }
            if system_text:
                kwargs["system"] = system_text

            try:
                response = self._client.messages.create(**kwargs)
            except _anthropic.APIStatusError as exc:
                logger.error("Bedrock API error: %s", exc)
                break
            except _anthropic.APITimeoutError:
                logger.error("Bedrock request timed out after %ss", self.timeout)
                break

            turns += 1

            text_parts       = [b.text for b in response.content if b.type == "text"]
            tool_use_blocks  = [b for b in response.content if b.type == "tool_use"]
            content_text     = "\n".join(text_parts)

            anth_msgs.append({"role": "assistant", "content": response.content})

            oai_msg: dict = {"role": "assistant", "content": content_text}
            if tool_use_blocks:
                oai_msg["tool_calls"] = [
                    {
                        "id":   b.id,
                        "type": "function",
                        "function": {
                            "name":      b.name,
                            "arguments": json.dumps(b.input),
                        },
                    }
                    for b in tool_use_blocks
                ]
            messages.append(oai_msg)

            if not tool_use_blocks:
                break

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
                messages.append({
                    "role":         "tool",
                    "tool_call_id": block.id,
                    "name":         block.name,
                    "content":      result,
                })

            anth_msgs.append({"role": "user", "content": tool_result_content})

        return messages, turns

    # ── Context manager ────────────────────────────────────────────────────────

    def close(self) -> None:
        """No persistent connection to close for the Anthropic Bedrock SDK."""

    def __enter__(self) -> "BedrockClient":  # type: ignore[override]
        return self

    def __exit__(self, *_: Any) -> None:
        self.close()
