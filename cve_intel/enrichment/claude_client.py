"""Anthropic SDK wrapper for structured tool_use output."""

import threading
import time
from typing import Any

import anthropic

from cve_intel.config import settings


class ClaudeError(Exception):
    pass


class ClaudeClient:
    # Class-level throttle shared across all instances and threads.
    # Prevents batch workers from flooding the Anthropic API concurrently.
    # Default: 10 req/s ceiling (0.1 s between calls). Tune via CLAUDE_MIN_INTERVAL_S.
    _lock = threading.Lock()
    _last_call: float = 0.0
    _min_interval: float = 0.1

    def __init__(self) -> None:
        if not settings.has_anthropic_key:
            raise ClaudeError("ANTHROPIC_API_KEY is not set.")
        self._client = anthropic.Anthropic(api_key=settings.anthropic_api_key)

    def complete_structured(
        self,
        system: str,
        user: str,
        output_schema: dict,
        tool_name: str,
        max_retries: int = 3,
    ) -> dict:
        """Call Claude with tool_use to get structured JSON output matching output_schema."""
        with self._lock:
            now = time.monotonic()
            wait = self._min_interval - (now - self._last_call)
            if wait > 0:
                time.sleep(wait)
            ClaudeClient._last_call = time.monotonic()

        last_exc: Exception | None = None
        for attempt in range(max_retries):
            try:
                response = self._client.messages.create(
                    model=settings.claude_model,
                    max_tokens=settings.max_tokens,
                    system=system,
                    messages=[{"role": "user", "content": user}],
                    tools=[{
                        "name": tool_name,
                        "description": "Return structured analysis result",
                        "input_schema": output_schema,
                    }],
                    tool_choice={"type": "tool", "name": tool_name},
                )
                for block in response.content:
                    if block.type == "tool_use":
                        return block.input
                raise ClaudeError("No tool_use block in Claude response.")
            except anthropic.RateLimitError as exc:
                wait = 2 ** attempt
                time.sleep(wait)
                last_exc = exc
            except anthropic.APIError as exc:
                last_exc = exc
                if attempt < max_retries - 1:
                    time.sleep(2 ** attempt)
        raise ClaudeError(f"Claude API failed after {max_retries} attempts: {last_exc}") from last_exc
