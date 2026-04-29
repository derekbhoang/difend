"""LangChain/OpenAI model setup and retry handling."""

from __future__ import annotations

import json
import os
import time
from typing import Any, TypeVar

from pydantic import BaseModel


DEFAULT_MODEL = "gpt-5.4-mini"
T = TypeVar("T", bound=BaseModel)


class ModelConfigurationError(RuntimeError):
    """Raised when the model cannot be configured."""


class AgentNodeError(RuntimeError):
    """Raised when an LLM-backed agent node fails."""


class StructuredModelClient:
    def __init__(self, model: str | None = None, retries: int = 2) -> None:
        self.model = model or os.getenv("DIFEND_OPENAI_MODEL", DEFAULT_MODEL)
        self.retries = retries
        self._chat_model: Any | None = None

    @classmethod
    def from_environment(cls, required: bool) -> "StructuredModelClient | None":
        if not required:
            return None
        if not os.getenv("OPENAI_API_KEY"):
            raise ModelConfigurationError(
                "OPENAI_API_KEY is required for agentic scans with non-empty diffs."
            )
        return cls()

    def invoke_structured(
        self,
        system_prompt: str,
        payload: dict[str, Any],
        schema: type[T],
        node_name: str,
    ) -> T:
        last_error: Exception | None = None
        for attempt in range(self.retries + 1):
            try:
                model = self._model().with_structured_output(schema)
                result = model.invoke(
                    [
                        ("system", system_prompt),
                        ("human", json.dumps(payload, indent=2, sort_keys=True)),
                    ]
                )
                if isinstance(result, schema):
                    return result
                return schema.model_validate(result)
            except Exception as exc:  # noqa: BLE001 - normalize provider/schema errors.
                last_error = exc
                if attempt >= self.retries:
                    break
                time.sleep(0.5 * (2 ** attempt))
        raise AgentNodeError(f"{node_name} failed after retries: {last_error}") from last_error

    def _model(self) -> Any:
        if self._chat_model is None:
            try:
                from langchain_openai import ChatOpenAI
            except ImportError as exc:
                raise ModelConfigurationError(
                    "langchain-openai is not installed. Install requirements.txt."
                ) from exc
            self._chat_model = ChatOpenAI(model=self.model)
        return self._chat_model
