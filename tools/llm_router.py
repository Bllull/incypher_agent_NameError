import os
import base64
import mimetypes
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any, Sequence, TypeVar

from openai import APIConnectionError, APIStatusError, OpenAI
import tools.config  # Loads .env before the client reads its settings.

# Initialized lazily so preflight can report missing settings cleanly.
client: OpenAI | None = None

DEFAULT_MAX_ATTEMPTS = 3
_RETRYABLE_STATUS_CODES = {408, 429, 500, 502, 503, 504}
_Result = TypeVar("_Result")


def _get_client() -> OpenAI:
    """Return the shared configured SOCLAas client."""
    global client
    if client is None:
        api_key = os.getenv("SOCLAAS_API_KEY")
        base_url = os.getenv("SOCLAAS_BASE_URL")
        if not api_key or not base_url:
            raise ValueError("SOCLAAS_API_KEY and SOCLAAS_BASE_URL must be set")
        client = OpenAI(api_key=api_key, base_url=base_url)
    return client


def _call_with_retry(
    operation: Callable[[], _Result],
    *,
    max_attempts: int = DEFAULT_MAX_ATTEMPTS,
) -> _Result:
    """Run an OpenAI operation with bounded exponential-backoff retries."""
    if max_attempts < 1:
        raise ValueError("max_attempts must be at least 1")

    for attempt in range(1, max_attempts + 1):
        try:
            return operation()
        except APIStatusError as exc:
            if exc.status_code not in _RETRYABLE_STATUS_CODES or attempt == max_attempts:
                raise
        except APIConnectionError:
            if attempt == max_attempts:
                raise

        delay = min(2 ** (attempt - 1), 8)
        print(
            f"[llm] transient gateway failure; retrying in {delay}s "
            f"({attempt}/{max_attempts})"
        )
        time.sleep(delay)

    raise RuntimeError("LLM retry loop ended unexpectedly")


def call_openai(
    prompt: str,
    require_deep_reasoning: bool = False,
    *,
    max_attempts: int = DEFAULT_MAX_ATTEMPTS,
) -> str:
    """Route prompts to the default model or the coding model for deep reasoning."""
    model_name = "coding" if require_deep_reasoning else "default"
    
    # Configure parameter based on model family
    extra_params = {}
    if not require_deep_reasoning:
        extra_params["temperature"] = 0.0

    response = _call_with_retry(
        lambda: _get_client().chat.completions.create(
            model=model_name,
            messages=[{"role": "user", "content": prompt}],
            **extra_params,
        ),
        max_attempts=max_attempts,
    )
    return response.choices[0].message.content.strip()


def list_openai_models(
    *, max_attempts: int = DEFAULT_MAX_ATTEMPTS
) -> list[str]:
    """Return model IDs from the configured SOCLAas gateway."""
    response = _call_with_retry(
        lambda: _get_client().models.list(), max_attempts=max_attempts
    )
    return [model.id for model in response.data]


def _image_data_url(image_path: str | Path) -> str:
    """Return a supported local image as a base64 data URL."""
    path = Path(image_path)
    if not path.is_file():
        raise FileNotFoundError(f"Image file does not exist: {path}")

    mime_type, _ = mimetypes.guess_type(path.name)
    allowed_types = {"image/jpeg", "image/png", "image/gif", "image/webp"}
    if mime_type not in allowed_types:
        raise ValueError(
            "Unsupported image type. Use JPEG, PNG, GIF, or WebP images."
        )

    encoded_image = base64.b64encode(path.read_bytes()).decode("ascii")
    return f"data:{mime_type};base64,{encoded_image}"


def call_multimodal_openai(
    prompt: str,
    image_paths: Sequence[str | Path],
    model_name: str = "qwen3-vl:32b",
    *,
    max_attempts: int = DEFAULT_MAX_ATTEMPTS,
) -> str:
    """Send text and local images to a SOCLaas vision-capable chat model.

    SOCLaas exposes ``qwen3-vl:32b`` as a vision-capable model. The gateway
    must support OpenAI-style ``image_url`` message parts for this helper to
    work; images are encoded locally and are never written to the repository.
    """
    if not isinstance(prompt, str) or not prompt.strip():
        raise ValueError("prompt must be a non-empty string")
    if not image_paths:
        raise ValueError("image_paths must contain at least one image")

    content: list[dict[str, Any]] = [{"type": "text", "text": prompt}]
    content.extend(
        {
            "type": "image_url",
            "image_url": {"url": _image_data_url(image_path)},
        }
        for image_path in image_paths
    )

    response = _call_with_retry(
        lambda: _get_client().chat.completions.create(
            model=model_name,
            messages=[{"role": "user", "content": content}], #type: ignore
            temperature=0.0,
        ),
        max_attempts=max_attempts,
    )
    return response.choices[0].message.content.strip() #type: ignore
