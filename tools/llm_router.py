import os
import base64
import mimetypes
from pathlib import Path
from typing import Any, Sequence

from openai import OpenAI
import tools.config  # Loads .env before the client reads its settings.

# Initialize the OpenAI-compatible client using the SoClass gateway settings.
client = OpenAI(
    api_key=os.getenv("SOCLAAS_API_KEY"),
    base_url=os.getenv("SOCLAAS_BASE_URL"),
)

def call_openai(prompt: str, require_deep_reasoning: bool = False) -> str:
    """Routes prompts to gpt-4o-mini by default, or o3-mini for heavy reasoning tasks."""
    model_name = "coding" if require_deep_reasoning else "default"
    
    # Configure parameter based on model family
    extra_params = {}
    if not require_deep_reasoning:
        extra_params["temperature"] = 0.0

    response = client.chat.completions.create(
        model=model_name,
        messages=[{"role": "user", "content": prompt}],
        **extra_params
    )
    return response.choices[0].message.content.strip()


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

    response = client.chat.completions.create(
        model=model_name,
        messages=[{"role": "user", "content": content}],
        temperature=0.0,
    )
    return response.choices[0].message.content.strip()
