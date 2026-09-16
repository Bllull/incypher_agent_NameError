import os
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
