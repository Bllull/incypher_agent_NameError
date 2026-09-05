import os
from openai import OpenAI

# Initialize client using environment variable
client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

def call_openai(prompt: str, require_deep_reasoning: bool = False) -> str:
    """Routes prompts to gpt-4o-mini by default, or o3-mini for heavy reasoning tasks."""
    model_name = "o3-mini" if require_deep_reasoning else "gpt-4o-mini"
    
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