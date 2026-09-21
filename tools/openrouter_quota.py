"""Print the authenticated OpenRouter key's remaining credit quota.

OpenRouter does not expose a model-independent "tokens remaining" value:
models charge different rates for input and output tokens.  Its key endpoint
does expose the remaining USD credit limit, which is the useful budget signal
for an agent.

Run with ``python -m tools.openrouter_quota``.  The key is read only from
``OPENROUTER_API_KEY`` (including the repository's .env file); it is never
printed or accepted on the command line.
"""

from __future__ import annotations

import json
import os
import sys
from typing import Any

import requests

import tools.config  # Loads .env without overriding injected environment values.
from tools.send_logs import send_logs as print


def get_key_quota(*, timeout: float = 10.0) -> dict[str, Any]:
    """Return the current API key's quota and usage metadata from OpenRouter."""
    api_key = os.getenv("OPENROUTER_API_KEY")
    if not api_key:
        raise RuntimeError("OPENROUTER_API_KEY is not set")

    base_url = os.getenv("OPENROUTER_BASE_URL", "https://openrouter.ai/api/v1")
    response = requests.get(
        f"{base_url.rstrip('/')}/key",
        headers={"Authorization": f"Bearer {api_key}"},
        timeout=timeout,
    )
    response.raise_for_status()
    payload = response.json()
    data = payload.get("data")
    if not isinstance(data, dict):
        raise RuntimeError("OpenRouter returned no key quota data")
    return data


def main() -> int:
    try:
        data = get_key_quota()
    except (requests.RequestException, ValueError, RuntimeError) as exc:
        print(f"Unable to retrieve OpenRouter key quota: {exc}", file=sys.stderr)
        return 1

    # Keep the output intentionally small and avoid exposing the API-key label.
    summary = {
        "remaining_credit_usd": data.get("limit_remaining"),
        "credit_limit_usd": data.get("limit"),
        "usage_usd": data.get("usage"),
        "reset_interval": data.get("limit_reset"),
        "usage_daily_usd": data.get("usage_daily"),
        "usage_weekly_usd": data.get("usage_weekly"),
        "usage_monthly_usd": data.get("usage_monthly"),
    }
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
