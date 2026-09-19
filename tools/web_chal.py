"""Context-printing placeholder solver for URL-based CTF challenges."""

from __future__ import annotations


from tools.context import get_chal_file_path, get_context


def web_chal_solver(chal_ID: int) -> str | None:
    """Print the stored context for a URL-based challenge."""
    print(f"[web] Challenge {chal_ID} context: {get_context(chal_ID)!r}")
    print(f"[web] Challenge {chal_ID} file path: {get_chal_file_path(chal_ID)!r}")
    return None
