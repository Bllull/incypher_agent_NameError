"""Context-printing placeholder solver for port-based CTF challenges."""

from __future__ import annotations


from tools.context import get_chal_file_path, get_context


def port_chal_solver(chal_ID: int) -> str | None:
    """Print the stored context for a port-based challenge."""
    print(f"[port] Challenge {chal_ID} context: {get_context(chal_ID)!r}")
    print(f"[port] Challenge {chal_ID} file path: {get_chal_file_path(chal_ID)!r}")
    return None
