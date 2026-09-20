"""Context-printing placeholder solver for file-based CTF challenges."""

from __future__ import annotations


from tools.context import get_chal_file_path, get_context


def file_chal_solver(chal_ID: int) -> str | None:
    """Print stored context and return a temporary synthetic flag."""
    print(f"[file] Challenge {chal_ID} context: {get_context(chal_ID)!r}")
    print(f"[file] Challenge {chal_ID} file path: {get_chal_file_path(chal_ID)!r}")
    return f"INCYPHER{{placeholder_file_{chal_ID}}}"
