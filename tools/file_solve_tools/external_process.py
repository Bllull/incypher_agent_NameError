"""Shared bounded process support for installed local analysis tools."""

from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence


MAX_EXTERNAL_OUTPUT_BYTES = 64 * 1024
MAX_EXTERNAL_TIMEOUT_SECONDS = 60.0


class ExternalToolError(RuntimeError):
    """A local analysis tool was unavailable or could not complete safely."""


@dataclass(frozen=True)
class ExternalProcessResult:
    """Bounded stdout/stderr from a local analysis-tool process."""

    returncode: int
    stdout: str
    stderr: str
    output_truncated: bool


def resolve_tool(
    *,
    configured_path: str | Path | None,
    environment_variable: str,
    candidates: Sequence[str],
) -> str:
    """Resolve an installed tool from explicit config, environment, or PATH."""
    configured = configured_path or os.getenv(environment_variable)
    if configured:
        path = Path(configured).expanduser()
        if path.is_file():
            return str(path.resolve())
        resolved = shutil.which(str(configured))
        if resolved:
            return resolved
        raise ExternalToolError(f"{environment_variable} does not identify an executable: {configured}")
    for candidate in candidates:
        resolved = shutil.which(candidate)
        if resolved:
            return resolved
    raise ExternalToolError(
        f"Required tool is unavailable. Configure {environment_variable} or add one of "
        f"{', '.join(candidates)} to PATH."
    )


def run_external_tool(
    command: Sequence[str],
    *,
    timeout: float,
    cwd: Path,
    input_data: bytes | None = None,
) -> ExternalProcessResult:
    """Run a fixed argument vector without a shell and retain bounded evidence."""
    if not isinstance(timeout, (int, float)) or not 0 < timeout <= MAX_EXTERNAL_TIMEOUT_SECONDS:
        raise ValueError(f"timeout must be between 0 and {MAX_EXTERNAL_TIMEOUT_SECONDS}")
    try:
        completed = subprocess.run(
            list(command),
            cwd=str(cwd),
            shell=False,
            capture_output=True,
            input=input_data,
            timeout=float(timeout),
            check=False,
        )
    except FileNotFoundError as exc:
        raise ExternalToolError(f"Analysis tool was not found: {command[0]}") from exc
    except subprocess.TimeoutExpired as exc:
        raise ExternalToolError(f"Analysis tool exceeded its {timeout}-second timeout") from exc

    combined_size = len(completed.stdout) + len(completed.stderr)
    stdout = completed.stdout[:MAX_EXTERNAL_OUTPUT_BYTES].decode("utf-8", errors="replace")
    remaining = max(0, MAX_EXTERNAL_OUTPUT_BYTES - len(completed.stdout))
    stderr = completed.stderr[:remaining].decode("utf-8", errors="replace")
    return ExternalProcessResult(
        returncode=completed.returncode,
        stdout=stdout,
        stderr=stderr,
        output_truncated=combined_size > MAX_EXTERNAL_OUTPUT_BYTES,
    )
