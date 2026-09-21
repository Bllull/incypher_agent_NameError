"""Bounded static GDB analysis for authorized local challenge binaries."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Literal

from tools.file_solve_tools.external_process import resolve_tool, run_external_tool


GdbOperation = Literal["file_info", "functions", "variables", "disassemble"]
_SYMBOL_PATTERN = re.compile(r"^[A-Za-z_.$][A-Za-z0-9_.$@]*$")
_OPERATIONS = {"file_info", "functions", "variables", "disassemble"}


def run_gdb_analysis(
    binary_path: str | Path,
    *,
    operation: GdbOperation,
    symbol: str | None = None,
    gdb_path: str | Path | None = None,
    timeout: float = 20.0,
) -> dict[str, Any]:
    """Run one fixed, non-interactive GDB inspection operation.

    Arbitrary GDB commands are intentionally not accepted. ``disassemble``
    needs a simple symbol name; all other operations ignore ``symbol``.
    """
    target = Path(binary_path).resolve()
    if not target.is_file():
        raise FileNotFoundError(f"Binary does not exist or is not a file: {target}")
    if operation not in _OPERATIONS:
        raise ValueError(f"Unsupported GDB operation: {operation}")
    commands = {
        "file_info": ["info files"],
        "functions": ["info functions"],
        "variables": ["info variables"],
    }
    if operation == "disassemble":
        if not isinstance(symbol, str) or not _SYMBOL_PATTERN.fullmatch(symbol):
            raise ValueError("disassemble requires a simple symbol name")
        commands[operation] = [f"disassemble /r {symbol}"]

    executable = resolve_tool(
        configured_path=gdb_path,
        environment_variable="GDB_PATH",
        candidates=("gdb", "gdb.exe"),
    )
    command = [executable, "--batch", "--nx", "--nh", "--quiet", str(target)]
    for gdb_command in ("set pagination off", "set confirm off", *commands[operation]):
        command.extend(("--ex", gdb_command))
    result = run_external_tool(command, timeout=timeout, cwd=target.parent)
    return {
        "operation": operation,
        "symbol": symbol if operation == "disassemble" else None,
        "returncode": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "output_truncated": result.output_truncated,
    }
