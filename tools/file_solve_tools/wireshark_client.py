"""Bounded Wireshark/TShark inspection for local packet-capture artifacts."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Literal

from tools.file_solve_tools.external_process import resolve_tool, run_external_tool


WiresharkOperation = Literal["protocol_hierarchy", "conversations", "packet_fields"]
_OPERATIONS = {"protocol_hierarchy", "conversations", "packet_fields"}
_MAX_PACKETS = 1_000
_MAX_FILTER_LENGTH = 512


def run_wireshark_analysis(
    capture_path: str | Path,
    *,
    operation: WiresharkOperation,
    display_filter: str | None = None,
    max_packets: int = 100,
    tshark_path: str | Path | None = None,
    timeout: float = 30.0,
) -> dict[str, Any]:
    """Run one fixed TShark report against a local capture file.

    TShark is Wireshark's non-interactive command-line analyzer. The optional
    display filter is data passed to TShark, never shell text.
    """
    target = Path(capture_path).resolve()
    if not target.is_file():
        raise FileNotFoundError(f"Capture does not exist or is not a file: {target}")
    if operation not in _OPERATIONS:
        raise ValueError(f"Unsupported Wireshark operation: {operation}")
    if not isinstance(max_packets, int) or not 1 <= max_packets <= _MAX_PACKETS:
        raise ValueError(f"max_packets must be between 1 and {_MAX_PACKETS}")
    if display_filter is not None and (
        not isinstance(display_filter, str) or len(display_filter) > _MAX_FILTER_LENGTH
    ):
        raise ValueError(f"display_filter must be a string of at most {_MAX_FILTER_LENGTH} characters")

    executable = resolve_tool(
        configured_path=tshark_path,
        environment_variable="TSHARK_PATH",
        candidates=("tshark", "tshark.exe"),
    )
    command = [executable, "-n", "-r", str(target)]
    if display_filter:
        command.extend(("-Y", display_filter))
    if operation == "protocol_hierarchy":
        command.extend(("-q", "-z", "io,phs"))
    elif operation == "conversations":
        command.extend(("-q", "-z", "conv,tcp", "-z", "conv,udp"))
    else:
        fields = (
            "frame.number",
            "frame.time_relative",
            "ip.src",
            "ip.dst",
            "tcp.srcport",
            "tcp.dstport",
            "udp.srcport",
            "udp.dstport",
            "_ws.col.Protocol",
            "_ws.col.Info",
        )
        command.extend(("-c", str(max_packets), "-T", "fields", "-E", "header=y", "-E", "separator=\t"))
        for field in fields:
            command.extend(("-e", field))
    result = run_external_tool(command, timeout=timeout, cwd=target.parent)
    return {
        "operation": operation,
        "display_filter": display_filter,
        "returncode": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "output_truncated": result.output_truncated,
    }
