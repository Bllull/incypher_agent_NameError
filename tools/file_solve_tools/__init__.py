"""Bounded, structured tools for file-based CTF challenge solving."""

from tools.file_solve_tools.file_tools import (
    FileToolRequest,
    FileToolResult,
    execute_file_tool,
)
from tools.file_solve_tools.cyberchef_client import run_cyberchef_analysis
from tools.file_solve_tools.gdb_client import run_gdb_analysis
from tools.file_solve_tools.ghidra_client import run_ghidra_analysis
from tools.file_solve_tools.wireshark_client import run_wireshark_analysis

__all__ = [
    "FileToolRequest",
    "FileToolResult",
    "execute_file_tool",
    "run_cyberchef_analysis",
    "run_gdb_analysis",
    "run_ghidra_analysis",
    "run_wireshark_analysis",
]
