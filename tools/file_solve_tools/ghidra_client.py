"""Headless Ghidra reports for authorized local challenge binaries."""

from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Any, Literal

from tools.file_solve_tools.external_process import resolve_tool, run_external_tool


GhidraOperation = Literal["summary", "functions", "strings"]
_OPERATIONS = {"summary", "functions", "strings"}
_GHIDRA_REPORT_SCRIPT = """#@category InCypher
#@runtime Jython
from ghidra.program.model.listing import CodeUnit

args = getScriptArgs()
report_path = args[0]
operation = args[1]
program = currentProgram
lines = []
lines.append("program=" + program.getName())
lines.append("language=" + str(program.getLanguageID()))
lines.append("image_base=" + str(program.getImageBase()))

if operation == "summary" or operation == "functions":
    count = 0
    for function in program.getFunctionManager().getFunctions(True):
        lines.append("function\\t%s\\t%s" % (function.getEntryPoint(), function.getName()))
        count += 1
        if count >= 500:
            lines.append("function_limit_reached=true")
            break

if operation == "summary" or operation == "strings":
    count = 0
    listing = program.getListing()
    data_iterator = listing.getDefinedData(True)
    while data_iterator.hasNext():
        data = data_iterator.next()
        value = data.getValue()
        if isinstance(value, basestring) and len(value) >= 4:
            lines.append("string\\t%s\\t%s" % (data.getAddress(), value.replace("\\n", "\\\\n")))
            count += 1
            if count >= 500:
                lines.append("string_limit_reached=true")
                break

handle = open(report_path, "w")
handle.write("\\n".join(lines))
handle.close()
"""


def run_ghidra_analysis(
    binary_path: str | Path,
    *,
    operation: GhidraOperation,
    ghidra_headless_path: str | Path | None = None,
    timeout: float = 60.0,
) -> dict[str, Any]:
    """Import a binary into a temporary Ghidra project and return a text report.

    The wrapper never executes the challenge binary. Its project and temporary
    script are discarded after the report has been read.
    """
    target = Path(binary_path).resolve()
    if not target.is_file():
        raise FileNotFoundError(f"Binary does not exist or is not a file: {target}")
    if operation not in _OPERATIONS:
        raise ValueError(f"Unsupported Ghidra operation: {operation}")
    executable = resolve_tool(
        configured_path=ghidra_headless_path,
        environment_variable="GHIDRA_HEADLESS_PATH",
        candidates=("analyzeHeadless", "analyzeHeadless.bat"),
    )
    with tempfile.TemporaryDirectory(prefix="incypher-ghidra-") as temporary:
        root = Path(temporary)
        project_directory = root / "project"
        script_directory = root / "scripts"
        script_directory.mkdir()
        report_path = root / "report.txt"
        script_path = script_directory / "InCypherReport.py"
        script_path.write_text(_GHIDRA_REPORT_SCRIPT, encoding="utf-8")
        command = [
            executable,
            str(project_directory),
            "InCypherProject",
            "-import",
            str(target),
            "-analysisTimeoutPerFile",
            str(int(timeout)),
            "-scriptPath",
            str(script_directory),
            "-postScript",
            script_path.name,
            str(report_path),
            operation,
        ]
        result = run_external_tool(command, timeout=timeout, cwd=target.parent)
        report = report_path.read_text(encoding="utf-8", errors="replace")[:64 * 1024] if report_path.is_file() else ""
    return {
        "operation": operation,
        "returncode": result.returncode,
        "report": report,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "output_truncated": result.output_truncated,
    }
