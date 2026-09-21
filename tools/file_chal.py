"""Evidence-driven LLM orchestration for local file-based CTF challenges."""

from __future__ import annotations

from collections.abc import Callable
import hashlib
import os
import re
from pathlib import Path
from typing import Any

import base64
import json
import mimetypes
from pathlib import Path
from typing import Any

from tools.context import get_context, update_context
from tools.converter import SPECTROGRAM, WAVEFORM, convert_audio_file, extract_zip_archive
from tools.file_solve_tools import FileToolRequest, FileToolResult, execute_file_tool
from tools.flags import extract_flag, extract_flag_from_json

_FILE_TOOL_NAMES = {"inspect", "gdb", "wireshark", "ghidra", "cyberchef"}
_FILE_ACTIONS = _FILE_TOOL_NAMES | {"extract_zip", "convert_audio", "run_executable"}
MAX_FILE_TOOL_HISTORY = 16
MAX_EVIDENCE_CHARS = 6_000


def call_openai(*args: Any, **kwargs: Any) -> str:
    """Load the configured LLM client only when an action needs planning."""
    from tools.llm_router import call_openai as configured_call_openai

    return configured_call_openai(*args, **kwargs)


def _paths(context: dict[str, Any]) -> list[Path]:
    file_paths = context.get("file_paths", [])
    if not isinstance(file_paths, list):
        file_paths = []
    converted_paths = context.get("converted_file_paths", [])
    if not isinstance(converted_paths, list):
        converted_paths = []
    values: list[object] = [context.get("file_path"), *file_paths, *converted_paths]
    result: list[Path] = []
    seen: set[Path] = set()
    for value in values:
        if not isinstance(value, str) or not value.strip():
            continue
        path = Path(value).resolve()
        if path.is_file() and path not in seen:
            result.append(path)
            seen.add(path)
    return result


def _artifact_inventory(paths: list[Path]) -> list[dict[str, object]]:
    inventory: list[dict[str, object]] = []
    for path in paths:
        try:
            size = path.stat().st_size
        except OSError:
            continue
        mime, _ = mimetypes.guess_type(path.name)
        inventory.append({"path": str(path), "name": path.name, "suffix": path.suffix.lower(),
                          "mime_type": mime, "size": size})
    return inventory


def _configured_executable_client(context: dict[str, Any]) -> Any | None:
    """Build a process client only when an explicit challenge allowlist exists."""
    raw = context.get("allowed_executables", [])
    if not isinstance(raw, list) or not all(isinstance(item, str) for item in raw):
        return None
    paths = tuple(Path(item).resolve() for item in raw)
    if not paths:
        return None
    root = context.get("executable_workspace_root")
    workspace = Path(root).resolve() if isinstance(root, str) and root else Path.cwd().resolve()
    try:
        from tools.executable_client import ExecutableClient, ProcessPolicy
    except ModuleNotFoundError as exc:
        print(f"[file] Executable tool unavailable: {exc}")
        return None
    return ExecutableClient(ProcessPolicy(workspace_root=workspace, allowed_executables=paths))


def _bounded_evidence(value: object) -> dict[str, object]:
    """Produce JSON-safe, bounded durable evidence for the next LLM turn."""
    encoded = json.dumps(value, sort_keys=True, default=str)
    if len(encoded) <= MAX_EVIDENCE_CHARS and isinstance(value, dict):
        return value
    return {"truncated": True, "preview": encoded[:MAX_EVIDENCE_CHARS]}


def _recent_tool_results(context: dict[str, Any]) -> list[dict[str, object]]:
    results = context.get("file_tool_results", [])
    if not isinstance(results, list):
        return []
    return [item for item in results if isinstance(item, dict)][-MAX_FILE_TOOL_HISTORY:]


def _record_result(chal_ID: int, result: FileToolResult) -> None:
    """Save one completed action before the next LLM loop begins."""
    context = get_context(chal_ID) or {}
    history = [*_recent_tool_results(context), _bounded_evidence(result.as_dict())]
    update_context(
        {
            "file_tool_results": history[-MAX_FILE_TOOL_HISTORY:],
            "file_solver_state": {
                "last_tool": result.tool,
                "last_status": result.status,
                "last_artifact_path": result.artifact_path,
                "last_flag": result.flag,
            },
        },
        chal_ID,
    )


def _planner_error(chal_ID: int, message: str) -> None:
    """Store malformed plans as evidence so the next turn can correct them."""
    _record_result(
        chal_ID,
        FileToolResult(tool="planner", artifact_path="", status="error", output={"error": message}),
    )


def _parse_action(raw_plan: str, artifact_paths: list[Path]) -> tuple[dict[str, object], str]:
    """Validate one model-selected tool action against the current inventory."""
    cleaned = raw_plan.strip()
    if cleaned.startswith("```"):
        cleaned = cleaned.split("\n", 1)[1].rsplit("```", 1)[0].strip()
    plan = json.loads(cleaned)
    if not isinstance(plan, dict):
        raise ValueError("File solver plan must be a JSON object")
    action = plan.get("action")
    hypothesis = plan.get("hypothesis")
    if not isinstance(action, dict) or not isinstance(hypothesis, str) or not hypothesis.strip():
        raise ValueError("File solver plan requires an action and non-empty hypothesis")
    tool = action.get("tool")
    artifact_path = action.get("artifact_path")
    arguments = action.get("arguments", {})
    if tool not in _FILE_ACTIONS:
        raise ValueError(f"Unsupported file action: {tool!r}")
    if not isinstance(artifact_path, str) or not isinstance(arguments, dict):
        raise ValueError("File action requires artifact_path and object arguments")
    path = Path(artifact_path).resolve()
    if path not in {candidate.resolve() for candidate in artifact_paths}:
        raise ValueError("File action must target an artifact in the inventory")
    json.dumps(arguments)
    return {"tool": tool, "artifact_path": str(path), "arguments": arguments}, hypothesis


def _execute_action(action: dict[str, object], chal_ID: int, context: dict[str, Any]) -> FileToolResult:
    """Execute one agent action using the module that owns that capability."""
    tool = str(action["tool"])
    artifact_path = str(action["artifact_path"])
    arguments = action["arguments"]
    assert isinstance(arguments, dict)
    try:
        if tool in _FILE_TOOL_NAMES:
            return execute_file_tool(FileToolRequest(tool, artifact_path, arguments), chal_ID=chal_ID)
        if tool == "extract_zip":
            extracted = extract_zip_archive(artifact_path, chal_ID=chal_ID)
            return FileToolResult(
                tool=tool,
                artifact_path=artifact_path,
                status="ok",
                output={"extracted_count": len(extracted)},
                artifact_paths=tuple(str(path.resolve()) for path in extracted),
            )
        if tool == "convert_audio":
            representation = arguments.get("representation")
            conversion = {"spectrogram": SPECTROGRAM, "waveform": WAVEFORM}.get(representation)
            if conversion is None:
                raise ValueError("convert_audio requires 'spectrogram' or 'waveform'")
            output_path = convert_audio_file(artifact_path, conversion, chal_ID=chal_ID)
            return FileToolResult(
                tool=tool,
                artifact_path=artifact_path,
                status="ok",
                output={"representation": representation},
                artifact_paths=(str(output_path.resolve()),),
            )

        client = _configured_executable_client(context)
        if client is None:
            raise RuntimeError("run_executable requires an explicit executable allowlist")
        command_arguments = arguments.get("arguments", [])
        stdin = arguments.get("stdin", "")
        max_bytes = arguments.get("max_bytes", 4096)
        timeout = arguments.get("timeout", 5.0)
        if not isinstance(command_arguments, list) or not all(isinstance(item, str) for item in command_arguments):
            raise ValueError("run_executable arguments must be a list of strings")
        if not isinstance(stdin, str):
            raise ValueError("run_executable stdin must be a string")
        if not isinstance(max_bytes, int) or not 1 <= max_bytes <= 4096:
            raise ValueError("run_executable max_bytes must be between 1 and 4096")
        if not isinstance(timeout, (int, float)) or not 0 < timeout <= 15:
            raise ValueError("run_executable timeout must be between 0 and 15")
        session_id = client.launch(Path(artifact_path), command_arguments)
        try:
            if stdin:
                send = client.send_line if bool(arguments.get("send_line", False)) else client.send
                send(session_id, stdin.encode())
            output = client.receive(session_id, max_bytes, float(timeout))
            text = output.decode("utf-8", errors="replace")
            return FileToolResult(
                tool=tool,
                artifact_path=artifact_path,
                status="ok",
                output={
                    "output_text": text,
                    "output_b64": base64.b64encode(output).decode("ascii"),
                    "transcript": list(client.get_transcript(session_id)),
                },
                flag=extract_flag(text),
            )
        finally:
            client.close(session_id)
    except (OSError, TypeError, ValueError, RuntimeError) as exc:
        return FileToolResult(tool=tool, artifact_path=artifact_path, status="error", output={"error": str(exc)})


def _ask_for_action(chal_ID: int, context: dict[str, Any], inventory: list[dict[str, object]]) -> str:
    """Request one evidence-gated action; results are supplied on the next loop."""
    prompt = f"""You are solving an explicitly authorized local file-based InCypher CTF.
Choose exactly one action from inspect, extract_zip, convert_audio,
run_executable, gdb, wireshark, ghidra, cyberchef. Use only an exact
artifact_path listed in the inventory. The recent tool evidence is factual;
choose a different method when a prior result did not support its hypothesis.

Arguments:
- inspect: optional {{"max_bytes": integer <= 65536}}
- extract_zip: {{}}
- convert_audio: {{"representation": "spectrogram" | "waveform"}}
- run_executable: {{"arguments": [strings], "stdin": string, "send_line": boolean,
  "max_bytes": integer <= 4096, "timeout": number <= 15}} (allowlisted files only)
- gdb: {{"operation": "file_info" | "functions" | "variables" | "disassemble",
  "symbol": "simple_symbol"}}
- wireshark: {{"operation": "protocol_hierarchy" | "conversations" | "packet_fields",
  "display_filter": "optional", "max_packets": integer}}
- ghidra: {{"operation": "summary" | "functions" | "strings"}}
- cyberchef: {{"recipe": "operation name or saved recipe JSON"}}

Return JSON only:
{{"hypothesis": "brief evidence-based reason", "action": {{"tool": "allowed tool",
"artifact_path": "exact inventory path", "arguments": {{}}}}}}
Never return a speculative flag; flags must come from observed tool output.

Challenge ID: {chal_ID}
Challenge context:
{json.dumps({key: value for key, value in context.items() if key not in {"file_tool_results", "solver_scheduler", "solver_errors"}}, sort_keys=True, default=str)}

Artifact inventory:
{json.dumps(inventory, sort_keys=True)}

Recent tool evidence:
{json.dumps(_recent_tool_results(context), sort_keys=True, default=str)}
"""
    return call_openai(prompt, require_deep_reasoning=True)


def file_chal_solver(chal_ID: int) -> str | None:
    """Run internal LLM-selected tool turns until observed evidence yields a flag.

    Each completed action is written to persistent challenge context before the
    following action is planned. The outer orchestrator sees only this method's
    eventual flag or terminal failure, never individual tool turns.
    """
    while True:
        context = get_context(chal_ID) or {}
        artifacts = _paths(context)
        if not artifacts:
            _planner_error(chal_ID, "No available file artifacts")
            return None
        inventory = _artifact_inventory(artifacts)
        try:
            action, hypothesis = _parse_action(
                _ask_for_action(chal_ID, context, inventory), artifacts
            )
        except Exception as exc:
            _planner_error(chal_ID, str(exc))
            return None

        result = _execute_action(action, chal_ID, context)
        if result.flag is None:
            flag = extract_flag_from_json(result.as_dict())
            if flag:
                result = FileToolResult(
                    tool=result.tool,
                    artifact_path=result.artifact_path,
                    status=result.status,
                    output=result.output,
                    artifact_paths=result.artifact_paths,
                    flag=flag,
                )
        _record_result(chal_ID, result)
        print(f"[file] Challenge {chal_ID} hypothesis: {hypothesis}")
        print(f"[file] Challenge {chal_ID} {result.tool}: {result.status}")
        if result.flag:
            return result.flag


def file_chal_progress(chal_ID: int) -> dict[str, object]:
    """Return durable local-artifact evidence without running a file solver."""
    context = get_context(chal_ID) or {}
    return {
        "category": context.get("category"),
        "file_path": context.get("file_path"),
        "file_paths": context.get("file_paths", []),
        "converted_file_paths": context.get("converted_file_paths", []),
        "file_tool_results": _recent_tool_results(context),
        "file_solver_state": context.get("file_solver_state", {}),
    }


_MAX_RECON_BYTES = 8 * 1024 * 1024
_MAX_STRINGS = 200
_REPO_ROOT = Path(__file__).resolve().parent.parent
_WORK_ROOT = Path(os.getenv("IN_CYPHER_WORK_DIR", "/work")).resolve()
# Artifacts may be baked into the source tree for local tests or downloaded to
# the arena's writable work mount.  Do not accept arbitrary host paths.
_ALLOWED_ARTIFACT_ROOTS = (_REPO_ROOT, _WORK_ROOT)
_HARMLESS_INPUTS = (b"", b"test", b"AAAA", b"1")
_OVERFLOW_LENGTHS = (32, 64, 128, 256)
_FORMAT_READ_PROBES = (b"%p", b"%x", b"%08x")
_UNSAFE_INPUT_FUNCTIONS = ("gets", "strcpy", "strcat", "sprintf", "scanf", "read")
_FORMAT_FUNCTIONS = ("printf", "fprintf", "sprintf", "snprintf", "vprintf")
_ENCRYPTION_MARKERS = ("xor", "encrypt", "decrypt", "aes", "sha256", "sha-256", "md5")


def _challenge_paths(context: dict[str, Any]) -> list[Path]:
    """Return existing artifacts beneath the source tree or writable work mount."""
    values = context.get("file_paths", [])
    if not isinstance(values, list):
        values = []
    primary = context.get("file_path")
    if isinstance(primary, str):
        values = [primary, *values]
    paths: list[Path] = []
    for value in values:
        if not isinstance(value, str):
            continue
        path = Path(value).resolve()
        if not _is_allowed_artifact_path(path):
            continue
        if path.is_file() and path not in paths:
            paths.append(path)
    return paths


def _is_allowed_artifact_path(path: Path) -> bool:
    """Return whether a resolved artifact path remains inside an approved root."""
    for root in _ALLOWED_ARTIFACT_ROOTS:
        try:
            path.relative_to(root)
            return True
        except ValueError:
            continue
    return False


def _artifact_workspace_root(path: Path) -> Path:
    """Return the approved root enclosing an already-validated artifact path."""
    resolved_path = path.resolve()
    for root in _ALLOWED_ARTIFACT_ROOTS:
        try:
            resolved_path.relative_to(root)
            return root
        except ValueError:
            continue
    raise ValueError(f"Artifact is outside approved roots: {resolved_path}")


def _reconnaissance(path: Path) -> tuple[dict[str, object], str | None]:
    """Collect static, bounded metadata, strings, flag candidates, and ELF protections."""
    size = path.stat().st_size
    with path.open("rb") as artifact:
        data = artifact.read(_MAX_RECON_BYTES)
    strings = [match.decode("utf-8", errors="replace") for match in re.findall(rb"[ -~]{4,}", data)]
    strings = strings[:_MAX_STRINGS]
    flag_locations: list[dict[str, object]] = []
    for match in re.finditer(rb"INCYPHER\{[^\r\n}]{1,512}\}", data):
        candidate = match.group().decode("utf-8", errors="replace")
        flag_locations.append({"offset": match.start(), "candidate": candidate})
    protections = _elf_protections(path, data)
    finding: dict[str, object] = {
        "path": str(path),
        "size": size,
        "sha256": hashlib.sha256(data).hexdigest(),
        "truncated": size > len(data),
        "magic_hex": data[:16].hex(),
        "strings": strings,
        "flag_locations": flag_locations,
        "protections": protections,
    }
    flag = extract_flag(flag_locations[0]["candidate"]) if flag_locations else None
    return finding, flag


def _elf_protections(path: Path, data: bytes) -> dict[str, object]:
    """Read ELF entrypoint, common symbols, and standard binary mitigations."""
    if not data.startswith(b"\x7fELF"):
        return {"format": "PE" if data.startswith(b"MZ") else "unknown"}
    try:
        from pwn import ELF, context as pwn_context

        with pwn_context.local(log_level="error"):
            elf = ELF(str(path), checksec=False)
        interesting = ("_start", "main", "win", "flag", "print_flag")
        entrypoints = {
            name: address
            for name, address in elf.symbols.items()
            if name.lower() in interesting
        }
        return {
            "format": "ELF",
            "arch": elf.arch,
            "bits": elf.bits,
            "entrypoint": elf.entry,
            "entrypoints": entrypoints,
            "canary": bool(elf.canary),
            "pie": bool(elf.pie),
            "nx": bool(elf.nx),
            "relro": str(elf.relro),
            "pie_relative_offsets": {
                name: address for name, address in elf.symbols.items() if name.lower() in interesting
            },
            "canary_symbols": {
                name: address
                for name, address in elf.symbols.items()
                if "stack_chk" in name.lower() or "canary" in name.lower()
            },
            "decryption_candidates": {
                name: address
                for name, address in elf.symbols.items()
                if any(marker in name.lower() for marker in ("decrypt", "decode", "unpack", "copy"))
            },
        }
    except Exception as error:
        return {"format": "ELF", "parse_error": str(error)}


def _is_locally_executable(path: Path) -> bool:
    """Restrict dynamic probes to native executables suitable for this host."""
    with path.open("rb") as artifact:
        magic = artifact.read(4)
    if os.name == "nt":
        return magic == b"MZ" and path.suffix.lower() in {".exe", ".com"}
    return magic == b"\x7fELF" and os.access(path, os.X_OK)


def _probe_executable(
    path: Path, payloads: tuple[bytes, ...] = _HARMLESS_INPUTS
) -> tuple[list[dict[str, object]], str | None]:
    """Run harmless bounded line-input probes through ``ExecutableClient``."""
    client = ExecutableClient(
        ProcessPolicy(
            workspace_root=_artifact_workspace_root(path),
            allowed_executables=(path,),
            max_runtime_seconds=5,
            max_read_bytes=2_048,
            max_total_output_bytes=16_384,
        )
    )
    observations: list[dict[str, object]] = []
    for payload in payloads:
        session_id: str | None = None
        try:
            session_id = client.launch(path)
            opening = _receive_available(client, session_id)
            client.send_line(session_id, payload)
            response = _receive_available(client, session_id)
            text = (opening + response).decode("utf-8", errors="replace")
            observation = {"path": str(path), "input": payload.decode("ascii"), "response": text[:2_048]}
            observations.append(observation)
            flag = extract_flag(text)
            if flag:
                return observations, flag
        except ExecutableClientError as error:
            observations.append(
                {
                    "path": str(path),
                    "input": payload.decode("ascii"),
                    "error": str(error),
                    "partial_response": error.partial_data.decode("utf-8", errors="replace")[:2_048],
                }
            )
        finally:
            if session_id is not None:
                client.close(session_id)
    return observations, None


def _receive_available(client: ExecutableClient, session_id: str) -> bytes:
    """Treat an initial no-output timeout as an ordinary probe observation."""
    try:
        return client.receive(session_id, 2_048, 0.5)
    except ExecutableClientError as error:
        return error.partial_data


def _exploit_triage(path: Path, finding: dict[str, object]) -> dict[str, object]:
    """Create evidence-gated overflow, format, encryption, and debugger plans."""
    strings = finding.get("strings", [])
    strings = [value.lower() for value in strings if isinstance(value, str)]
    protections = finding.get("protections", {})
    protections = protections if isinstance(protections, dict) else {}
    unsafe_functions = sorted(
        {name for name in _UNSAFE_INPUT_FUNCTIONS if any(name in value for value in strings)}
    )
    format_functions = sorted(
        {name for name in _FORMAT_FUNCTIONS if any(name in value for value in strings)}
    )
    encryption_markers = sorted(
        {name for name in _ENCRYPTION_MARKERS if any(name in value for value in strings)}
    )
    canary_present = bool(protections.get("canary"))
    pie_present = bool(protections.get("pie"))
    return {
        "path": str(path),
        "unsafe_input_functions": unsafe_functions,
        "format_functions": format_functions,
        "encryption_markers": encryption_markers,
        "canary_present": canary_present,
        "canary_symbols": protections.get("canary_symbols", {}),
        "pie_present": pie_present,
        "pie_relative_offsets": protections.get("pie_relative_offsets", {}),
        "decryption_breakpoint_plan": {
            "candidates": protections.get("decryption_candidates", {}),
            "status": "requires_opt_in_debugger_outside_executable_client",
        },
        "overflow_probe_eligible": bool(unsafe_functions),
        "format_probe_eligible": bool(format_functions),
        "return_address_overwrite_status": (
            "requires_verified_offset_and_runtime_mitigation_evidence"
            if canary_present or pie_present
            else "requires_verified_offset_from_bounded_crash_triage"
        ),
        "encryption_analysis_plan": _encryption_analysis_plan(encryption_markers),
    }


def _probe_overflow_boundaries(path: Path) -> tuple[list[dict[str, object]], str | None]:
    """Use bounded cyclic-style padding to identify crash/length boundaries.

    This does not construct a control-flow payload. A return-address overwrite
    requires a verified offset plus runtime mitigation evidence first.
    """
    payloads = tuple(b"A" * length for length in _OVERFLOW_LENGTHS)
    return _run_input_probes(path, payloads, probe_type="overflow_boundary")


def _probe_format_strings(path: Path) -> tuple[list[dict[str, object]], str | None]:
    """Test read-only C format directives; never send the write directive ``%n``."""
    return _run_input_probes(path, _FORMAT_READ_PROBES, probe_type="format_read")


def _run_input_probes(
    path: Path, payloads: tuple[bytes, ...], *, probe_type: str
) -> tuple[list[dict[str, object]], str | None]:
    """Execute one bounded, local-only probe batch through ``ExecutableClient``."""
    client = ExecutableClient(
        ProcessPolicy(
            workspace_root=_artifact_workspace_root(path),
            allowed_executables=(path,),
            max_runtime_seconds=5,
            max_input_bytes=512,
            max_read_bytes=2_048,
            max_total_output_bytes=16_384,
        )
    )
    observations: list[dict[str, object]] = []
    for payload in payloads:
        session_id: str | None = None
        try:
            session_id = client.launch(path)
            opening = _receive_available(client, session_id)
            client.send_line(session_id, payload)
            response = _receive_available(client, session_id)
            exit_code = client.poll(session_id)
            text = (opening + response).decode("utf-8", errors="replace")
            observations.append(
                {
                    "path": str(path),
                    "probe_type": probe_type,
                    "input": payload.decode("ascii", errors="replace"),
                    "response": text[:2_048],
                    "exit_code": exit_code,
                    # A normal rejection may intentionally use exit status 1.
                    # Subprocess-style negative values indicate signal termination.
                    "possible_crash": isinstance(exit_code, int) and exit_code < 0,
                }
            )
            flag = extract_flag(text)
            if flag:
                return observations, flag
        except ExecutableClientError as error:
            observations.append(
                {
                    "path": str(path),
                    "probe_type": probe_type,
                    "input": payload.decode("ascii", errors="replace"),
                    "error": str(error),
                    "partial_response": error.partial_data.decode("utf-8", errors="replace")[:2_048],
                }
            )
        finally:
            if session_id is not None:
                client.close(session_id)
    return observations, None


def _encryption_analysis_plan(markers: list[str]) -> dict[str, object]:
    """Describe bounded next steps without assuming an encryption scheme exists."""
    if not markers:
        return {"status": "no_static_encryption_indicator"}
    plan: dict[str, object] = {"markers": markers}
    if "xor" in markers:
        plan["xor"] = "compare known plaintext/ciphertext pairs with derive_xor_key()"
    if "sha256" in markers or "sha-256" in markers:
        plan["sha256"] = "use build_byte_hash_rainbow_table('sha256') for byte-sized digest matches"
    return plan


def derive_xor_key(ciphertext: bytes, known_plaintext: bytes) -> bytes:
    """Derive a bytewise XOR key segment from equal-length known data pairs."""
    if not ciphertext or len(ciphertext) != len(known_plaintext):
        raise ValueError("ciphertext and known_plaintext must be non-empty and equal length")
    return bytes(left ^ right for left, right in zip(ciphertext, known_plaintext))


def build_byte_hash_rainbow_table(algorithm: str = "sha256") -> dict[str, int]:
    """Map each one-byte input digest to its source byte for local CTF analysis."""
    try:
        hashlib.new(algorithm)
    except ValueError as error:
        raise ValueError(f"Unsupported hash algorithm: {algorithm}") from error
    return {
        hashlib.new(algorithm, bytes([value])).hexdigest(): value
        for value in range(256)
    }
