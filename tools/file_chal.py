"""Delegation shell for authorized file-based CTF challenges."""

from __future__ import annotations

from collections.abc import Callable
import hashlib
import os
import re
from pathlib import Path
from typing import Any

from tools.context import append_context_list, get_context
from tools.executable_client import ExecutableClient, ExecutableClientError, ProcessPolicy
from tools.flags import extract_flag


FileSolver = Callable[[int, dict[str, Any]], str | None]
REV_SOLVER_MAX_PASSES = 5


def _category_key(category: object) -> str:
    """Normalize CTFd category labels without guessing an unsupported solver."""
    if not isinstance(category, str):
        return ""
    return "".join(character for character in category.lower() if character.isalnum())


def _not_implemented(kind: str, chal_ID: int, context: dict[str, Any]) -> None:
    """Record a safe hand-off point for a future specialist file solver."""
    file_paths = context.get("file_paths", [])
    print(f"[file][{kind}] Challenge {chal_ID} is awaiting its specialist solver.")
    append_context_list(
        [{"solver": kind, "event": "specialist_solver_unavailable", "file_count": len(file_paths) if isinstance(file_paths, list) else 0}],
        "file_solver_attempts",
        chal_ID,
    )


def pwn_file_solver(chal_ID: int, context: dict[str, Any]) -> str | None:
    """Reserved handler for local binary-exploitation challenge artifacts."""
    _not_implemented("pwn", chal_ID, context)
    return None


def rev_file_solver(chal_ID: int, context: dict[str, Any]) -> str | None:
    """Perform up to five bounded solve passes before yielding to the scheduler."""
    paths = _challenge_paths(context)
    if not paths:
        _not_implemented("rev", chal_ID, context)
        return None

    prior_attempts = _rev_attempt_summaries(context)
    pass_records: list[dict[str, object]] = []
    summaries: list[dict[str, object]] = []
    for pass_number in range(1, REV_SOLVER_MAX_PASSES + 1):
        print(
            f"[rev] Challenge {chal_ID}: starting pass {pass_number}/"
            f"{REV_SOLVER_MAX_PASSES} with {len(prior_attempts) + len(summaries)} prior summary/summaries."
        )
        flag, report = _run_rev_solver_pass(
            chal_ID, paths, prior_attempts=[*prior_attempts, *summaries]
        )
        ordinal = len(prior_attempts) + pass_number
        pass_records.append(
            {
                "pass": ordinal,
                "outcome": "flag_found" if flag else "no_flag",
            }
        )
        summaries.append(
            _describe_rev_pass(
                ordinal=ordinal,
                prior_attempt_count=len(prior_attempts) + len(summaries),
                report=report,
                flag_found=bool(flag),
            )
        )
        print(f"[rev] Challenge {chal_ID}: {summaries[-1]['description']}")
        if flag:
            append_context_list(pass_records, "rev_solver_passes", chal_ID, unique=True)
            append_context_list(summaries, "rev_attempt_summaries", chal_ID, unique=True)
            return flag
    append_context_list(pass_records, "rev_solver_passes", chal_ID, unique=True)
    append_context_list(summaries, "rev_attempt_summaries", chal_ID, unique=True)
    return None


def _run_rev_solver_pass(
    chal_ID: int, paths: list[Path], *, prior_attempts: list[dict[str, object]]
) -> tuple[str | None, dict[str, object]]:
    """Run one finite pass, carrying prior outcomes into the current solve call."""
    report: dict[str, object] = {
        "artifact_count": len(paths),
        "prior_attempts_considered": len(prior_attempts),
        "reconnaissance_completed": 0,
        "executable_probe_paths": 0,
        "overflow_probe_paths": 0,
        "format_probe_paths": 0,
    }
    print(
        f"[rev] Challenge {chal_ID}: static reconnaissance of {len(paths)} local artifact(s)."
    )
    findings: list[dict[str, object]] = []
    for path in paths:
        finding, flag = _reconnaissance(path)
        findings.append(finding)
        report["reconnaissance_completed"] = int(report["reconnaissance_completed"]) + 1
        if flag:
            append_context_list(findings, "rev_reconnaissance", chal_ID, unique=True)
            return flag, report
    append_context_list(findings, "rev_reconnaissance", chal_ID, unique=True)

    for path in paths:
        if not _is_locally_executable(path):
            print(f"[rev] Skipping dynamic probes for non-executable artifact: {path.name}")
            continue
        print(f"[rev] Running bounded basic-input probes: {path.name}")
        observations, flag = _probe_executable(path)
        report["executable_probe_paths"] = int(report["executable_probe_paths"]) + 1
        append_context_list(observations, "rev_input_observations", chal_ID, unique=True)
        if flag:
            return flag, report
    for path, finding in zip(paths, findings):
        triage = _exploit_triage(path, finding)
        append_context_list([triage], "rev_exploit_triage", chal_ID, unique=True)
        if not _is_locally_executable(path):
            continue
        if triage["overflow_probe_eligible"]:
            print(f"[rev] Running bounded overflow-boundary probes: {path.name}")
            observations, flag = _probe_overflow_boundaries(path)
            report["overflow_probe_paths"] = int(report["overflow_probe_paths"]) + 1
            append_context_list(observations, "rev_overflow_observations", chal_ID, unique=True)
            if flag:
                return flag, report
        if triage["format_probe_eligible"]:
            print(f"[rev] Running read-only format-string probes: {path.name}")
            observations, flag = _probe_format_strings(path)
            report["format_probe_paths"] = int(report["format_probe_paths"]) + 1
            append_context_list(observations, "rev_format_observations", chal_ID, unique=True)
            if flag:
                return flag, report
    return None, report


def _rev_attempt_summaries(context: dict[str, Any]) -> list[dict[str, object]]:
    """Read only well-formed persisted summaries for use in the next solve pass."""
    values = context.get("rev_attempt_summaries", [])
    if not isinstance(values, list):
        return []
    return [value for value in values if isinstance(value, dict)]


def _describe_rev_pass(
    *,
    ordinal: int,
    prior_attempt_count: int,
    report: dict[str, object],
    flag_found: bool,
) -> dict[str, object]:
    """Create a bounded hand-off summary for later solver and model calls."""
    outcome = "An INCYPHER flag was recovered; stop further probing." if flag_found else (
        "No flag was recovered in this bounded pass; preserve these results for the next pass."
    )
    description = (
        f"Reverse-engineering pass {ordinal} considered {prior_attempt_count} prior attempt "
        f"summary/summaries. It completed static reconnaissance on "
        f"{report['reconnaissance_completed']} of {report['artifact_count']} artifact(s), then ran "
        f"basic input probes on {report['executable_probe_paths']} executable(s), overflow-boundary "
        f"probes on {report['overflow_probe_paths']} executable(s), and read-only format-string probes "
        f"on {report['format_probe_paths']} executable(s). {outcome}"
    )
    return {
        "pass": ordinal,
        "outcome": "flag_found" if flag_found else "no_flag",
        "description": description,
        "report": report,
    }


def forensics_file_solver(chal_ID: int, context: dict[str, Any]) -> str | None:
    """Reserved handler for forensic challenge artifacts."""
    _not_implemented("forensics", chal_ID, context)
    return None


def cryptography_file_solver(chal_ID: int, context: dict[str, Any]) -> str | None:
    """Reserved handler for cryptography challenge artifacts."""
    _not_implemented("cryptography", chal_ID, context)
    return None


# Future specialist solvers only replace one handler; the agent remains generic.
FILE_SOLVERS: dict[str, FileSolver] = {
    "pwn": pwn_file_solver,
    "rev": rev_file_solver,
    "forensics": forensics_file_solver,
    "cryptography": cryptography_file_solver,
}
CATEGORY_ALIASES = {
    "pwn": "pwn",
    "(Practice) pwn": "pwn",
    "practicepwn": "pwn",
    "binaryexploitation": "pwn",
    "binary": "pwn",
    "re": "rev",
    "rev": "rev",
    "(Practice) rev": "rev",
    "practicerev": "rev",
    "reverse": "rev",
    "reversing": "rev",
    "reverseengineering": "rev",
    "forensics": "forensics",
    "(Practice) forensics": "forensics",
    "practiceforensics": "forensics",
    "forensic": "forensics",
    "crypto": "cryptography",
    "(Practice) cryptography": "cryptography",
    "cryptography": "cryptography",
    "practicecrypto": "cryptography",
    "practicecryptography": "cryptography",
}


def file_chal_solver(chal_ID: int) -> str | None:
    """Delegate one file challenge to its category-specific specialist solver."""
    context = get_context(chal_ID)
    if context is None:
        print(f"[file] Challenge {chal_ID} has no prepared context.")
        return None
    category = CATEGORY_ALIASES.get(_category_key(context.get("category")))
    if category is None:
        print(f"[file] Challenge {chal_ID} has unsupported category: {context.get('category')!r}")
        append_context_list(
            [{"event": "unsupported_category", "category": str(context.get("category", ""))}],
            "file_solver_attempts",
            chal_ID,
        )
        return None
    return FILE_SOLVERS[category](chal_ID, context)


def file_chal_progress(chal_ID: int) -> dict[str, object]:
    """Return durable local-artifact evidence without running a file solver."""
    context = get_context(chal_ID) or {}
    return {
        "category": context.get("category"),
        "file_path": context.get("file_path"),
        "file_paths": context.get("file_paths", []),
        "converted_file_paths": context.get("converted_file_paths", []),
    }


_MAX_RECON_BYTES = 8 * 1024 * 1024
_MAX_STRINGS = 200
_REPO_ROOT = Path(__file__).resolve().parent.parent
_HARMLESS_INPUTS = (b"", b"test", b"AAAA", b"1")
_OVERFLOW_LENGTHS = (32, 64, 128, 256)
_FORMAT_READ_PROBES = (b"%p", b"%x", b"%08x")
_UNSAFE_INPUT_FUNCTIONS = ("gets", "strcpy", "strcat", "sprintf", "scanf", "read")
_FORMAT_FUNCTIONS = ("printf", "fprintf", "sprintf", "snprintf", "vprintf")
_ENCRYPTION_MARKERS = ("xor", "encrypt", "decrypt", "aes", "sha256", "sha-256", "md5")


def _challenge_paths(context: dict[str, Any]) -> list[Path]:
    """Return unique, existing workspace-local artifact paths from context."""
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
        try:
            path.relative_to(_REPO_ROOT)
        except ValueError:
            continue
        if path.is_file() and path not in paths:
            paths.append(path)
    return paths


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
    return magic == b"\x7fE" and os.access(path, os.X_OK)


def _probe_executable(path: Path) -> tuple[list[dict[str, object]], str | None]:
    """Run harmless bounded line-input probes through ``ExecutableClient``."""
    client = ExecutableClient(
        ProcessPolicy(
            workspace_root=_REPO_ROOT,
            allowed_executables=(path,),
            max_runtime_seconds=5,
            max_read_bytes=2_048,
            max_total_output_bytes=16_384,
        )
    )
    observations: list[dict[str, object]] = []
    for payload in _HARMLESS_INPUTS:
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
            workspace_root=_REPO_ROOT,
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
                    "possible_crash": exit_code not in (None, 0),
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
