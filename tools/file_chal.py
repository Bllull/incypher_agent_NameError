"""Delegation shell for authorized file-based CTF challenges."""

from __future__ import annotations

from collections.abc import Callable
import hashlib
import os
import re
from pathlib import Path
from typing import Any

from tools.context import append_context_list, get_context, update_context
from tools.executable_client import ExecutableClient, ExecutableClientError, ProcessPolicy
from tools.flags import extract_flag


FileSolver = Callable[[int, dict[str, Any]], str | None]
REV_SOLVER_MAX_PASSES = 5
REV_ATTEMPT_HISTORY_LIMIT = 10
REV_MAX_STATIC_CANDIDATES = 16
REV_MAX_CANDIDATE_BYTES = 64


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

    prior_attempts = _rev_attempt_summaries(context)[-REV_ATTEMPT_HISTORY_LIMIT:]
    known_probes = _known_probe_signatures(context)
    analyzed_artifacts = _analyzed_artifact_hashes(context)
    prior_passes = _recorded_rev_passes(context)
    pass_records: list[dict[str, object]] = []
    summaries: list[dict[str, object]] = []
    for pass_number in range(1, REV_SOLVER_MAX_PASSES + 1):
        print(
            f"[rev] Challenge {chal_ID}: starting pass {pass_number}/"
            f"{REV_SOLVER_MAX_PASSES} with {len(prior_attempts) + len(summaries)} prior summary/summaries."
        )
        flag, report = _run_rev_solver_pass(
            chal_ID,
            paths,
            prior_attempts=[*prior_attempts, *summaries],
            known_probes=known_probes,
            analyzed_artifacts=analyzed_artifacts,
        )
        new_probe_entries = report.pop("new_probe_entries", [])
        if isinstance(new_probe_entries, list):
            known_probes.update(_probe_entry_signature(entry) for entry in new_probe_entries)
            if new_probe_entries:
                append_context_list(new_probe_entries, "rev_probe_ledger", chal_ID, unique=True)
        ordinal = prior_passes + pass_number
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
            _persist_rev_attempt_summaries(chal_ID, summaries)
            return flag
    append_context_list(pass_records, "rev_solver_passes", chal_ID, unique=True)
    _persist_rev_attempt_summaries(chal_ID, summaries)
    return None


def _run_rev_solver_pass(
    chal_ID: int,
    paths: list[Path],
    *,
    prior_attempts: list[dict[str, object]],
    known_probes: set[str],
    analyzed_artifacts: set[str],
) -> tuple[str | None, dict[str, object]]:
    """Run one finite pass, carrying prior outcomes into the current solve call."""
    report: dict[str, object] = {
        "artifact_count": len(paths),
        "prior_attempts_considered": len(prior_attempts),
        "reconnaissance_completed": 0,
        "executable_probe_paths": 0,
        "overflow_probe_paths": 0,
        "format_probe_paths": 0,
        "static_candidate_probe_paths": 0,
        "static_analysis_paths": 0,
        "new_probe_entries": [],
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

    baseline_probe_ran = False
    for path, finding in zip(paths, findings):
        if not _is_locally_executable(path):
            print(f"[rev] Skipping dynamic probes for non-executable artifact: {path.name}")
            continue
        artifact_hash = _artifact_hash(finding)
        payloads, entries = _unseen_probe_payloads(
            artifact_hash, "basic_input", _HARMLESS_INPUTS, known_probes
        )
        if payloads:
            print(f"[rev] Running bounded basic-input probes: {path.name}")
            observations, flag = _probe_executable(path, payloads)
            baseline_probe_ran = True
            report["executable_probe_paths"] = int(report["executable_probe_paths"]) + 1
            report["new_probe_entries"].extend(entries)
            append_context_list(observations, "rev_input_observations", chal_ID, unique=True)
            if flag:
                return flag, report
    for path, finding in zip(paths, findings):
        triage = _exploit_triage(path, finding)
        append_context_list([triage], "rev_exploit_triage", chal_ID, unique=True)
        if not _is_locally_executable(path):
            continue
        artifact_hash = _artifact_hash(finding)
        if triage["overflow_probe_eligible"]:
            payloads, entries = _unseen_probe_payloads(
                artifact_hash,
                "overflow_boundary",
                tuple(b"A" * length for length in _OVERFLOW_LENGTHS),
                known_probes,
            )
            if payloads:
                print(f"[rev] Running bounded overflow-boundary probes: {path.name}")
                observations, flag = _run_input_probes(path, payloads, probe_type="overflow_boundary")
                baseline_probe_ran = True
                report["overflow_probe_paths"] = int(report["overflow_probe_paths"]) + 1
                report["new_probe_entries"].extend(entries)
                append_context_list(observations, "rev_overflow_observations", chal_ID, unique=True)
                if flag:
                    return flag, report
        if triage["format_probe_eligible"]:
            payloads, entries = _unseen_probe_payloads(
                artifact_hash, "format_read", _FORMAT_READ_PROBES, known_probes
            )
            if payloads:
                print(f"[rev] Running read-only format-string probes: {path.name}")
                observations, flag = _run_input_probes(path, payloads, probe_type="format_read")
                baseline_probe_ran = True
                report["format_probe_paths"] = int(report["format_probe_paths"]) + 1
                report["new_probe_entries"].extend(entries)
                append_context_list(observations, "rev_format_observations", chal_ID, unique=True)
                if flag:
                    return flag, report
    if not baseline_probe_ran:
        for path, finding in zip(paths, findings):
            artifact_hash = _artifact_hash(finding)
            if artifact_hash in analyzed_artifacts:
                continue
            analysis = _static_rev_analysis(path, finding)
            analyzed_artifacts.add(artifact_hash)
            report["static_analysis_paths"] = int(report["static_analysis_paths"]) + 1
            append_context_list([analysis], "rev_static_analysis", chal_ID, unique=True)
            if not _is_locally_executable(path):
                continue
            candidates = _static_candidates(analysis)
            payloads, entries = _unseen_probe_payloads(
                artifact_hash, "static_candidate", candidates, known_probes
            )
            if not payloads:
                continue
            print(f"[rev] Verifying {len(payloads)} static candidate input(s): {path.name}")
            observations, flag = _run_input_probes(path, payloads, probe_type="static_candidate")
            report["static_candidate_probe_paths"] = int(report["static_candidate_probe_paths"]) + 1
            report["new_probe_entries"].extend(entries)
            append_context_list(observations, "rev_static_candidate_observations", chal_ID, unique=True)
            if flag:
                return flag, report
    return None, report


def _rev_attempt_summaries(context: dict[str, Any]) -> list[dict[str, object]]:
    """Read only well-formed persisted summaries for use in the next solve pass."""
    values = context.get("rev_attempt_summaries", [])
    if not isinstance(values, list):
        return []
    return [value for value in values if isinstance(value, dict)]


def _persist_rev_attempt_summaries(chal_ID: int, summaries: list[dict[str, object]]) -> None:
    """Keep only a bounded hand-off history; concrete evidence remains intact."""
    existing = _rev_attempt_summaries(get_context(chal_ID) or {})
    update_context(
        {"rev_attempt_summaries": [*existing, *summaries][-REV_ATTEMPT_HISTORY_LIMIT:]},
        chal_ID,
    )


def _recorded_rev_passes(context: dict[str, Any]) -> int:
    """Return the highest persisted pass number for stable pass labels."""
    values = context.get("rev_solver_passes", [])
    if not isinstance(values, list):
        return 0
    return max(
        (value.get("pass", 0) for value in values if isinstance(value, dict) and isinstance(value.get("pass"), int)),
        default=0,
    )


def _artifact_hash(finding: dict[str, object]) -> str:
    """Return a stable artifact identity for deterministic probe caching."""
    value = finding.get("sha256")
    return value if isinstance(value, str) and value else "unknown-artifact"


def _probe_entry_signature(entry: object) -> str:
    """Canonicalize one ledger entry without retaining the probe payload itself."""
    if not isinstance(entry, dict):
        return ""
    artifact_hash = entry.get("artifact_sha256")
    probe_type = entry.get("probe_type")
    payload_hash = entry.get("payload_sha256")
    if not all(isinstance(value, str) for value in (artifact_hash, probe_type, payload_hash)):
        return ""
    return f"{artifact_hash}:{probe_type}:{payload_hash}"


def _known_probe_signatures(context: dict[str, Any]) -> set[str]:
    """Read the durable probe ledger without treating it as solver progress."""
    values = context.get("rev_probe_ledger", [])
    if not isinstance(values, list):
        return set()
    return {signature for value in values if (signature := _probe_entry_signature(value))}


def _analyzed_artifact_hashes(context: dict[str, Any]) -> set[str]:
    """Return artifact hashes that already completed the generic static pipeline."""
    values = context.get("rev_static_analysis", [])
    if not isinstance(values, list):
        return set()
    return {
        value["artifact_sha256"]
        for value in values
        if isinstance(value, dict) and isinstance(value.get("artifact_sha256"), str)
    }


def _unseen_probe_payloads(
    artifact_hash: str,
    probe_type: str,
    payloads: tuple[bytes, ...],
    known_signatures: set[str],
) -> tuple[tuple[bytes, ...], list[dict[str, str]]]:
    """Select only payloads not already executed against this exact artifact."""
    selected: list[bytes] = []
    entries: list[dict[str, str]] = []
    for payload in payloads:
        payload_hash = hashlib.sha256(payload).hexdigest()
        entry = {
            "artifact_sha256": artifact_hash,
            "probe_type": probe_type,
            "payload_sha256": payload_hash,
        }
        signature = _probe_entry_signature(entry)
        if signature in known_signatures:
            continue
        selected.append(payload)
        entries.append(entry)
        known_signatures.add(signature)
    return tuple(selected), entries


def _static_rev_analysis(path: Path, finding: dict[str, object]) -> dict[str, object]:
    """Run evidence-gated, format-agnostic recognizers on one local CTF artifact."""
    data = path.read_bytes()[:_MAX_RECON_BYTES]
    strings = finding.get("strings", [])
    text_strings = [value for value in strings if isinstance(value, str)]
    recognizers = [
        _recognize_state_machine(data, text_strings),
        _recognize_hardcoded_comparator(text_strings),
        _recognize_transform_or_hash(text_strings),
        _recognize_encoding_or_vm(text_strings),
    ]
    candidates = [
        candidate
        for recognizer in recognizers
        for candidate in recognizer.pop("candidate_inputs", [])
        if isinstance(candidate, str)
    ][:REV_MAX_STATIC_CANDIDATES]
    return {
        "path": str(path),
        "artifact_sha256": _artifact_hash(finding),
        "pipeline": ["format", "entrypoint", "strings", "recognizers", "candidate_verifier"],
        "recognizers": recognizers,
        "candidate_inputs": candidates,
    }


def _recognize_state_machine(data: bytes, strings: list[str]) -> dict[str, object]:
    """Find small input alphabets and embedded transition-like candidate sequences."""
    alphabet = ""
    for value in strings:
        match = re.search(r"\(([A-Za-z0-9](?:/[A-Za-z0-9]){1,15})\)", value)
        if match:
            alphabet = "".join(match.group(1).split("/"))
            break
    if not alphabet:
        return {"name": "state_machine", "status": "no_small_alphabet_evidence"}
    candidates = _alphabet_runs(data, alphabet)
    return {
        "name": "state_machine",
        "status": "small_alphabet_evidence",
        "alphabet": alphabet,
        "candidate_inputs": candidates,
    }


def _alphabet_runs(data: bytes, alphabet: str) -> list[str]:
    """Extract bounded printable runs over an evidenced alphabet for local verification."""
    allowed = set(alphabet.encode("ascii", errors="ignore"))
    candidates: list[str] = []
    current = bytearray()
    for value in data:
        if value in allowed:
            current.append(value)
            continue
        if 2 <= len(current) <= REV_MAX_CANDIDATE_BYTES:
            candidate = current.decode("ascii")
            if candidate not in candidates:
                candidates.append(candidate)
        current.clear()
        if len(candidates) >= REV_MAX_STATIC_CANDIDATES:
            break
    if 2 <= len(current) <= REV_MAX_CANDIDATE_BYTES and len(candidates) < REV_MAX_STATIC_CANDIDATES:
        candidate = current.decode("ascii")
        if candidate not in candidates:
            candidates.append(candidate)
    return candidates


def _recognize_hardcoded_comparator(strings: list[str]) -> dict[str, object]:
    """Record comparator evidence without assuming a plaintext secret exists."""
    markers = sorted({marker for marker in ("strcmp", "strncmp", "memcmp") if marker in "\n".join(strings).lower()})
    return {
        "name": "hardcoded_comparator",
        "status": "evidence" if markers else "no_evidence",
        "markers": markers,
    }


def _recognize_transform_or_hash(strings: list[str]) -> dict[str, object]:
    """Record reversible-transform and digest evidence for later specialists."""
    lowered = "\n".join(strings).lower()
    transforms = sorted({marker for marker in ("xor", "encrypt", "decrypt", "rotate") if marker in lowered})
    hashes = sorted({marker for marker in ("sha256", "sha-256", "md5", "sha1") if marker in lowered})
    return {"name": "transform_or_hash", "status": "evidence" if transforms or hashes else "no_evidence", "transforms": transforms, "hashes": hashes}


def _recognize_encoding_or_vm(strings: list[str]) -> dict[str, object]:
    """Record encoding and interpreter-dispatch hints without executing them."""
    lowered = "\n".join(strings).lower()
    encodings = sorted({marker for marker in ("base64", "zlib", "gzip", "decode") if marker in lowered})
    vm_markers = sorted({marker for marker in ("bytecode", "opcode", "interpreter", "virtual machine") if marker in lowered})
    return {"name": "encoding_or_vm", "status": "evidence" if encodings or vm_markers else "no_evidence", "encodings": encodings, "vm_markers": vm_markers}


def _static_candidates(analysis: dict[str, object]) -> tuple[bytes, ...]:
    """Return bounded printable candidates emitted by the static recognizers."""
    values = analysis.get("candidate_inputs", [])
    if not isinstance(values, list):
        return ()
    return tuple(
        value.encode("ascii")
        for value in values[:REV_MAX_STATIC_CANDIDATES]
        if isinstance(value, str) and 0 < len(value.encode("ascii", errors="ignore")) <= REV_MAX_CANDIDATE_BYTES
    )


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
