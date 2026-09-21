"""Constrained local process interaction for authorized CTF artifacts.

This module deliberately exposes only bounded stdin/stdout operations.  It is
not a general shell, debugger, or networking interface.
"""

from __future__ import annotations

import base64
import os
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from time import monotonic
from typing import Any
from uuid import uuid4

from pwn import PIPE, STDOUT, context, process


class ExecutableClientError(RuntimeError):
    """Base class for constrained executable-client errors with I/O evidence."""

    def __init__(
        self,
        message: str,
        *,
        partial_data: bytes = b"",
        attempted_data: bytes = b"",
    ) -> None:
        super().__init__(message)
        self.partial_data = partial_data
        self.attempted_data = attempted_data


class ExecutableValidationError(ExecutableClientError):
    """The requested local executable or input is outside policy."""


class ExecutableLaunchError(ExecutableClientError):
    """The approved executable could not be started."""


class ExecutableTimeoutError(ExecutableClientError):
    """The process did not produce the requested output in time."""


class ExecutableOutputLimitError(ExecutableClientError):
    """The process exceeded its cumulative output allowance."""


class ExecutableProtocolError(ExecutableClientError):
    """A session ID is unknown, closed, or otherwise unusable."""


@dataclass(frozen=True)
class ProcessPolicy:
    """Limits for a restricted executable interaction."""

    workspace_root: Path
    allowed_executables: tuple[Path, ...]
    max_arguments: int = 32
    max_argument_bytes: int = 4_096
    max_input_bytes: int = 4_096
    max_runtime_seconds: float = 15.0
    max_read_bytes: int = 4_096
    max_total_output_bytes: int = 65_536
    max_transcript_events: int = 256
    environment_allowlist: tuple[str, ...] = (
        "COMSPEC",
        "PATHEXT",
        "SYSTEMROOT",
        "TEMP",
        "TMP",
        "USERPROFILE",
        "WINDIR",
    )
    redact_patterns: tuple[bytes, ...] = ()


@dataclass
class _Session:
    tube: Any
    executable: Path
    started_at: float
    output_bytes: int = 0
    closed: bool = False
    transcript: deque[dict[str, Any]] = field(default_factory=deque)


class ExecutableClient:
    """Run explicitly approved workspace executables with bounded tube I/O."""

    def __init__(self, policy: ProcessPolicy) -> None:
        self.policy = policy
        self._workspace_root = policy.workspace_root.resolve()
        self._allowed_executables = {
            executable.resolve() for executable in policy.allowed_executables
        }
        self._sessions: dict[str, _Session] = {}

    def launch(self, executable: Path, arguments: list[str] | tuple[str, ...] = ()) -> str:
        """Launch an allowlisted executable without a shell or caller environment."""
        executable_path = self._validate_executable(executable)
        argument_list = self._validate_arguments(arguments)
        environment = {
            name: os.environ[name]
            for name in self.policy.environment_allowlist
            if name in os.environ
        }
        try:
            with context.local(log_level="error"):
                tube = process(
                    [str(executable_path), *argument_list],
                    shell=False,
                    cwd=str(executable_path.parent),
                    env=environment,
                    ignore_environ=True,
                    stdin=PIPE,
                    stdout=PIPE,
                    stderr=STDOUT,
                    alarm=self.policy.max_runtime_seconds,
                    display=False,
                )
        except Exception as error:  # pwntools uses platform-specific exceptions.
            raise ExecutableLaunchError(f"Unable to launch approved executable: {error}") from error

        session_id = str(uuid4())
        session = _Session(tube=tube, executable=executable_path, started_at=monotonic())
        self._sessions[session_id] = session
        self._record(session_id, session, "launch", str(executable_path).encode())
        return session_id

    def send(self, session_id: str, data: bytes) -> None:
        """Write one bounded byte sequence to standard input."""
        self._validate_input(data)
        session = self._session(session_id)
        self._record(session_id, session, "send_attempt", data)
        try:
            session.tube.send(data)
        except Exception as error:
            self._record(session_id, session, "send_error", str(error).encode(errors="replace"))
            raise ExecutableProtocolError(
                f"Unable to send to process: {error}", attempted_data=data
            ) from error
        self._record(session_id, session, "send_complete", data)

    def send_line(self, session_id: str, data: bytes = b"") -> None:
        """Write one bounded line to standard input."""
        self._validate_input(data)
        session = self._session(session_id)
        line = data + b"\n"
        self._record(session_id, session, "send_line_attempt", line)
        try:
            session.tube.sendline(data)
        except Exception as error:
            self._record(session_id, session, "send_line_error", str(error).encode(errors="replace"))
            raise ExecutableProtocolError(
                f"Unable to send line to process: {error}", attempted_data=line
            ) from error
        self._record(session_id, session, "send_line_complete", line)

    def receive(self, session_id: str, max_bytes: int, timeout: float) -> bytes:
        """Read up to ``max_bytes`` bytes, respecting policy and timeout."""
        session = self._session(session_id)
        count = self._validated_read_size(max_bytes)
        try:
            data = self._recv_once(session, count, timeout)
        except ExecutableClientError as error:
            self._record(session_id, session, "receive_error", error.partial_data)
            raise
        self._record_output(session_id, session, "receive", data)
        return data

    def receive_until(
        self, session_id: str, delimiter: bytes, max_bytes: int, timeout: float
    ) -> bytes:
        """Read a bounded response until a nonempty delimiter is observed."""
        if not delimiter:
            raise ExecutableValidationError("A nonempty delimiter is required.")
        session = self._session(session_id)
        count = self._validated_read_size(max_bytes)
        deadline = monotonic() + self._validated_timeout(timeout)
        response = bytearray()
        while len(response) < count:
            remaining = deadline - monotonic()
            if remaining <= 0:
                self._raise_after_partial(
                    session_id,
                    session,
                    "receive_until_timeout",
                    ExecutableTimeoutError("Timed out waiting for delimiter."),
                    bytes(response),
                )
            try:
                chunk = self._recv_once(session, 1, remaining)
            except ExecutableClientError as error:
                self._raise_after_partial(
                    session_id, session, "receive_until_error", error, bytes(response) + error.partial_data
                )
            if not chunk:
                break
            response.extend(chunk)
            if response.endswith(delimiter):
                data = bytes(response)
                self._record_output(session_id, session, "receive_until", data)
                return data
        data = bytes(response)
        self._record_output(session_id, session, "receive_until", data)
        if data.endswith(delimiter):
            return data
        if len(data) >= count:
            raise ExecutableOutputLimitError(
                "Delimiter was not found within the requested read limit.", partial_data=data
            )
        return data

    def receive_line(self, session_id: str, max_bytes: int, timeout: float) -> bytes:
        """Read a bounded newline-terminated response."""
        return self.receive_until(session_id, b"\n", max_bytes, timeout)

    def poll(self, session_id: str) -> int | None:
        """Return an exit status, or ``None`` while the process is running."""
        return self._session(session_id).tube.poll()

    def close(self, session_id: str) -> None:
        """Close a session and terminate a still-running local process."""
        session = self._session(session_id, allow_closed=True)
        if session.closed:
            return
        try:
            if session.tube.poll() is None:
                session.tube.kill()
            session.tube.close()
        finally:
            session.closed = True
            self._record(session_id, session, "close", b"")

    def get_transcript(self, session_id: str) -> tuple[dict[str, Any], ...]:
        """Return a read-only snapshot of bounded, redacted session events."""
        return tuple(dict(event) for event in self._session(session_id, allow_closed=True).transcript)

    def _validate_executable(self, executable: Path) -> Path:
        path = Path(executable).resolve()
        try:
            path.relative_to(self._workspace_root)
        except ValueError as error:
            raise ExecutableValidationError("Executable must be inside the workspace.") from error
        if not path.exists() or not path.is_file():
            raise ExecutableValidationError("Executable does not exist or is not a file.")
        if path not in self._allowed_executables:
            raise ExecutableValidationError("Executable is not in the explicit allowlist.")
        return path

    def _validate_arguments(self, arguments: list[str] | tuple[str, ...]) -> list[str]:
        if len(arguments) > self.policy.max_arguments:
            raise ExecutableValidationError("Too many executable arguments.")
        if not all(isinstance(argument, str) for argument in arguments):
            raise ExecutableValidationError("Executable arguments must be strings.")
        if sum(len(argument.encode()) for argument in arguments) > self.policy.max_argument_bytes:
            raise ExecutableValidationError("Executable arguments exceed the byte limit.")
        return list(arguments)

    def _validate_input(self, data: bytes) -> None:
        if not isinstance(data, bytes):
            raise ExecutableValidationError("Process input must be bytes.")
        if len(data) > self.policy.max_input_bytes:
            raise ExecutableValidationError("Process input exceeds the byte limit.")

    def _validated_read_size(self, max_bytes: int) -> int:
        if not isinstance(max_bytes, int) or max_bytes < 1:
            raise ExecutableValidationError("Read size must be a positive integer.")
        if max_bytes > self.policy.max_read_bytes:
            raise ExecutableValidationError("Read size exceeds the policy limit.")
        return max_bytes

    @staticmethod
    def _validated_timeout(timeout: float) -> float:
        if not isinstance(timeout, (int, float)) or timeout <= 0:
            raise ExecutableValidationError("Timeout must be positive.")
        return float(timeout)

    def _recv_once(self, session: _Session, count: int, timeout: float) -> bytes:
        timeout = self._validated_timeout(timeout)
        try:
            data = session.tube.recv(count, timeout=timeout)
        except EOFError:
            return b""
        except Exception as error:
            raise ExecutableProtocolError(f"Unable to receive from process: {error}") from error
        if not data and session.tube.poll() is None:
            raise ExecutableTimeoutError("Timed out waiting for process output.")
        return data

    def _record_output(self, session_id: str, session: _Session, event_type: str, data: bytes) -> None:
        session.output_bytes += len(data)
        self._record(session_id, session, event_type, data)
        if session.output_bytes > self.policy.max_total_output_bytes:
            self.close(session_id)
            raise ExecutableOutputLimitError(
                "Process exceeded its total output allowance.", partial_data=data
            )

    def _raise_after_partial(
        self,
        session_id: str,
        session: _Session,
        event_type: str,
        error: ExecutableClientError,
        partial_data: bytes,
    ) -> None:
        try:
            self._record_output(session_id, session, event_type, partial_data)
        except ExecutableOutputLimitError as limit_error:
            raise ExecutableOutputLimitError(
                str(limit_error), partial_data=partial_data, attempted_data=error.attempted_data
            ) from error
        raise type(error)(
            str(error), partial_data=partial_data, attempted_data=error.attempted_data
        ) from error

    def _session(self, session_id: str, allow_closed: bool = False) -> _Session:
        session = self._sessions.get(session_id)
        if session is None:
            raise ExecutableProtocolError("Unknown executable session.")
        if session.closed:
            if allow_closed:
                return session
            raise ExecutableProtocolError("Executable session is closed.")
        if monotonic() - session.started_at > self.policy.max_runtime_seconds:
            self.close(session_id)
            raise ExecutableTimeoutError("Process exceeded its maximum runtime.")
        return session

    def _record(self, session_id: str, session: _Session, event_type: str, data: bytes) -> None:
        redacted = data
        for pattern in self.policy.redact_patterns:
            if pattern:
                redacted = redacted.replace(pattern, b"[REDACTED]")
        session.transcript.append(
            {
                "session_id": session_id,
                "event": event_type,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "byte_count": len(data),
                "payload_b64": base64.b64encode(redacted).decode("ascii"),
            }
        )
        while len(session.transcript) > self.policy.max_transcript_events:
            session.transcript.popleft()
