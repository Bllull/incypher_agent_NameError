"""CTFd API access and challenge connection helpers."""

from __future__ import annotations

import os
import re
import shlex
import socket
import tempfile
from pathlib import Path
from typing import Any, Literal
from urllib.parse import unquote, urljoin, urlparse

import requests

import tools.config  # Loads .env before API settings are read.
from tools.context import append_context_list, get_context, update_context
from tools.flags import extract_flag
from tools.tcp_client import connect_tcp


PLATFORM_URL = os.getenv("PLATFORM_URL", "https://hackathon.in-cypher.com")
DOCKER_PLATFORM_AVAILABLE_ENV = "IN_CYPHER_DOCKER_PLATFORM_AVAILABLE"
CHALLENGE_DOWNLOAD_DIR = (
    Path(__file__).resolve().parent.parent / ".agent_data" / "challenge_files"
)
ChallengeDetails = dict[str, Any]


class ChallengeFileDownloadError(RuntimeError):
    """One or more CTF file assets failed after safe partial downloads."""

    def __init__(self, errors: list[dict[str, str]], downloaded_paths: list[str]) -> None:
        super().__init__(f"{len(errors)} challenge file download(s) failed")
        self.errors = errors
        self.downloaded_paths = downloaded_paths


class CTFdClient:
    """Small authenticated client shared by all CTFd operations."""

    def __init__(
        self,
        base_url: str,
        api_token: str | None,
        *,
        timeout: float = 30,
        session: requests.Session | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.session = session or requests.Session()
        self.session.headers.update(
            {
                "Authorization": f"Bearer {api_token}",
                "Content-Type": "application/json",
            }
        )

    def request_json(self, method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        """Send one API request and return its decoded JSON object."""
        response = self.session.request(
            method,
            f"{self.base_url}/{path.lstrip('/')}",
            timeout=kwargs.pop("timeout", self.timeout),
            **kwargs,
        )
        response.raise_for_status()
        payload = response.json()
        if not isinstance(payload, dict):
            raise ValueError("CTFd API response must be a JSON object")
        return payload

    def list_challenges(self) -> list[dict[str, Any]]:
        payload = self.request_json("GET", "/api/v1/challenges")
        challenges = payload.get("data", [])
        if not isinstance(challenges, list):
            raise ValueError("CTFd challenge list must be a JSON list")
        return [item for item in challenges if isinstance(item, dict)]

    def challenge_details(self, challenge_id: int) -> ChallengeDetails:
        payload = self.request_json("GET", f"/api/v1/challenges/{int(challenge_id)}")
        details = payload.get("data", {})
        if not isinstance(details, dict):
            raise ValueError("CTFd challenge details must be a JSON object")
        return details

    def deploy(self, challenge_id: int) -> dict[str, Any]:
        payload = self.request_json(
            "POST", "/api/v1/container", json={"challenge_id": int(challenge_id)}
        )
        data = payload.get("data")
        return data if isinstance(data, dict) else payload

    def submit(self, challenge_id: int, flag: str) -> dict[str, Any]:
        return self.request_json(
            "POST",
            "/api/v1/challenges/attempt",
            json={"challenge_id": int(challenge_id), "submission": flag.strip()},
        )

    def download(self, file_url: str) -> bytes:
        response = self.session.get(file_url, timeout=self.timeout)
        response.raise_for_status()
        return response.content


_client = CTFdClient(PLATFORM_URL, os.getenv("CTFD_API_TOKEN"))


def _details_or_fetch(
    challenge_id: int, details: ChallengeDetails | None
) -> ChallengeDetails:
    return details if details is not None else get_challenge_details(challenge_id)


def extract_challenge_description(
    challenge_id: int, details: ChallengeDetails | None = None
) -> tuple[str, str]:
    """Return the challenge name and Markdown description from CTFd details."""
    record = _details_or_fetch(challenge_id, details)
    name = record.get("name", "")
    description = record.get("description", "")
    return (
        name.strip() if isinstance(name, str) else "",
        description.strip() if isinstance(description, str) else "",
    )


def identify_challenge_type(
    challenge_id: int, details: ChallengeDetails | None = None
) -> Literal["file", "url", "tcp"]:
    """Classify raw CTFd details or normalized stored challenge context."""
    record = _details_or_fetch(challenge_id, details)
    files = record.get("files", record.get("file_links"))
    if isinstance(files, list) and files:
        return "file"

    description = record.get("description", "")
    category = record.get("category", "")
    web_text = " ".join(
        value.lower() for value in (description, category) if isinstance(value, str)
    )
    web_markers = ("http://", "https://", "ssti", "jinja", "web challenge")
    if "web" in str(category).lower() or any(
        marker in web_text for marker in web_markers
    ):
        return "url"

    stored_type = record.get("challenge_type")
    if stored_type in {"file", "url", "tcp"}:
        return stored_type
    return "tcp"


def prepare_challenge_context(
    challenge_id: int, listed_name: str = "unnamed"
) -> ChallengeDetails:
    """Fetch challenge details once, normalize them, and replace stored context."""
    details = get_challenge_details(challenge_id)
    retrieved_name, description = extract_challenge_description(challenge_id, details)
    challenge_type = identify_challenge_type(challenge_id, details)
    file_links = details.get("files", [])
    context: ChallengeDetails = {
        "name": retrieved_name or listed_name,
        "category": details.get("category", ""),
        "description": description,
        "challenge_type": challenge_type,
        "file_links": file_links if isinstance(file_links, list) else [],
    }
    update_context(context, challenge_id)
    return context


def _stored_challenge_context(challenge_id: int) -> ChallengeDetails:
    context = get_context(challenge_id)
    if context is None:
        raise ValueError(
            f"Challenge {challenge_id} has no stored context; prepare it before connecting"
        )
    return context


def _challenge_directory_name(challenge_name: str) -> str:
    name = re.sub(r"[^a-zA-Z0-9._-]+", "_", challenge_name).strip("._")
    return name or "unnamed_challenge"


def _download_filename(file_url: str, index: int) -> str:
    filename = Path(unquote(urlparse(file_url).path)).name
    filename = re.sub(r"[^a-zA-Z0-9._-]+", "_", filename).strip("._")
    return filename or f"file_{index}"


def _docker_platform_available() -> bool:
    value = os.getenv(DOCKER_PLATFORM_AVAILABLE_ENV, "false").strip().lower()
    if value in {"true", "1", "yes"}:
        return True
    if value in {"false", "0", "no", ""}:
        return False
    raise ValueError(
        f"{DOCKER_PLATFORM_AVAILABLE_ENV} must be true or false, not {value!r}"
    )


def _tcp_target(host: Any, port: Any) -> tuple[str, int]:
    if not isinstance(host, str) or not host.strip():
        raise ValueError("A non-empty TCP host is required")
    try:
        normalized_port = int(port)
    except (TypeError, ValueError) as exc:
        raise ValueError("A numeric TCP port is required") from exc
    if not 1 <= normalized_port <= 65535:
        raise ValueError("TCP port must be between 1 and 65535")
    return host.strip(), normalized_port


def connect_challenge_tcp(challenge_id: int, timeout: int = 15) -> socket.socket:
    """Resolve a TCP target and connect through the platform helper adapter."""
    context = _stored_challenge_context(challenge_id)
    challenge_name = str(context.get("name", "unnamed"))
    if _docker_platform_available():
        deployment = deploy_instance(challenge_id)
        host, port = _tcp_target(deployment.get("ip"), deployment.get("port"))
    else:
        command = input(
            f"Enter the manually deployed TCP endpoint for [{challenge_id}] {challenge_name} "
            "as 'nc HOST PORT': "
        )
        parts = shlex.split(command)
        if len(parts) != 3 or parts[0].lower() != "nc":
            raise ValueError("Manual TCP endpoint must use the form: nc HOST PORT")
        host, port = _tcp_target(parts[1], parts[2])

    team_key = os.getenv("TEAM_KEY", "").strip()
    if not team_key:
        raise ValueError("TEAM_KEY is required for the InCypher TCP connection helper")
    connection = connect_tcp(host, port, team_key)
    connection.settimeout(timeout)
    return connection


def download_challenge_files(challenge_name: str, challenge_id: int) -> list[str]:
    """Download file links previously stored in the challenge context."""
    context = _stored_challenge_context(challenge_id)
    file_links = context.get("file_links", [])
    if not isinstance(file_links, list):
        raise ValueError("Stored challenge file_links must be a list")

    challenge_directory = CHALLENGE_DOWNLOAD_DIR / _challenge_directory_name(challenge_name)
    downloaded_paths: list[str] = []
    errors: list[dict[str, str]] = []
    used_destinations: set[Path] = set()
    for index, href in enumerate(file_links, start=1):
        if not isinstance(href, str):
            continue
        file_url = urljoin(f"{PLATFORM_URL.rstrip('/')}/", href)
        destination = challenge_directory / _download_filename(file_url, index)
        if destination in used_destinations:
            destination = destination.with_stem(f"{destination.stem}_{index}")
        temporary_path: Path | None = None
        try:
            content = _client.download(file_url)
            challenge_directory.mkdir(parents=True, exist_ok=True)
            with tempfile.NamedTemporaryFile(
                dir=challenge_directory,
                prefix=f".{destination.name}.",
                suffix=".part",
                delete=False,
            ) as temporary_file:
                temporary_file.write(content)
                temporary_file.flush()
                os.fsync(temporary_file.fileno())
                temporary_path = Path(temporary_file.name)
            temporary_path.replace(destination)
            used_destinations.add(destination)
            downloaded_paths.append(str(destination.resolve()))
        except Exception as exc:
            if temporary_path is not None:
                temporary_path.unlink(missing_ok=True)
            errors.append(
                {
                    "index": str(index),
                    "filename": destination.name,
                    "error": str(exc),
                }
            )
    if downloaded_paths:
        update_context(
            {"file_path": downloaded_paths[0], "file_paths": downloaded_paths},
            challenge_id,
        )
    if errors:
        append_context_list(errors, "file_download_errors", challenge_id)
        raise ChallengeFileDownloadError(errors, downloaded_paths)
    return downloaded_paths


def get_challenges() -> list[dict[str, Any]]:
    """Fetch the list of active challenges from CTFd."""
    return _client.list_challenges()


def get_challenge_details(challenge_id: int) -> ChallengeDetails:
    """Fetch one challenge detail record through CTFd's read-only API."""
    return _client.challenge_details(challenge_id)


def get_challenge_url(challenge_id: int) -> str:
    """Deploy or request a URL using previously stored challenge context."""
    context = _stored_challenge_context(challenge_id)
    challenge_name = str(context.get("name", "unnamed"))
    slug = re.sub(r"[^a-z0-9]+", "-", challenge_name.lower()).strip("-")
    ctfd_page_url = f"{PLATFORM_URL.rstrip('/')}/challenges#{slug}-{challenge_id}"
    if _docker_platform_available():
        deployment = deploy_instance(challenge_id)
        for key in ("url", "connection_url"):
            deployed_url = deployment.get(key)
            if isinstance(deployed_url, str) and deployed_url.strip():
                return deployed_url.strip()
        return ctfd_page_url

    manual_url = input(
        f"Deploy [{challenge_id}] {challenge_name} manually at {ctfd_page_url}, "
        "then enter the deployed challenge URL: "
    ).strip()
    if not manual_url:
        raise ValueError("A manually deployed challenge URL is required")
    return manual_url


def deploy_instance(challenge_id: int) -> dict[str, Any]:
    """Trigger container deployment for an isolated challenge."""
    return _client.deploy(challenge_id)


def submit_flag(challenge_id: int, flag: str) -> dict[str, Any]:
    """Submit a solved flag to the platform."""
    normalized_flag = flag.strip()
    if extract_flag(normalized_flag) != normalized_flag:
        raise ValueError("flag must use the exact format INCYPHER{...}")
    return _client.submit(challenge_id, normalized_flag)
