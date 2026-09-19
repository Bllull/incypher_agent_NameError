import requests
import os
import tools.config  # Loads .env before API settings are read.
import re
import shlex
import socket
from pathlib import Path
from typing import Any, Literal
from urllib.parse import unquote, urljoin, urlparse

PLATFORM_URL = os.getenv("PLATFORM_URL", "https://hackathon.in-cypher.com")
HEADERS = {
    "Authorization": f"Bearer {os.getenv('CTFD_API_TOKEN')}",
    "Content-Type": "application/json"
}

DOCKER_PLATFORM_AVAILABLE_ENV = "IN_CYPHER_DOCKER_PLATFORM_AVAILABLE"
CHALLENGE_DOWNLOAD_DIR = (
    Path(__file__).resolve().parent.parent / ".agent_data" / "challenge_files"
)


def extract_challenge_description(challenge_id: int) -> str:
    """Return the Markdown value at CTFd's ``data.description`` field."""
    details = get_challenge_details(challenge_id)
    description = details.get("description", "")
    return description.strip() if isinstance(description, str) else ""


def identify_challenge_type(challenge_id: int) -> Literal["file", "url", "tcp"]:
    """Classify a challenge from its CTFd detail fields.

    A non-empty ``files`` list takes priority, followed by ``http`` in the
    Markdown description. All remaining challenges are treated as TCP.
    """
    details = get_challenge_details(challenge_id)
    files = details.get("files")
    if isinstance(files, list) and files:
        return "file"

    description = details.get("description", "")
    if isinstance(description, str) and "http" in description.lower():
        return "url"
    return "tcp"


def _challenge_directory_name(challenge_name: str) -> str:
    """Return a filesystem-safe directory name for one challenge."""
    name = re.sub(r"[^a-zA-Z0-9._-]+", "_", challenge_name).strip("._")
    return name or "unnamed_challenge"


def _download_filename(file_url: str, index: int) -> str:
    """Derive a safe local filename from a challenge file URL."""
    filename = Path(unquote(urlparse(file_url).path)).name
    filename = re.sub(r"[^a-zA-Z0-9._-]+", "_", filename).strip("._")
    return filename or f"file_{index}"


def _docker_platform_available() -> bool:
    """Return the configured CTFd container-deployment mode."""
    value = os.getenv(DOCKER_PLATFORM_AVAILABLE_ENV, "false").strip().lower()
    if value in {"true", "1", "yes"}:
        return True
    if value in {"false", "0", "no", ""}:
        return False
    raise ValueError(
        f"{DOCKER_PLATFORM_AVAILABLE_ENV} must be true or false, not {value!r}"
    )


def _tcp_target(host: Any, port: Any) -> tuple[str, int]:
    """Validate and normalize a TCP host and port."""
    if not isinstance(host, str) or not host.strip():
        raise ValueError("A non-empty TCP host is required")
    try:
        normalized_port = int(port)
    except (TypeError, ValueError) as exc:
        raise ValueError("A numeric TCP port is required") from exc
    if not 1 <= normalized_port <= 65535:
        raise ValueError("TCP port must be between 1 and 65535")
    return host.strip(), normalized_port


def connect_challenge_tcp(
    challenge_id: int,
    timeout: int = 15,
    challenge_name: str | None = None,
) -> socket.socket:
    """Open a TCP connection to an automatic or manually deployed challenge.

    When ``IN_CYPHER_DOCKER_PLATFORM_AVAILABLE`` is true, CTFd deploys the
    challenge and supplies its ``ip`` and ``port``. Otherwise the operator is
    prompted for exactly ``nc HOST PORT``. The prompt identifies the challenge
    as ``[challenge_id] challenge name``. The caller owns the returned socket
    and must close it after use.
    """
    if _docker_platform_available():
        deployment = deploy_instance(challenge_id)
        if not isinstance(deployment, dict):
            raise ValueError("CTFd deployment response must be an object")
        host, port = _tcp_target(deployment.get("ip"), deployment.get("port"))
    else:
        if challenge_name is None:
            details = get_challenge_details(challenge_id)
            challenge_name = str(details.get("name", "unnamed"))
        command = input(
            f"Enter the manually deployed TCP endpoint for [{challenge_id}] {challenge_name} "
            "as 'nc HOST PORT': "
        )
        parts = shlex.split(command)
        if len(parts) != 3 or parts[0].lower() != "nc":
            raise ValueError("Manual TCP endpoint must use the form: nc HOST PORT")
        host, port = _tcp_target(parts[1], parts[2])

    return socket.create_connection((host, port), timeout=timeout)


def download_challenge_files(challenge_name: str, challenge_id: int) -> list[str]:
    """Download all links in CTFd's API ``data.files`` list.

    Files are saved beneath ``.agent_data/challenge_files/<challenge_name>/``.
    The returned paths are absolute strings in the order the links appear in
    the API response.
    """
    details = get_challenge_details(challenge_id)
    file_links = details.get("files", [])
    if not isinstance(file_links, list):
        return []

    challenge_directory = CHALLENGE_DOWNLOAD_DIR / _challenge_directory_name(challenge_name)
    downloaded_paths: list[str] = []
    used_destinations: set[Path] = set()

    for index, href in enumerate(file_links, start=1):
        if not isinstance(href, str):
            continue
        file_url = urljoin(f"{PLATFORM_URL.rstrip('/')}/", href)
        response = requests.get(file_url, headers=HEADERS, timeout=30)
        response.raise_for_status()

        challenge_directory.mkdir(parents=True, exist_ok=True)
        destination = challenge_directory / _download_filename(file_url, index)
        if destination in used_destinations:
            destination = destination.with_stem(f"{destination.stem}_{index}")
        destination.write_bytes(response.content)
        used_destinations.add(destination)
        downloaded_paths.append(str(destination.resolve()))

    return downloaded_paths

def get_challenges():
    """Fetches list of active challenges from CTFd API."""
    res = requests.get(f"{PLATFORM_URL}/api/v1/challenges", headers=HEADERS)
    if res.status_code == 200:
        return res.json().get("data", [])
    return []


def get_challenge_details(challenge_id: int):
    """Fetch one challenge's detail record through CTFd's read-only API."""
    res = requests.get(
        f"{PLATFORM_URL.rstrip('/')}/api/v1/challenges/{int(challenge_id)}",
        headers=HEADERS,
    )
    res.raise_for_status()
    return res.json().get("data", {})

def connect_challenge_url(challenge_name: str, challenge_id: int) -> str:
    """Deploy through CTFd or request a manually deployed challenge URL.

    Set ``IN_CYPHER_DOCKER_PLATFORM_AVAILABLE=true`` to use CTFd's container
    deployment API. Otherwise, the operator is shown the CTFd challenge page
    and asked to paste the URL of a manually deployed instance.
    """
    slug = re.sub(r"[^a-z0-9]+", "-", challenge_name.lower()).strip("-")
    ctfd_page_url = f"{PLATFORM_URL.rstrip('/')}/challenges#{slug}-{challenge_id}"
    if _docker_platform_available():
        deploy_instance(challenge_id)
        return ctfd_page_url

    manual_url = input(
        f"Deploy [{challenge_id}] {challenge_name} manually at {ctfd_page_url}, "
        "then enter the deployed challenge URL: "
    ).strip()
    if not manual_url:
        raise ValueError("A manually deployed challenge URL is required")
    return manual_url


def deploy_instance(challenge_id: int):
    """Triggers container deployment for isolated challenges."""
    res = requests.post(f"{PLATFORM_URL}/api/v1/container", json={"challenge_id": challenge_id}, headers=HEADERS)
    return res.json()

def submit_flag(challenge_id: int, flag: str):
    """Submits a solved flag to the platform."""
    data = {"challenge_id": int(challenge_id), "submission": flag.strip()}
    res = requests.post(f"{PLATFORM_URL}/api/v1/challenges/attempt", json=data, headers=HEADERS)
    return res.json()
