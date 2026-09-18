import requests
import os
import tools.config  # Loads .env before API settings are read.
import re
from pathlib import Path
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


def _challenge_directory_name(challenge_name: str) -> str:
    """Return a filesystem-safe directory name for one challenge."""
    name = re.sub(r"[^a-zA-Z0-9._-]+", "_", challenge_name).strip("._")
    return name or "unnamed_challenge"


def _download_filename(file_url: str, index: int) -> str:
    """Derive a safe local filename from a challenge file URL."""
    filename = Path(unquote(urlparse(file_url).path)).name
    filename = re.sub(r"[^a-zA-Z0-9._-]+", "_", filename).strip("._")
    return filename or f"file_{index}"


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

def challenge_page_url(challenge_name: str, challenge_id: int) -> str:
    """Deploy through CTFd or request a manually deployed challenge URL.

    Set ``IN_CYPHER_DOCKER_PLATFORM_AVAILABLE=true`` to use CTFd's container
    deployment API. Otherwise, the operator is shown the CTFd challenge page
    and asked to paste the URL of a manually deployed instance.
    """
    slug = re.sub(r"[^a-z0-9]+", "-", challenge_name.lower()).strip("-")
    ctfd_page_url = f"{PLATFORM_URL.rstrip('/')}/challenges#{slug}-{challenge_id}"
    docker_available = os.getenv(DOCKER_PLATFORM_AVAILABLE_ENV, "false").strip().lower()

    if docker_available in {"true", "1", "yes"}:
        deploy_instance(challenge_id)
        return ctfd_page_url
    if docker_available not in {"false", "0", "no", ""}:
        raise ValueError(
            f"{DOCKER_PLATFORM_AVAILABLE_ENV} must be true or false, not {docker_available!r}"
        )

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
