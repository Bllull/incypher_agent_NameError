import requests
import os
import tools.config  # Loads .env before API settings are read.
import re
from html.parser import HTMLParser

PLATFORM_URL = os.getenv("PLATFORM_URL", "https://hackathon.in-cypher.com")
HEADERS = {
    "Authorization": f"Bearer {os.getenv('CTFD_API_TOKEN')}",
    "Content-Type": "application/json"
}


class _ChallengeDescriptionParser(HTMLParser):
    """Extract visible text from CTFd's challenge-desc span only."""

    def __init__(self):
        super().__init__()
        self.in_description = False
        self.description_depth = 0
        self.skip_depth = 0
        self.parts: list[str] = []

    def handle_starttag(self, tag, attrs):
        attributes = dict(attrs)
        classes = attributes.get("class", "").split() # type: ignore
        if not self.in_description:
            if tag == "span" and "challenge-desc" in classes:
                self.in_description = True
                self.description_depth = 1
            return

        self.description_depth += 1
        if self.skip_depth:
            self.skip_depth += 1
        elif tag == "div" and (
            "row" in classes or attributes.get("id") == "whale-panel"
        ):
            # CTFd appends dynamic instance controls inside challenge-desc.
            self.skip_depth = 1

    def handle_endtag(self, tag):
        if not self.in_description:
            return
        if self.skip_depth:
            self.skip_depth -= 1
        self.description_depth -= 1
        if self.description_depth == 0:
            self.in_description = False

    def handle_data(self, data):
        if self.in_description and not self.skip_depth:
            self.parts.append(data)


def extract_challenge_description(details: dict) -> str:
    """Return only the text contained in CTFd's ``challenge-desc`` span."""
    view = details.get("view")
    if isinstance(view, str):
        parser = _ChallengeDescriptionParser()
        parser.feed(view)
        description = " ".join(" ".join(parser.parts).split())
        if description:
            return description

    # Some CTFd API responses expose the same description separately as Markdown.
    description = details.get("description", "")
    return description.strip() if isinstance(description, str) else ""

def get_challenges():
    """Fetches list of active challenges from CTFd API."""
    res = requests.get(f"{PLATFORM_URL}/api/v1/challenges", headers=HEADERS)
    if res.status_code == 200:
        return res.json().get("data", [])
    return []


def challenge_page_url(challenge_name: str, challenge_id: int) -> str:
    """Build CTFd's client-side challenge URL: /challenges#name-id."""
    slug = re.sub(r"[^a-z0-9]+", "-", challenge_name.lower()).strip("-")
    return f"{PLATFORM_URL.rstrip('/')}/challenges#{slug}-{challenge_id}"


def get_challenge_details(challenge_id: int):
    """Fetch one challenge's detail record through CTFd's read-only API."""
    res = requests.get(
        f"{PLATFORM_URL.rstrip('/')}/api/v1/challenges/{int(challenge_id)}",
        headers=HEADERS,
    )
    res.raise_for_status()
    return res.json().get("data", {})

def deploy_instance(challenge_id: int):
    """Triggers container deployment for isolated challenges."""
    res = requests.post(f"{PLATFORM_URL}/api/v1/container", json={"challenge_id": challenge_id}, headers=HEADERS)
    return res.json()

def submit_flag(challenge_id: int, flag: str):
    """Submits a solved flag to the platform."""
    data = {"challenge_id": int(challenge_id), "submission": flag.strip()}
    res = requests.post(f"{PLATFORM_URL}/api/v1/challenges/attempt", json=data, headers=HEADERS)
    return res.json()
