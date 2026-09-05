import requests
import os

PLATFORM_URL = os.getenv("PLATFORM_URL", "https://hackathon.in-cypher.com")
HEADERS = {
    "Authorization": f"Bearer {os.getenv('CTFD_API_TOKEN')}",
    "Content-Type": "application/json"
}

def get_challenges():
    """Fetches list of active challenges from CTFd API."""
    res = requests.get(f"{PLATFORM_URL}/api/v1/challenges", headers=HEADERS)
    if res.status_code == 200:
        return res.json().get("data", [])
    return []

def deploy_instance(challenge_id: int):
    """Triggers container deployment for isolated challenges."""
    res = requests.post(f"{PLATFORM_URL}/api/v1/container", json={"challenge_id": challenge_id}, headers=HEADERS)
    return res.json()

def submit_flag(challenge_id: int, flag: str):
    """Submits a solved flag to the platform."""
    data = {"challenge_id": int(challenge_id), "submission": flag.strip()}
    res = requests.post(f"{PLATFORM_URL}/api/v1/challenges/attempt", json=data, headers=HEADERS)
    return res.json()