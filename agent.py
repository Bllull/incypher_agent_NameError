import os
import re
import json
from typing import Any
from urllib.parse import urlparse
from tools.ctfd_api import (
    challenge_page_url,
    deploy_instance,
    extract_challenge_description,
    get_challenge_details,
    get_challenges,
    submit_flag,
)
from tools.tcp_client import interact_tcp
from tools.http_client import create_session, interact_http
from tools.llm_router import call_openai

# Validate variables needed for the model-driven solver.
TEAM_KEY = os.getenv("TEAM_KEY")
if not os.getenv("SOCLAAS_API_KEY") or not os.getenv("SOCLAAS_BASE_URL"):
    raise ValueError(
        "Missing mandatory environment variable: SOCLAAS_API_KEY or SOCLAAS_BASE_URL."
    )

def solve_tcp_challenge(ch_id: int, ip: str, port: int, max_attempts: int = 2):
    """Interacts with target endpoint using the LLM router to obtain the flag."""
    print(f"\n[*] Starting solution loop for Challenge ID {ch_id} on {ip}:{port}")
    
    # 1. Initial banner grab
    banner = interact_tcp(ip, port, TEAM_KEY) # type: ignore
    print(f"[+] Initial Banner: {banner.strip()}")
    
    # Check if banner already contains flag
    flag_match = re.search(r"flag\{.*?\}", banner)
    if flag_match:
        return flag_match.group(0)

    # 2. Iterative Tool Loop using Router
    attempts = 0
    require_deep_reasoning = False  # Start with cheap model (gpt-4o-mini)
    
    while attempts < max_attempts:
        attempts += 1
        print(f"[*] Attempt {attempts}/{max_attempts} (Deep Reasoning: {require_deep_reasoning})")

        prompt = f"""
        You are an automated CTF solver agent.
        Target output received from server:
        {banner}
        
        Generate the exact input payload needed to obtain the flag. 
        Output ONLY the raw payload string, nothing else.
        """
        
        # Route execution to gpt-4o-mini (attempt 1) or o3-mini (attempt 2 fallback)
        payload = call_openai(prompt, require_deep_reasoning=require_deep_reasoning)
        print(f"[*] Generated Payload: {payload}")

        # Send payload to TCP endpoint
        result = interact_tcp(ip, port, TEAM_KEY, payload=payload) # type: ignore
        print(f"[+] Server Response: {result.strip()}")

        # Check for flag match
        flag_match = re.search(r"flag\{.*?\}", result)
        if flag_match:
            return flag_match.group(0)
        
        # Escalate to reasoning model for subsequent attempt if failed
        banner = result
        require_deep_reasoning = True

    return None


def _request_from_model(raw: str) -> dict[str, Any]:
    """Parse and validate the intentionally small request format used by the LLM."""
    request = json.loads(raw)
    if not isinstance(request, dict):
        raise ValueError("Model response must be a JSON object")

    path = request.get("path", "/")
    if not isinstance(path, str) or not path.startswith("/"):
        raise ValueError("Model response path must start with '/'")
    method = request.get("method", "GET").upper()
    if method not in {"GET", "POST"}:
        raise ValueError("Model response method must be GET or POST")

    for name in ("params", "data"):
        value = request.get(name, {})
        if not isinstance(value, dict) or not all(isinstance(k, str) for k in value):
            raise ValueError(f"Model response {name} must be an object with string keys")

    summary = request.get("summary", "No decision summary provided.")
    if not isinstance(summary, str):
        raise ValueError("Model response summary must be a string")

    return {
        "method": method,
        "path": path,
        "params": request.get("params", {}),
        "data": request.get("data", {}),
        "summary": summary[:500],
    }


def solve_http_challenge(
    target_url: str,
    challenge_descriptions: list[str] | None = None,
    max_attempts: int = 4,
) -> str | None:
    """Explore a same-origin web challenge through a cookie-preserving session."""
    parsed = urlparse(target_url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("The deployed challenge URL must be an absolute http(s) URL")
    base_url = f"{parsed.scheme}://{parsed.netloc}/"
    session = create_session()
    challenge_context = "\n\n".join(challenge_descriptions or [])[:12000]

    response = interact_http(session, base_url)
    page = response.text
    print(f"[+] HTTP landing page: {response.status_code} {response.url}")
    print(f"[*] Observed {len(page)} response characters; checking for a flag before requesting another page.")
    flag_match = re.search(r"flag\{.*?\}", page, re.IGNORECASE | re.DOTALL)
    if flag_match:
        return flag_match.group(0)

    for attempt in range(1, max_attempts + 1):
        prompt = f"""
You are an automated CTF web solver. The target origin is {base_url}.
CTFd challenge description(s) retrieved before this instance was contacted:
---
{challenge_context}
---
The latest HTTP response had status {response.status_code} at path {urlparse(response.url).path}:
---
{page[:12000]}
---
Choose the next safe, same-origin application request needed to obtain a flag.
Return ONLY valid JSON in this exact shape:
{{"summary":"one concise evidence-based decision summary","method":"GET or POST","path":"/relative-path","params":{{}},"data":{{}}}}
Use params for query-string fields and data for form fields. Do not return a full URL,
headers, shell commands, or prose. The summary is an externally visible activity log,
not private chain-of-thought; keep it to one sentence.
"""
        try:
            request = _request_from_model(call_openai(prompt, require_deep_reasoning=attempt > 1))
            print(f"[*] Decision summary: {request.pop('summary')}")
            print(f"[*] HTTP attempt {attempt}/{max_attempts}: {request['method']} {request['path']}")
            response = interact_http(session, base_url, **request)
        except (ValueError, json.JSONDecodeError) as exc:
            print(f"[-] Invalid model-generated HTTP request: {exc}")
            continue
        except Exception as exc:
            print(f"[-] HTTP request failed: {exc}")
            break

        page = response.text
        print(f"[+] HTTP response: {response.status_code} {response.url}")
        print(f"[*] Observed {len(page)} response characters; checking response for a flag.")
        flag_match = re.search(r"flag\{.*?\}", page, re.IGNORECASE | re.DOTALL)
        if flag_match:
            return flag_match.group(0)

    return None


def _http_url_from_deployment(container_data: dict[str, Any]) -> str | None:
    """Return an HTTP(S) instance URL when the CTFd deployment supplies one."""
    for key in ("url", "instance_url", "web_url"):
        value = container_data.get(key)
        if isinstance(value, str) and urlparse(value).scheme in {"http", "https"}:
            return value
    return None


def main():
    """Main execution loop running across available platform challenges."""
    print("[*] Fetching challenge list from CTFd API...")
    challenges = get_challenges()
    
    if not challenges:
        print("[-] No challenges returned or API token invalid.")
        return

    direct_target_url = os.getenv("CHALLENGE_URL")
    if direct_target_url:
        challenge_descriptions: list[str] = []
        print(f"[*] Retrieving details for {len(challenges)} CTFd challenge(s)...")
        for challenge in challenges:
            raw_challenge_id = challenge.get("id")
            challenge_name = str(challenge.get("name", "unnamed"))
            try:
                challenge_id = int(raw_challenge_id)
            except (TypeError, ValueError):
                print(f"[-] Skipping challenge with invalid ID: {challenge_name}")
                continue
            page_url = challenge_page_url(challenge_name, challenge_id)
            try:
                details = get_challenge_details(challenge_id)
            except Exception as exc:
                print(f"[-] Could not retrieve details for [{challenge_id}] {challenge_name}: {exc}")
                continue
            description = extract_challenge_description(details)
            if not description:
                print(f"[-] No challenge description found for [{challenge_id}] {challenge_name}")
                continue
            challenge_descriptions.append(description)
            print(
                f"    [{challenge_id}] {challenge_name} | page={page_url}"
            )
        if not challenge_descriptions:
            print("[-] No challenge details were retrieved; not contacting CHALLENGE_URL.")
            return
        print(f"[*] Starting direct HTTP workflow for CHALLENGE_URL: {direct_target_url}")
        flag = solve_http_challenge(direct_target_url, challenge_descriptions)
        if flag:
            print(f"[SUCCESS] Flag found: {flag}")
        else:
            print("[-] Failed to extract a flag from the HTTP challenge.")
        return

    for ch in challenges:
        ch_id = ch.get("id")
        ch_name = ch.get("name")
        print(f"\n=== Processing Challenge: {ch_name} (ID: {ch_id}) ===")

        # Deploy instance via CTFd API
        container_data = deploy_instance(ch_id)

        target_url = _http_url_from_deployment(container_data)
        if target_url:
            print(f"[*] Using HTTP instance returned by CTFd: {target_url}")
            flag = solve_http_challenge(target_url)
        else:
            if not TEAM_KEY:
                print(f"[-] '{ch_name}' requires raw TCP, but TEAM_KEY is not set. Skipping...")
                continue
            ip = container_data.get("ip", "47.236.162.54")  # Platform default IP
            port = container_data.get("port")
            if not port:
                print(f"[-] No HTTP URL or raw TCP port assigned for '{ch_name}'. Skipping...")
                continue
            flag = solve_tcp_challenge(ch_id, ip, int(port))
        
        if flag:
            print(f"[SUCCESS] Flag found: {flag}")
            sub_res = submit_flag(ch_id, flag)
            print(f"[+] Submission Result: {sub_res}")
        else:
            print(f"[-] Failed to extract flag for {ch_name}.")

if __name__ == "__main__":
    main()
