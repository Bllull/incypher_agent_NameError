import os
import re
from tools.ctfd_api import get_challenges, deploy_instance, submit_flag
from tools.tcp_client import interact_tcp
from tools.llm_router import call_openai

# Validate required variables
TEAM_KEY = os.getenv("TEAM_KEY")
if not os.getenv("OPENAI_API_KEY") or not TEAM_KEY:
    raise ValueError("Missing mandatory environment variables: OPENAI_API_KEY or TEAM_KEY.")

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

def main():
    """Main execution loop running across available platform challenges."""
    print("[*] Fetching challenge list from CTFd API...")
    challenges = get_challenges()
    
    if not challenges:
        print("[-] No challenges returned or API token invalid.")
        return

    for ch in challenges:
        ch_id = ch.get("id")
        ch_name = ch.get("name")
        print(f"\n=== Processing Challenge: {ch_name} (ID: {ch_id}) ===")

        # Deploy instance via CTFd API
        container_data = deploy_instance(ch_id)
        
        ip = container_data.get("ip", "47.236.162.54")  # Platform default IP
        port = container_data.get("port")

        if not port:
            print(f"[-] No raw TCP port assigned for '{ch_name}'. Skipping...")
            continue

        # Solve challenge via router pipeline
        flag = solve_tcp_challenge(ch_id, ip, int(port))
        
        if flag:
            print(f"[SUCCESS] Flag found: {flag}")
            sub_res = submit_flag(ch_id, flag)
            print(f"[+] Submission Result: {sub_res}")
        else:
            print(f"[-] Failed to extract flag for {ch_name}.")

if __name__ == "__main__":
    main()