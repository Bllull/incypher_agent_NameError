import sys
import os

# Ensure solver.py in root directory can be found
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from solver import connect  # Import platform-provided helper

def interact_tcp(ip: str, port: int, team_key: str, payload: str = None) -> str: # type: ignore
    """Passes the team key Proof-of-Work gate and exchanges data over raw TCP."""
    try:
        s = connect(ip, port, team_key)
        if payload:
            s.sendall((payload + "\n").encode())
        response = s.recv(4096).decode(errors="ignore")
        s.close()
        return response
    except Exception as e:
        return f"TCP Connection Error: {str(e)}"