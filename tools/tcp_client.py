import socket

from solver import connect  # Temporary stand-in for the platform-provided helper.


def connect_tcp(ip: str, port: int, team_key: str) -> socket.socket:
    """Open a proof-of-work-aware connection through ``solver.connect``."""
    return connect(ip, port, team_key)

def interact_tcp(ip: str, port: int, team_key: str, payload: str | None = None) -> str:
    """Passes the team key Proof-of-Work gate and exchanges data over raw TCP."""
    try:
        s = connect_tcp(ip, port, team_key)
        if payload:
            s.sendall((payload + "\n").encode())
        response = s.recv(4096).decode(errors="ignore")
        s.close()
        return response
    except Exception as e:
        return f"TCP Connection Error: {str(e)}"
