import socket

def connect(ip: str, port: int, team_key: str) -> socket.socket:
    """Mock helper that simulates the platform proof-of-work gate."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((ip, port))
    return s