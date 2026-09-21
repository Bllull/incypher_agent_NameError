"""A local-only child process used to test constrained CTF executable I/O."""

from __future__ import annotations

import sys
import time


mode = sys.argv[1]
if mode == "echo":
    print("challenge prompt", flush=True)
    print(f"answer:{sys.stdin.buffer.readline().decode().strip()}", flush=True)
elif mode == "output":
    sys.stdout.write("X" * int(sys.argv[2]))
    sys.stdout.flush()
elif mode == "sleep":
    time.sleep(float(sys.argv[2]))
elif mode == "partial_sleep":
    sys.stdout.write("partial")
    sys.stdout.flush()
    time.sleep(float(sys.argv[2]))
elif mode == "secret":
    print("token=fixture-secret", flush=True)
