"""Load repository-local environment settings before clients are initialized."""

from pathlib import Path

from dotenv import load_dotenv


# Explicit PowerShell/Docker environment variables take precedence over .env.
load_dotenv(Path(__file__).resolve().parent.parent / ".env", override=False)
