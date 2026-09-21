"""Load repository-local environment settings before clients are initialized."""

from pathlib import Path
import os

from dotenv import load_dotenv


# Explicit PowerShell/Docker environment variables take precedence over .env.
load_dotenv(Path(__file__).resolve().parent.parent / ".env", override=False)


def _alias_environment(target: str, *sources: str) -> None:
    """Populate legacy settings from the arena's injected environment aliases."""
    if os.getenv(target):
        return
    for source in sources:
        value = os.getenv(source)
        if value:
            os.environ[target] = value
            return


_alias_environment("CTFD_API_TOKEN", "CTF_TOKEN", "CTFD_TOKEN")
_alias_environment("PLATFORM_URL", "CTF_BASE", "CTFD_URL")
