import re
from pathlib import Path

from config import get_settings
from services.errors import NotFoundError

_VERSION = re.compile(r"<!--\s*version:\s*(\S+)\s*-->")
_NUMBERED = re.compile(r"^\s*\d+\.\s+(.+?)\s*$")


def load(name: str) -> tuple[str, str]:
    """Returns (version, markdown) for content/<name>.md. The version comes from <!-- version: ... -->."""
    path = Path(get_settings().content_dir) / f"{name}.md"
    if not path.is_file():
        raise NotFoundError(f"Content file {path} is missing")
    text = path.read_text(encoding="utf-8")
    match = _VERSION.search(text)
    return (match.group(1) if match else "unversioned"), _VERSION.sub("", text).strip()


def consent_statements(markdown: str) -> list[str]:
    return [m.group(1) for line in markdown.splitlines() if (m := _NUMBERED.match(line))]
