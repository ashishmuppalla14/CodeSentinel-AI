"""Security helpers: safe ZIP extraction, secret redaction, URL validation."""
from __future__ import annotations

import os
import re
import stat
import zipfile

MAX_ZIP_BYTES = 50_000_000
MAX_ZIP_FILES = 5000
MAX_RATIO = 200  # compression-bomb guard


class UnsafeArchiveError(Exception):
    pass


def safe_extract_zip(zip_path: str, dest: str,
                     max_bytes: int = MAX_ZIP_BYTES, max_files: int = MAX_ZIP_FILES) -> int:
    """Extract a ZIP defending against path traversal, symlinks and zip bombs.
    Nothing from the archive is executed. Returns number of files extracted."""
    dest = os.path.realpath(dest)
    os.makedirs(dest, exist_ok=True)
    try:
        zf = zipfile.ZipFile(zip_path)
    except zipfile.BadZipFile as e:
        raise UnsafeArchiveError(f"Not a valid ZIP file: {e}")
    with zf:
        infos = zf.infolist()
        if len(infos) > max_files:
            raise UnsafeArchiveError(f"Archive has too many entries ({len(infos)} > {max_files})")
        total = sum(i.file_size for i in infos)
        if total > max_bytes:
            raise UnsafeArchiveError(f"Archive expands to {total} bytes (limit {max_bytes})")
        comp = sum(i.compress_size for i in infos) or 1
        if total / comp > MAX_RATIO and total > 1_000_000:
            raise UnsafeArchiveError("Suspicious compression ratio (possible zip bomb)")
        count = 0
        for info in infos:
            name = info.filename
            if name.startswith(("/", "\\")) or re.match(r"^[A-Za-z]:", name):
                raise UnsafeArchiveError(f"Absolute path in archive: {name}")
            target = os.path.realpath(os.path.join(dest, name))
            if target != dest and not target.startswith(dest + os.sep):
                raise UnsafeArchiveError(f"Path traversal attempt: {name}")
            mode = (info.external_attr >> 16) & 0xFFFF
            if mode and stat.S_ISLNK(mode):
                continue  # never materialize symlinks
            if info.is_dir():
                os.makedirs(target, exist_ok=True)
                continue
            os.makedirs(os.path.dirname(target), exist_ok=True)
            with zf.open(info) as src, open(target, "wb") as out:
                out.write(src.read())
            count += 1
    return count


GITHUB_RE = re.compile(r"^https://github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+?)(?:\.git)?/?$")


def parse_github_url(url: str):
    """Return (owner, repo) or None. Only plain https://github.com/owner/repo URLs."""
    m = GITHUB_RE.match((url or "").strip())
    return (m.group(1), m.group(2)) if m else None


_REDACT = [
    re.compile(r"gsk_[A-Za-z0-9]{20,}"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"gh[pousr]_[A-Za-z0-9]{30,}"),
    re.compile(r"sk-[A-Za-z0-9]{20,}"),
    re.compile(r"(?i)(api[_-]?key|secret|token|passwd|password)(\s*[=:]\s*)(['\"])([^'\"\n]{4,})\3"),
]


def redact(text: str) -> str:
    """Mask secret-looking values so they never reach reports, logs or AI prompts."""
    if not text:
        return text
    out = text
    out = re.sub(_REDACT[4], lambda m: f"{m.group(1)}{m.group(2)}{m.group(3)}***REDACTED***{m.group(3)}", out)
    for rx in _REDACT[:4]:
        out = rx.sub("***REDACTED***", out)
    return out
