"""File discovery, filtering and size limits. Files are only ever read as text."""
from __future__ import annotations

import os
from dataclasses import dataclass, field

SKIP_DIRS = {
    ".git", ".hg", ".svn", "node_modules", "venv", ".venv", "env", "__pycache__",
    "dist", "build", ".idea", ".vscode", "vendor", "target", ".tox", ".mypy_cache",
    ".pytest_cache", "site-packages", ".next", "coverage",
}

BINARY_EXT = {
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".pdf", ".zip", ".gz", ".tar", ".jar",
    ".class", ".exe", ".dll", ".so", ".dylib", ".bin", ".woff", ".woff2", ".ttf",
    ".mp3", ".mp4", ".mov", ".pyc", ".o", ".a", ".lock", ".min.js", ".map", ".svg",
}

# Files whose content must never be sent to an AI backend.
SENSITIVE_NAMES = {".env", "credentials", "credentials.json", "id_rsa", "id_dsa",
                   "secrets.json", "secrets.yml", "secrets.yaml", ".npmrc", ".pypirc",
                   ".netrc", "service-account.json"}
SENSITIVE_EXT = {".pem", ".key", ".p12", ".pfx", ".jks", ".keystore"}

LIMITS = {
    "max_file_bytes": 500_000,
    "max_repo_bytes": 50_000_000,
    "max_files": 3000,
}


def is_sensitive(path: str) -> bool:
    name = os.path.basename(path).lower()
    ext = os.path.splitext(name)[1]
    return name in SENSITIVE_NAMES or name.startswith(".env") or ext in SENSITIVE_EXT


@dataclass
class SourceFile:
    rel: str
    abs: str
    size: int
    text: str = ""
    sensitive: bool = False

    @property
    def lines(self) -> list:
        return self.text.splitlines()


@dataclass
class FileSet:
    files: list = field(default_factory=list)
    skipped: int = 0
    warnings: list = field(default_factory=list)
    total_bytes: int = 0


def collect_files(root: str, limits: dict | None = None) -> FileSet:
    lim = {**LIMITS, **(limits or {})}
    fs = FileSet()
    root = os.path.abspath(root)
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not os.path.islink(os.path.join(dirpath, d))]
        for fn in sorted(filenames):
            full = os.path.join(dirpath, fn)
            rel = os.path.relpath(full, root).replace(os.sep, "/")
            if os.path.islink(full):
                fs.skipped += 1
                continue
            low = fn.lower()
            if any(low.endswith(e) for e in BINARY_EXT):
                fs.skipped += 1
                continue
            try:
                size = os.path.getsize(full)
            except OSError:
                fs.skipped += 1
                continue
            if size > lim["max_file_bytes"]:
                fs.skipped += 1
                fs.warnings.append(f"Skipped {rel}: larger than {lim['max_file_bytes']} bytes")
                continue
            if len(fs.files) >= lim["max_files"]:
                fs.warnings.append(f"File limit ({lim['max_files']}) reached; remaining files skipped")
                return fs
            if fs.total_bytes + size > lim["max_repo_bytes"]:
                fs.warnings.append("Repository size limit reached; remaining files skipped")
                return fs
            try:
                with open(full, "rb") as fh:
                    raw = fh.read()
            except OSError:
                fs.skipped += 1
                continue
            if b"\x00" in raw[:4096]:
                fs.skipped += 1
                continue
            fs.total_bytes += size
            fs.files.append(SourceFile(rel=rel, abs=full, size=size,
                                       text=raw.decode("utf-8", errors="replace"),
                                       sensitive=is_sensitive(rel)))
    return fs
