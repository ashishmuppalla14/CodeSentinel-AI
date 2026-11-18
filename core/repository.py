"""Repository acquisition: GitHub URL, uploaded ZIP, local path.

Repository code is only ever read as text. Nothing is imported, built or executed,
and no git hooks / install scripts run (GitHub sources are fetched as a ZIP archive).
"""
from __future__ import annotations

import os
import shutil
import tempfile
import urllib.error
import urllib.request
from contextlib import contextmanager

from utils.security_utils import UnsafeArchiveError, parse_github_url, safe_extract_zip, MAX_ZIP_BYTES


class RepositoryError(Exception):
    """User-facing acquisition error."""


def _single_root(path: str) -> str:
    """If an archive has exactly one top-level directory, descend into it."""
    entries = [e for e in os.listdir(path) if e != "__MACOSX"]
    if len(entries) == 1 and os.path.isdir(os.path.join(path, entries[0])):
        return os.path.join(path, entries[0])
    return path


def download_github(url: str, dest_zip: str, timeout: int = 30) -> str:
    parsed = parse_github_url(url)
    if not parsed:
        raise RepositoryError("Invalid GitHub URL. Expected https://github.com/<owner>/<repo>")
    owner, repo = parsed
    last_err = None
    for ref in ("HEAD",):
        api = f"https://codeload.github.com/{owner}/{repo}/zip/{ref}"
        req = urllib.request.Request(api, headers={"User-Agent": "CodeSentinel-AI"})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp, open(dest_zip, "wb") as out:
                total = 0
                while True:
                    chunk = resp.read(65536)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > MAX_ZIP_BYTES:
                        raise RepositoryError("Repository download exceeds the size limit")
                    out.write(chunk)
            return owner + "/" + repo
        except urllib.error.HTTPError as e:
            if e.code == 404:
                raise RepositoryError("Repository not found or private. Only public repositories are supported.")
            if e.code in (403, 429):
                raise RepositoryError("GitHub rate limit or access restriction hit. Try again later or upload a ZIP.")
            last_err = e
        except urllib.error.URLError as e:
            raise RepositoryError(f"Could not reach GitHub: {e.reason}")
        except TimeoutError:
            raise RepositoryError("GitHub request timed out")
    raise RepositoryError(f"GitHub download failed: {last_err}")


@contextmanager
def acquire(source_type: str, value, keep: bool = False):
    """Yield (repo_root, repo_name). Temp data is deleted on exit unless keep=True.

    source_type: 'github' (value=url), 'zip' (value=path to zip file), 'local' (value=dir).
    """
    tmp = None
    try:
        if source_type == "local":
            if not value or not os.path.isdir(value):
                raise RepositoryError(f"Local path does not exist or is not a directory: {value}")
            root = os.path.abspath(value)
            yield root, os.path.basename(root.rstrip(os.sep)) or "local-repo"
            return
        tmp = tempfile.mkdtemp(prefix="codesentinel_")
        if source_type == "github":
            zp = os.path.join(tmp, "repo.zip")
            name = download_github(value, zp)
            ex = os.path.join(tmp, "src")
            _extract(zp, ex)
            yield _single_root(ex), name
        elif source_type == "zip":
            if not value or not os.path.isfile(value):
                raise RepositoryError("ZIP file not found")
            ex = os.path.join(tmp, "src")
            _extract(value, ex)
            base = os.path.splitext(os.path.basename(value))[0]
            yield _single_root(ex), base
        else:
            raise RepositoryError(f"Unknown source type: {source_type}")
    finally:
        if tmp and not keep:
            shutil.rmtree(tmp, ignore_errors=True)


def _extract(zip_path: str, dest: str) -> None:
    try:
        safe_extract_zip(zip_path, dest)
    except UnsafeArchiveError as e:
        raise RepositoryError(str(e))
