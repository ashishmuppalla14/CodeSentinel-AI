"""GitHub acquisition tests. The network is mocked: these verify handling logic, not live GitHub access."""
import io
import urllib.error
import zipfile

import pytest

from core import repository
from core.repository import RepositoryError
from core.scanner import scan


class FakeResp(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def make_zip_bytes():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("repo-main/app.py", "import os\nos.system('x' + y)\n")
    return buf.getvalue()


def test_github_success(monkeypatch):
    monkeypatch.setattr(repository.urllib.request, "urlopen", lambda req, timeout=30: FakeResp(make_zip_bytes()))
    res = scan("github", "https://github.com/o/r", {"use_semgrep": False})
    assert res.repo_name == "o/r" and any(f.rule_id.startswith("cmd") for f in res.findings)


@pytest.mark.parametrize("code,fragment", [(404, "not found"), (403, "rate limit"), (429, "rate limit")])
def test_github_http_errors(monkeypatch, code, fragment):
    def boom(req, timeout=30):
        raise urllib.error.HTTPError(req.full_url, code, "x", {}, None)
    monkeypatch.setattr(repository.urllib.request, "urlopen", boom)
    with pytest.raises(RepositoryError, match="(?i)" + fragment):
        scan("github", "https://github.com/o/r", {})


def test_github_network_down(monkeypatch):
    def boom(req, timeout=30):
        raise urllib.error.URLError("offline")
    monkeypatch.setattr(repository.urllib.request, "urlopen", boom)
    with pytest.raises(RepositoryError, match="(?i)could not reach"):
        scan("github", "https://github.com/o/r", {})
