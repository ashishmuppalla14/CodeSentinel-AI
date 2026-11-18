import json
import os
import zipfile

import pytest

from agents.lead_agent import classify_severity, dedupe, review
from core.models import Finding
from core.report_generator import to_json, to_markdown, to_sarif
from core.repository import RepositoryError
from core.scanner import scan, scan_directory
from utils.security_utils import UnsafeArchiveError, parse_github_url, redact, safe_extract_zip

SETTINGS = {"use_semgrep": False}
FAKE_AWS = "AKIA" + "IOSFODNN7EXAMPLE"  # AWS documentation example, not a real credential


def write(root, rel, text):
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)
    return p


def run(root, settings=SETTINGS):
    return scan_directory(str(root), "t", "local", settings)


def titles(res, cat=None):
    return [f.title for f in res.findings if cat is None or f.category == cat]


def rules(res):
    return {f.rule_id for f in res.findings}


# ---- security ---------------------------------------------------------
def test_sql_injection_detected_via_ast(tmp_path):
    write(tmp_path, "db.py", "def q(cur, name):\n    cur.execute(\"SELECT * FROM t WHERE n='\" + name + \"'\")\n")
    res = run(tmp_path)
    f = next(f for f in res.findings if f.rule_id.startswith("sqli"))
    assert f.line == 2 and f.category == "Security" and f.kind == "static-analysis"


def test_parameterized_query_not_flagged(tmp_path):
    write(tmp_path, "db.py", "def q(cur, n):\n    cur.execute('SELECT * FROM t WHERE n = ?', (n,))\n")
    assert not any(f.rule_id.startswith("sqli") for f in run(tmp_path).findings)


def test_dangerous_command_and_deserialization(tmp_path):
    write(tmp_path, "x.py", "import os, pickle\nos.system('ls ' + d)\nobj = pickle.loads(data)\n")
    r = rules(run(tmp_path))
    assert any(x.startswith("cmd") for x in r) and any(x.startswith("deser") for x in r)


def test_multi_language_rules(tmp_path):
    write(tmp_path, "a.js", "el.innerHTML = userInput;\n")
    write(tmp_path, "b.php", "<?php\necho $_GET['x'];\n")
    r = rules(run(tmp_path))
    assert "xss.innerhtml" in r and "xss.php" in r


# ---- secrets ----------------------------------------------------------
def test_secret_detected_and_masked(tmp_path):
    write(tmp_path, "cfg.py", f'KEY = "{FAKE_AWS}"\nPASSWORD = "Zx9!hunter-two"\n')
    res = run(tmp_path)
    secrets = [f for f in res.findings if f.rule_id.startswith("secret")]
    assert {f.line for f in secrets} == {1, 2}
    blob = to_json(res) + to_markdown(res) + to_sarif(res)
    assert FAKE_AWS not in blob and "Zx9!hunter-two" not in blob  # never leaked into reports


def test_placeholder_secret_ignored(tmp_path):
    write(tmp_path, "cfg.py", 'api_key = "your_api_key_here"\npassword = os.environ["PW"]\n')
    assert not any(f.rule_id == "secret.generic" for f in run(tmp_path).findings)


def test_redact_helper():
    assert "hunter22" not in redact('password = "hunter22"')


# ---- completeness -----------------------------------------------------
def test_todo_fixme_detected(tmp_path):
    write(tmp_path, "a.py", "x = 1\n# TODO: finish\n# FIXME broken\n")
    write(tmp_path, "b.js", "// TODO wire up\nconst s = 'TODO in string';\n")
    res = run(tmp_path)
    got = {(f.file, f.line, f.rule_id) for f in res.findings if f.rule_id.startswith("todo")}
    assert ("a.py", 2, "todo.todo") in got and ("a.py", 3, "todo.fixme") in got and ("b.js", 1, "todo.todo") in got
    assert ("b.js", 2, "todo.todo") not in got  # marker inside a string literal


def test_placeholder_implementations(tmp_path):
    write(tmp_path, "m.py", "def a():\n    pass\n\ndef b():\n    raise NotImplementedError\n\n"
                            "def fetch_user(uid):\n    return None\n\ndef real(x):\n    return x + 1\n")
    r = rules(run(tmp_path))
    assert "stub.pass" in r and "stub.not-implemented" in r and "stub.placeholder-return" in r
    stubs = [f.title for f in run(tmp_path).findings if f.rule_id.startswith("stub")]
    assert not any("real" in t for t in stubs)


def test_abstract_methods_not_flagged(tmp_path):
    write(tmp_path, "m.py", "from abc import ABC, abstractmethod\nclass A(ABC):\n    @abstractmethod\n    def f(self):\n        pass\n")
    assert not any(f.rule_id.startswith("stub") for f in run(tmp_path).findings)


def test_empty_endpoint_and_empty_file(tmp_path):
    write(tmp_path, "api.py", "@app.get('/x')\ndef x():\n    pass\n")
    write(tmp_path, "empty.py", "")
    r = rules(run(tmp_path))
    assert "incomplete.endpoint" in r and "empty.file" in r


# ---- quality / slop ---------------------------------------------------
def test_quality_and_slop(tmp_path):
    body = "\n".join(f"    x{i} = {i}" for i in range(70))
    write(tmp_path, "q.py", f"import os\n\ndef big(a, b=[]):\n{body}\n    return a\n\n"
                            "def w(a):\n    return big(a)\n\ndef s():\n    try:\n        big(1)\n    except Exception:\n        pass\n")
    r = rules(run(tmp_path))
    for expected in ("quality.long-function", "quality.unused-import", "quality.mutable-default", "slop.wrapper", "slop.generic-except"):
        assert expected in r, expected


# ---- lead agent -------------------------------------------------------
def mkf(**kw):
    d = dict(title="T", category="Security", severity="HIGH", confidence=80, file="a.py", line=3, evidence="x", explanation="e",
             remediation="r", agent="A", rule_id="sqli.x", kind="heuristic")
    d.update(kw)
    return Finding(**d)


def test_duplicate_removal_and_corroboration():
    a = mkf(agent="Security Agent", confidence=70)
    b = mkf(agent="Bandit", rule_id="sqli.B608", confidence=90, kind="static-analysis", severity="MEDIUM")
    c = mkf(rule_id="quality.other", category="Code Quality", agent="Q")  # same line, different issue: kept
    out = dedupe([a, b, c])
    assert len(out) == 2
    kept = next(f for f in out if f.category == "Security")
    assert kept.agent == "Bandit" and kept.confidence == 95 and kept.severity == "HIGH"


def test_severity_classification():
    assert classify_severity(mkf(confidence=90)) == "CRITICAL"                 # escalated
    assert classify_severity(mkf(confidence=90, file="tests/test_a.py")) == "HIGH"  # tests never escalated
    assert classify_severity(mkf(confidence=40)) == "MEDIUM"                   # low confidence downgraded
    assert classify_severity(mkf(rule_id="cfg.debug", confidence=90)) == "HIGH"
    assert classify_severity(mkf(category="Code Quality", severity="LOW", rule_id="q.x")) == "LOW"


def test_evidence_verification_flags_mismatch():
    f = mkf(evidence="this text is not in the file", line=1)
    out = review([f], {"a.py": ["print('hi')"]})
    assert out[0].verified is False and out[0].confidence < 80


def test_results_sorted_by_severity():
    out = review([mkf(severity="LOW", rule_id="a.b", category="Code Quality", evidence="x", line=1),
                  mkf(severity="HIGH", confidence=60, rule_id="cfg.x", evidence="x", line=1)], {"a.py": ["x"]})
    assert [f.severity for f in out] == ["HIGH", "LOW"]


# ---- ZIP safety & acquisition ----------------------------------------
def test_zip_path_traversal_blocked(tmp_path):
    z = tmp_path / "evil.zip"
    with zipfile.ZipFile(z, "w") as zf:
        zf.writestr("../escape.txt", "pwned")
    with pytest.raises(UnsafeArchiveError):
        safe_extract_zip(str(z), str(tmp_path / "out"))
    assert not (tmp_path / "escape.txt").exists()


def test_zip_absolute_path_and_bomb_blocked(tmp_path):
    z = tmp_path / "abs.zip"
    with zipfile.ZipFile(z, "w") as zf:
        zf.writestr("/etc/evil", "x")
    with pytest.raises(UnsafeArchiveError):
        safe_extract_zip(str(z), str(tmp_path / "o1"))
    big = tmp_path / "bomb.zip"
    with zipfile.ZipFile(big, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("a.txt", "0" * 3_000_000)
    with pytest.raises(UnsafeArchiveError):
        safe_extract_zip(str(big), str(tmp_path / "o2"))


def test_valid_zip_scan_and_cleanup(tmp_path):
    z = tmp_path / "proj.zip"
    with zipfile.ZipFile(z, "w") as zf:
        zf.writestr("proj/app.py", "import os\nos.system('rm ' + x)\n")
    import glob, tempfile
    before = set(glob.glob(os.path.join(tempfile.gettempdir(), "codesentinel_*")))
    res = scan("zip", str(z), SETTINGS)
    after = set(glob.glob(os.path.join(tempfile.gettempdir(), "codesentinel_*")))
    assert any(f.rule_id.startswith("cmd") for f in res.findings)
    assert after == before  # temp dirs removed


def test_invalid_inputs(tmp_path):
    with pytest.raises(RepositoryError):
        scan("github", "https://evil.example.com/x/y", SETTINGS)
    with pytest.raises(RepositoryError):
        scan("github", "not a url", SETTINGS)
    with pytest.raises(RepositoryError):
        scan("local", str(tmp_path / "missing"), SETTINGS)
    bad = tmp_path / "bad.zip"
    bad.write_text("not a zip")
    with pytest.raises(RepositoryError):
        scan("zip", str(bad), SETTINGS)
    assert parse_github_url("https://github.com/a/b") == ("a", "b")
    assert parse_github_url("https://github.com/a/b/../../c") is None


def test_empty_repository(tmp_path):
    res = run(tmp_path)
    assert res.files_scanned == 0 and res.findings == [] and res.health_score == 100
    assert json.loads(to_json(res))["summary"]["total"] == 0


def test_failing_agent_does_not_crash_scan(tmp_path, monkeypatch):
    from agents.slop_agent import SlopAgent
    write(tmp_path, "a.py", "x = 1\n")
    monkeypatch.setattr(SlopAgent, "run", lambda self, ctx: (_ for _ in ()).throw(RuntimeError("boom")))
    res = run(tmp_path)
    assert res.agent_results["AI Slop Detector"]["status"] == "failed"
    assert res.agent_results["Security Agent"]["status"] == "ok"


# ---- reports ----------------------------------------------------------
def test_reports_from_real_results(tmp_path):
    write(tmp_path, "a.py", "import os\nos.system('x' + y)\n# TODO later\n")
    res = run(tmp_path)
    j = json.loads(to_json(res))
    assert j["summary"]["total"] == len(res.findings) > 0
    for key in ("title", "category", "severity", "confidence", "file", "line", "evidence", "explanation", "remediation"):
        assert key in j["findings"][0]
    sarif = json.loads(to_sarif(res))
    assert sarif["version"] == "2.1.0" and len(sarif["runs"][0]["results"]) == len(res.findings)
    assert sarif["runs"][0]["results"][0]["level"] in ("error", "warning", "note")
    md = to_markdown(res)
    assert "Repository Health Score" in md and "a.py" in md


def test_sample_project_demo():
    root = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "sample_project")
    res = scan("local", root, SETTINGS)
    assert res.agent_results and all(r["status"] == "ok" for r in res.agent_results.values())
    cats = {f.category for f in res.findings}
    assert cats == {"Security", "AI Slop", "Completeness", "Code Quality"}
    assert any(f.severity == "CRITICAL" for f in res.findings) and res.health_score < 50
