"""Agent 1: Security. Regex rules + Python AST + Bandit + optional Semgrep.

Tool/AST results are labelled static-analysis; regex matches are labelled heuristic.
Repository code is only parsed or read, never executed.
"""
from __future__ import annotations

import ast
import json
import os
import re
import shutil
import subprocess
import sys

from core.context import AnalysisContext, is_test_path, mk, snippet
from core.models import KIND_HEURISTIC, KIND_STATIC
from utils.file_filter import SKIP_DIRS
from utils.security_utils import redact

NAME = "Security Agent"
CAT = "Security"
PLACEHOLDER_RE = re.compile(r"(?i)(your[_-]|<.*>|example|changeme|placeholder|xxx+|dummy|sample|\*{3,}|\$\{|%\(|\{\{|todo|test|fake|redacted)")

ALL = None
PY, JS, JAVA, PHP, GO, C = ["Python"], ["JavaScript", "TypeScript"], ["Java"], ["PHP"], ["Go"], ["C", "C++"]

# (rule_id, title, severity, confidence, languages, regex, explanation, fix)
RULES = [
    ("cmd.system", "Dangerous command execution (os.system / shell=True)", "HIGH", 70, PY,
     r"\bos\.(system|popen)\s*\(|subprocess\.\w+\([^)]*shell\s*=\s*True",
     "Commands run through a shell can be hijacked if any part of the string is attacker-influenced.",
     "Use subprocess with an argument list and shell=False; validate any external input."),
    ("cmd.eval", "Use of eval/exec on dynamic input", "HIGH", 65, PY + JS,
     r"(?<![\w.])(eval|exec)\s*\(\s*(?!['\"]\s*\))",
     "eval/exec run arbitrary code; with user-influenced input this is remote code execution.",
     "Remove eval/exec; use ast.literal_eval, JSON parsing or an explicit dispatch table."),
    ("cmd.node", "Node child_process exec", "HIGH", 65, JS,
     r"child_process|\b(?:exec|execSync)\s*\(\s*[`'\"].*(\$\{|\+)",
     "Shell commands built from strings can lead to command injection.",
     "Use execFile/spawn with an argument array and validate inputs."),
    ("cmd.php", "PHP command execution function", "HIGH", 70, PHP,
     r"\b(system|exec|shell_exec|passthru|popen|proc_open)\s*\(",
     "These functions run OS commands; user-controlled input leads to command injection.",
     "Avoid shell execution; if unavoidable use escapeshellarg() and a strict allow-list."),
    ("cmd.java", "Java Runtime.exec / ProcessBuilder", "MEDIUM", 60, JAVA,
     r"Runtime\.getRuntime\(\)\.exec\s*\(|new\s+ProcessBuilder\s*\(",
     "Spawning processes with concatenated input can allow command injection.",
     "Pass arguments as separate list items and validate input against an allow-list."),
    ("cmd.go", "Go exec.Command via shell", "MEDIUM", 60, GO,
     r"exec\.Command\(\s*\"(sh|bash|cmd)\"",
     "Invoking a shell with dynamic strings enables command injection.",
     "Call the binary directly with separate arguments."),
    ("cmd.c", "C system()/popen() call", "HIGH", 65, C,
     r"(?<![\w.])(system|popen)\s*\(",
     "system()/popen() invoke a shell and are injection-prone with untrusted input.",
     "Use execve-style APIs with fixed argument vectors."),
    ("sqli.js", "Potential SQL injection (string-built query)", "HIGH", 70, JS,
     r"\.(query|execute|raw)\s*\(\s*(`[^`]*\$\{|['\"][^'\"]*['\"]\s*\+)",
     "A query is assembled from variables via concatenation or template strings.",
     "Use parameterized queries / prepared statements."),
    ("sqli.java", "Potential SQL injection (string-built query)", "HIGH", 70, JAVA,
     r"(executeQuery|executeUpdate|prepareStatement|createQuery)\s*\(\s*\"[^\"]*\"\s*\+",
     "SQL text is concatenated with variables.",
     "Use PreparedStatement with ? placeholders."),
    ("sqli.php", "Potential SQL injection (user input in query)", "HIGH", 75, PHP,
     r"(mysqli?_query|->query|->exec|pg_query)\s*\([^;]*\$_(GET|POST|REQUEST|COOKIE)|\"\s*(SELECT|INSERT|UPDATE|DELETE)[^\"]*\.\s*\$_(GET|POST|REQUEST)",
     "Request data flows directly into an SQL statement.",
     "Use PDO prepared statements with bound parameters."),
    ("sqli.go", "Potential SQL injection (fmt.Sprintf query)", "HIGH", 65, GO,
     r"\.(Query|Exec|QueryRow)\w*\(\s*fmt\.Sprintf\(",
     "A query string is formatted with fmt.Sprintf instead of using placeholders.",
     "Use placeholders ($1 / ?) and pass arguments separately."),
    ("deser.pickle", "Insecure deserialization (pickle/marshal/shelve)", "HIGH", 75, PY,
     r"\b(pickle|cPickle|dill|marshal|shelve)\.(loads?|Unpickler)\s*\(",
     "Unpickling untrusted data can execute arbitrary code.",
     "Use JSON or another data-only format; never unpickle untrusted input."),
    ("deser.yaml", "yaml.load without safe loader", "HIGH", 80, PY,
     r"\byaml\.load\s*\((?![^)]*Safe)(?![^)]*safe)",
     "yaml.load with the default loader can construct arbitrary Python objects.",
     "Use yaml.safe_load."),
    ("deser.php", "PHP unserialize()", "HIGH", 70, PHP, r"\bunserialize\s*\(",
     "Unserializing attacker-controlled data enables object injection.", "Use json_decode or pass allowed_classes => false."),
    ("deser.java", "Java ObjectInputStream deserialization", "HIGH", 60, JAVA, r"new\s+ObjectInputStream\s*\(|\.readObject\s*\(\s*\)",
     "Native Java deserialization of untrusted data is a well-known RCE vector.", "Use a data-only format or a strict deserialization filter."),
    ("deser.node", "Unsafe deserialization (node-serialize)", "HIGH", 70, JS, r"require\(['\"]node-serialize['\"]\)|serialize\.unserialize",
     "node-serialize unserialize can execute code embedded in input.", "Use JSON.parse."),
    ("file.traversal", "Possible path traversal (request data used in file path)", "HIGH", 60, PY,
     r"\b(open|send_file|send_from_directory)\s*\([^)]*\b(request\.(args|form|values|json|files)|input\s*\()",
     "A file path appears to derive from user-controlled input.",
     "Resolve the path, verify it stays inside an allowed base directory, use secure_filename."),
    ("file.include", "PHP include/require of request data", "CRITICAL", 80, PHP,
     r"\b(include|require)(_once)?\s*\(?\s*\$_(GET|POST|REQUEST|COOKIE)",
     "Including a file named by the request allows local/remote file inclusion.", "Map identifiers to fixed file names via an allow-list."),
    ("file.node", "Possible path traversal (req data in fs call)", "HIGH", 60, JS,
     r"fs\.\w+\([^)]*\breq\.(params|query|body)",
     "Request data is used to build a filesystem path.", "Normalize and confine paths to a base directory."),
    ("file.mktemp", "Insecure temporary file (mktemp)", "MEDIUM", 75, PY, r"\btempfile\.mktemp\s*\(",
     "mktemp is race-prone and allows temp-file attacks.", "Use tempfile.mkstemp or NamedTemporaryFile."),
    ("file.perm", "World-writable permissions", "MEDIUM", 75, ALL, r"chmod\s+(-R\s+)?0?777\b|os\.chmod\([^)]*0o?777",
     "Granting everyone write access lets any local user tamper with files.", "Use least-privilege permissions (e.g. 640/750)."),
    ("xss.innerhtml", "Potential XSS (innerHTML / document.write)", "MEDIUM", 60, JS,
     r"\.innerHTML\s*=(?!\s*['\"`]\s*['\"`])|\bdocument\.write(ln)?\s*\(|dangerouslySetInnerHTML|\.insertAdjacentHTML\s*\(",
     "Writing dynamic strings as HTML can execute attacker-supplied scripts.",
     "Use textContent or a vetted sanitizer such as DOMPurify."),
    ("xss.php", "Potential XSS (unescaped request data echoed)", "HIGH", 75, PHP,
     r"\b(echo|print)\b[^;]*\$_(GET|POST|REQUEST|COOKIE)",
     "Request data is output without escaping.", "Wrap output in htmlspecialchars($v, ENT_QUOTES, 'UTF-8')."),
    ("xss.py", "Potential XSS (template escaping disabled)", "MEDIUM", 65, PY,
     r"\bmark_safe\s*\(|\bMarkup\s*\(|\|\s*safe\b|autoescape\s*=\s*False",
     "Disabling auto-escaping lets untrusted text become executable markup.", "Remove |safe/mark_safe or sanitize with an allow-list library."),
    ("cfg.debug", "Debug mode enabled", "MEDIUM", 70, ALL,
     r"\bapp\.run\([^)]*debug\s*=\s*True|^\s*DEBUG\s*=\s*True\b",
     "Debug mode can expose stack traces and interactive consoles in production.", "Drive debug from an environment variable defaulting to off."),
    ("cfg.tls", "TLS certificate verification disabled", "HIGH", 85, ALL,
     r"verify\s*=\s*False|_create_unverified_context|rejectUnauthorized\s*:\s*false|InsecureSkipVerify\s*:\s*true|CURLOPT_SSL_VERIFYPEER\s*,\s*(false|0)",
     "Disabling certificate checks allows man-in-the-middle attacks.", "Keep verification on; supply a CA bundle if needed."),
    ("cfg.cors", "Wildcard CORS policy", "LOW", 70, ALL,
     r"Access-Control-Allow-Origin['\"]?\s*[:,]\s*['\"]?\*|allow_origins\s*=\s*\[\s*['\"]\*['\"]|cors\(\s*\)",
     "Any website may call this API from a browser.", "Restrict allowed origins to trusted domains."),
    ("cfg.hash", "Weak hash algorithm (MD5/SHA-1)", "MEDIUM", 65, ALL,
     r"hashlib\.(md5|sha1)\s*\(|MessageDigest\.getInstance\(\s*\"(MD5|SHA-?1)\"|createHash\(\s*['\"](md5|sha1)['\"]|\bmd5\s*\(\s*\$",
     "MD5/SHA-1 are broken for security purposes (passwords, signatures).", "Use SHA-256+ or a password KDF (bcrypt/argon2/scrypt)."),
    ("cfg.bind", "Service bound to all interfaces", "LOW", 55, ALL, r"[\"']0\.0\.0\.0[\"']",
     "Binding to 0.0.0.0 exposes the service on every network interface.", "Bind to 127.0.0.1 unless external access is intended."),
    ("cfg.random", "Non-cryptographic randomness used for secrets", "MEDIUM", 55, PY,
     r"\brandom\.(random|randint|choice|choices)\s*\([^)]*\).*(token|password|secret|key|otp)|(token|password|secret|otp)\w*\s*=.*\brandom\.(random|randint|choice)",
     "The random module is predictable and unsuitable for secrets.", "Use the secrets module."),
]
_COMPILED = [(r[0], r[1], r[2], r[3], r[4], re.compile(r[5]), r[6], r[7]) for r in RULES]

# Secret detection: (rule, title, regex, group-with-secret-or-0, confidence, severity)
SECRET_RULES = [
    ("secret.aws", "AWS access key ID", re.compile(r"\b(AKIA[0-9A-Z]{16})\b"), 1, 90, "HIGH"),
    ("secret.privkey", "Private key committed to repository", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY"), 0, 95, "HIGH"),
    ("secret.github", "GitHub token", re.compile(r"\b(gh[pousr]_[A-Za-z0-9]{30,})\b"), 1, 92, "HIGH"),
    ("secret.groq", "Groq API key", re.compile(r"\b(gsk_[A-Za-z0-9]{20,})\b"), 1, 92, "HIGH"),
    ("secret.openai", "API secret key (sk-...)", re.compile(r"\b(sk-[A-Za-z0-9]{24,})\b"), 1, 85, "HIGH"),
    ("secret.slack", "Slack token", re.compile(r"\b(xox[baprs]-[A-Za-z0-9-]{10,})\b"), 1, 90, "HIGH"),
    ("secret.generic", "Hardcoded credential",
     re.compile(r"(?i)\b(?:api[_-]?key|secret[_-]?key|secret|access[_-]?token|auth[_-]?token|token|passwd|password|pwd|client[_-]?secret)\w*\s*[:=]\s*['\"]([^'\"\s]{6,})['\"]"),
     1, 70, "HIGH"),
]
DOC_EXT = (".md", ".rst", ".txt")


def _mask(line: str, secret: str) -> str:
    if secret and secret in line:
        keep = secret[:4] if len(secret) > 10 else ""
        line = line.replace(secret, keep + "***REDACTED***")
    return line.strip()[:220]


def _is_comment(line: str) -> bool:
    s = line.lstrip()
    return s.startswith(("#", "//", "*", "/*", "--", "<!--"))


class SecurityAgent:
    name = NAME
    description = "Hardcoded secrets, injection, unsafe execution/deserialization, insecure config; runs Bandit and Semgrep when available."

    def run(self, ctx: AnalysisContext) -> list:
        out = []
        for f in ctx.files:
            try:
                out += self._scan_file(ctx, f)
            except Exception as e:  # one bad file must not stop the agent
                ctx.settings.setdefault("_warnings", []).append(f"SecurityAgent skipped {f.rel}: {e}")
        if ctx.settings.get("use_bandit", True) and ctx.py_files():
            out += self._bandit(ctx)
        if ctx.settings.get("use_semgrep", True):
            out += self._semgrep(ctx)
        return out

    # ---- per-file -------------------------------------------------------
    def _scan_file(self, ctx, f):
        res = []
        lang = ctx.lang(f)
        lines = f.text.splitlines()
        in_test = is_test_path(f.rel)
        is_doc = f.rel.lower().endswith(DOC_EXT)
        for i, line in enumerate(lines, 1):
            if len(line) > 2000:
                continue
            # secrets (scanned in all text files, incl. .env and config)
            if not is_doc:
                for rid, title, rx, grp, conf, sev in SECRET_RULES:
                    m = rx.search(line)
                    if not m:
                        continue
                    secret = m.group(grp) if grp else ""
                    if rid == "secret.generic":
                        if PLACEHOLDER_RE.search(secret) or re.search(r"os\.|environ|getenv|process\.env", line):
                            continue
                        if _is_comment(line):
                            continue
                    c = max(conf - (25 if in_test else 0), 30)
                    s = sev if not in_test else "LOW"
                    res.append(mk(NAME, rid, title, CAT, s, c, f.rel, i, _mask(line, secret),
                                  "A credential-like value is stored directly in source. Anyone with repository access can read it, and it stays in git history.",
                                  "Remove it, rotate the credential, load it from an environment variable or secret manager, and purge it from history.",
                                  KIND_HEURISTIC))
                    break
            if lang is None and not f.rel.lower().endswith((".yml", ".yaml", ".json", ".conf", ".ini", ".env", ".cfg", ".toml", ".sh")):
                continue
            if _is_comment(line):
                continue
            for rid, title, sev, conf, langs, rx, expl, fix in _COMPILED:
                if langs and lang not in langs:
                    continue
                if rx.search(line):
                    c = conf - (20 if in_test else 0)
                    s = sev if not in_test else "LOW"
                    res.append(mk(NAME, rid, title, CAT, s, c, f.rel, i, snippet(lines, i),
                                  expl, fix, KIND_HEURISTIC))
        if lang == "Python":
            res += self._python_ast(ctx, f)
        return res

    def _python_ast(self, ctx, f):
        tree = ctx.tree(f)
        if tree is None:
            return []
        res = []
        lines = f.text.splitlines()
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) \
                    and node.func.attr in ("execute", "executemany", "executescript") and node.args:
                a = node.args[0]
                dyn = False
                if isinstance(a, ast.JoinedStr) and any(isinstance(v, ast.FormattedValue) for v in a.values):
                    dyn = True
                elif isinstance(a, ast.BinOp) and isinstance(a.op, (ast.Add, ast.Mod)) and \
                        not (isinstance(a.left, ast.Constant) and isinstance(a.right, ast.Constant)):
                    dyn = True
                elif isinstance(a, ast.Call) and isinstance(a.func, ast.Attribute) and a.func.attr == "format":
                    dyn = True
                if dyn:
                    res.append(mk(NAME, "sqli.python-ast", "Potential SQL injection (string-built query)", CAT, "HIGH", 90,
                                  f.rel, node.lineno, snippet(lines, node.lineno),
                                  "The SQL statement passed to execute() is built with string formatting/concatenation rather than bound parameters, so any user-controlled part can alter the query.",
                                  "Use parameterized queries, e.g. cursor.execute('SELECT * FROM t WHERE id = ?', (user_id,)).",
                                  KIND_STATIC))
        return res

    # ---- external tools -------------------------------------------------
    def _bandit(self, ctx):
        try:
            excl = ",".join(os.path.join(ctx.root, d) for d in SKIP_DIRS)
            cmd = [sys.executable, "-m", "bandit", "-r", ctx.root, "-f", "json", "-q", "--exit-zero",
                   "-s", "B101,B110,B112,B403,B404,B405,B406,B407,B408,B409,B410", "-x", excl]
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=ctx.settings.get("tool_timeout", 120))
            if not p.stdout.strip():
                if "No module named bandit" in p.stderr:
                    ctx.settings.setdefault("_warnings", []).append("Bandit not installed; skipped Bandit analysis")
                return []
            data = json.loads(p.stdout)
        except FileNotFoundError:
            return []
        except subprocess.TimeoutExpired:
            ctx.settings.setdefault("_warnings", []).append("Bandit timed out")
            return []
        except Exception as e:
            ctx.settings.setdefault("_warnings", []).append(f"Bandit failed: {e}")
            return []
        conf_map = {"HIGH": 90, "MEDIUM": 70, "LOW": 50}
        sev_map = {"HIGH": "HIGH", "MEDIUM": "MEDIUM", "LOW": "LOW"}
        res = []
        for r in data.get("results", []):
            rel = os.path.relpath(r["filename"], ctx.root).replace(os.sep, "/")
            tid = r.get("test_id", "B000")
            fam = {"B608": "sqli", "B602": "cmd", "B605": "cmd", "B604": "cmd", "B606": "cmd", "B607": "cmd",
                   "B307": "cmd", "B102": "cmd", "B301": "deser", "B302": "deser", "B506": "deser",
                   "B105": "secret", "B106": "secret", "B107": "secret", "B108": "file",
                   "B201": "cfg.debug", "B501": "cfg.tls", "B323": "cfg.tls", "B324": "cfg.hash", "B104": "cfg.bind",
                   "B701": "xss", "B703": "xss", "B308": "xss"}.get(tid, "bandit")
            rule_id = fam if "." in fam else f"{fam}.{tid}"
            code = " ".join(r.get("code", "").split("\n")[:1]) if r.get("code") else ""
            res.append(mk("Bandit", rule_id, r.get("issue_text", "Bandit finding"), CAT,
                          sev_map.get(r.get("issue_severity", "LOW"), "LOW"),
                          conf_map.get(r.get("issue_confidence", "LOW"), 50), rel, r.get("line_number"),
                          redact(self._line(ctx, rel, r.get("line_number") or 0)) or redact(code),
                          f"Bandit {tid} ({r.get('test_name','')}): {r.get('issue_text','')} See {r.get('more_info','')}",
                          "Review the flagged call and apply the remediation in the Bandit documentation for this check.",
                          KIND_STATIC))
        return res

    @staticmethod
    def _line(ctx, rel, n):
        for f in ctx.files:
            if f.rel == rel:
                ls = f.text.splitlines()
                return ls[n - 1].strip() if 0 < n <= len(ls) else ""
        return ""

    def _semgrep(self, ctx):
        exe = shutil.which("semgrep")
        cfg = ctx.settings.get("semgrep_config")
        if not exe or not cfg:
            return []  # Semgrep is optional; needs a rules config (e.g. "p/security-audit" or a local path)
        try:
            p = subprocess.run([exe, "--config", cfg, "--json", "--metrics=off", "--quiet", ctx.root],
                               capture_output=True, text=True, timeout=ctx.settings.get("tool_timeout", 180))
            data = json.loads(p.stdout or "{}")
        except Exception as e:
            ctx.settings.setdefault("_warnings", []).append(f"Semgrep failed: {e}")
            return []
        sev = {"ERROR": "HIGH", "WARNING": "MEDIUM", "INFO": "LOW"}
        res = []
        for r in data.get("results", []):
            rel = os.path.relpath(r["path"], ctx.root).replace(os.sep, "/")
            ex = r.get("extra", {})
            res.append(mk("Semgrep", "semgrep." + r.get("check_id", "rule").split(".")[-1], ex.get("message", "Semgrep finding")[:120],
                          CAT, sev.get(ex.get("severity", "INFO"), "LOW"), 80, rel, r.get("start", {}).get("line"),
                          self._line(ctx, rel, r.get("start", {}).get("line", 0)),
                          ex.get("message", ""), "Follow the remediation suggested by the Semgrep rule.", KIND_STATIC))
        return res
