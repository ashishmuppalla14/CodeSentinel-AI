"""Agent 3: Completeness. TODO/FIXME, stubs, placeholder returns, empty files, missing tests/config."""
from __future__ import annotations

import ast
import os
import re

from core.context import AnalysisContext, is_test_path, line_of, mk, snippet
from core.language_detector import CODE_LANGS
from core.models import KIND_HEURISTIC, KIND_STATIC

NAME = "Completeness Agent"
CAT = "Completeness"

MARKER_RE = re.compile(r"(?:#|//|/\*|\*|--|<!--)\s*.*?\b(TODO|FIXME|XXX|HACK)\b[:\s(]?(.*)", re.I)
ROUTE_ATTRS = {"get", "post", "put", "delete", "patch", "route", "api_route", "head", "options"}
PLACEHOLDER_NAMES = re.compile(r"^(get|fetch|load|process|handle|compute|calculate|save|send|parse|validate|create|update|delete|run|execute|generate|build|authenticate|connect)")
STUB_STR = re.compile(r"(?i)^(todo|tbd|not implemented|not yet implemented|coming soon|placeholder|stub|fixme)\b")
UNCONFIGURED = re.compile(
    r"(?i)\b(api[_-]?key|token|secret|endpoint|base[_-]?url|client[_-]?id|webhook)\w*\s*[:=]\s*['\"](|your[_-][^'\"]*|<[^'\"]*>|x{3,}|todo|changeme|replace[^'\"]*|insert[^'\"]*)['\"]")

MANIFESTS = {
    "Python": ["requirements.txt", "pyproject.toml", "setup.py", "Pipfile"],
    "JavaScript": ["package.json"], "TypeScript": ["package.json"],
    "Java": ["pom.xml", "build.gradle", "build.gradle.kts"], "Go": ["go.mod"],
    "PHP": ["composer.json"], "C": ["Makefile", "CMakeLists.txt", "meson.build"],
    "C++": ["Makefile", "CMakeLists.txt", "meson.build"],
}


def _trivial(body):
    """Return a label if a function body is a stub, else None."""
    b = list(body)
    if b and isinstance(b[0], ast.Expr) and isinstance(getattr(b[0], "value", None), ast.Constant) and isinstance(b[0].value.value, str):
        b = b[1:]
    if not b:
        return "docstring-only"
    if len(b) == 1:
        n = b[0]
        if isinstance(n, ast.Pass):
            return "pass"
        if isinstance(n, ast.Expr) and isinstance(n.value, ast.Constant) and n.value.value is Ellipsis:
            return "ellipsis"
        if isinstance(n, ast.Raise):
            e = n.exc
            nm = getattr(e, "id", None) or getattr(getattr(e, "func", None), "id", None)
            if nm == "NotImplementedError":
                return "not-implemented"
        if isinstance(n, ast.Return):
            v = n.value
            if v is None:
                return "return-none"
            if isinstance(v, ast.Constant) and (v.value in (None, False, 0, "") or (isinstance(v.value, str) and STUB_STR.match(v.value))):
                return "placeholder-return"
            if isinstance(v, (ast.List, ast.Dict, ast.Tuple, ast.Set)) and not (getattr(v, "elts", None) or getattr(v, "keys", None)):
                return "placeholder-return"
            if isinstance(v, ast.Dict) and all(isinstance(x, ast.Constant) and isinstance(x.value, str) and STUB_STR.match(x.value) for x in v.values) and v.values:
                return "placeholder-return"
    return None


def _is_abstract(fn, cls):
    for d in fn.decorator_list:
        t = ast.unparse(d)
        if "abstract" in t or "overload" in t:
            return True
    if cls is not None:
        for b in cls.bases:
            if ast.unparse(b) in ("ABC", "abc.ABC", "Protocol", "typing.Protocol") or "Protocol" in ast.unparse(b):
                return True
    return False


class CompletenessAgent:
    name = NAME
    description = "TODO/FIXME markers, stub or placeholder functions, unfinished API endpoints, empty files, missing tests and project config."

    def run(self, ctx: AnalysisContext) -> list:
        out = []
        for f in ctx.files:
            if f.sensitive:
                continue
            try:
                out += self._markers(ctx, f)
                out += self._empty_file(ctx, f)
                out += self._placeholders_cfg(ctx, f)
                if f.rel.endswith(".py"):
                    out += self._python(ctx, f)
                else:
                    out += self._brace(ctx, f)
            except Exception as e:
                ctx.settings.setdefault("_warnings", []).append(f"CompletenessAgent skipped {f.rel}: {e}")
        try:
            out += self._repo_level(ctx)
        except Exception as e:
            ctx.settings.setdefault("_warnings", []).append(f"CompletenessAgent repo checks failed: {e}")
        return out

    def _markers(self, ctx, f):
        res = []
        if not (ctx.lang(f) or f.rel.lower().endswith((".sh", ".yml", ".yaml", ".md", ".txt", ".toml", ".cfg", ".ini"))):
            return res
        if f.rel.lower().endswith((".md", ".txt")):
            return res
        lines = f.text.splitlines()
        for i, line in enumerate(lines, 1):
            if len(line) > 1000:
                continue
            m = MARKER_RE.search(line)
            if not m:
                continue
            # require the marker to be inside a comment, not a string literal
            pre = line[:m.start(1)]
            if pre.count('"') % 2 == 1 or pre.count("'") % 2 == 1:
                if not pre.lstrip().startswith(("#", "//", "*", "/*")):
                    continue
            kind = m.group(1).upper()
            sev = "MEDIUM" if kind in ("FIXME", "XXX") else "LOW"
            note = m.group(2).strip()[:100]
            res.append(mk(NAME, f"todo.{kind.lower()}", f"{kind} marker: {note}" if note else f"{kind} marker", CAT, sev, 95,
                          f.rel, i, snippet(lines, i),
                          f"A {kind} comment indicates known unfinished work or a known defect.",
                          "Resolve the item or track it in an issue tracker and remove the comment.", KIND_STATIC))
        return res

    def _empty_file(self, ctx, f):
        if not ctx.lang(f) or os.path.basename(f.rel) in ("__init__.py", "conftest.py"):
            return []
        body = f.text.strip()
        if not body:
            return [mk(NAME, "empty.file", "Empty source file", CAT, "LOW", 95, f.rel, 1, "(file is empty)",
                       "The file contains no code.", "Remove it or implement its intended content.", KIND_STATIC)]
        code = [l for l in body.splitlines() if l.strip() and not l.strip().startswith(("#", "//", "/*", "*", "*/", "--"))]
        if not code and len(body.splitlines()) >= 1:
            return [mk(NAME, "empty.comments-only", "Source file contains only comments", CAT, "LOW", 80, f.rel, 1,
                       snippet(body, 1), "The file has no executable code.", "Implement it or remove it.", KIND_STATIC)]
        return []

    def _placeholders_cfg(self, ctx, f):
        res = []
        if not ctx.lang(f) or is_test_path(f.rel):
            return res
        lines = f.text.splitlines()
        for i, line in enumerate(lines, 1):
            if UNCONFIGURED.search(line) and not line.lstrip().startswith(("#", "//")):
                res.append(mk(NAME, "integration.unconfigured", "Unconfigured integration placeholder", CAT, "LOW", 65,
                              f.rel, i, snippet(lines, i),
                              "A credential/endpoint setting is left empty or filled with a placeholder, so this integration likely does not work yet.",
                              "Read the value from configuration/environment and document it in .env.example.", KIND_HEURISTIC))
        return res

    def _python(self, ctx, f):
        tree = ctx.tree(f)
        if tree is None:
            return []
        res, lines = [], f.text.splitlines()
        in_test = is_test_path(f.rel)
        parents = {}
        for node in ast.walk(tree):
            for ch in ast.iter_child_nodes(node):
                parents[ch] = node
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            cls = parents.get(node) if isinstance(parents.get(node), ast.ClassDef) else None
            label = _trivial(node.body)
            if not label or in_test or _is_abstract(node, cls):
                continue
            if node.name.startswith("__") and node.name.endswith("__"):
                continue
            route = next((d for d in node.decorator_list if isinstance(d, ast.Call) and isinstance(d.func, ast.Attribute)
                          and d.func.attr in ROUTE_ATTRS), None)
            if route is not None:
                res.append(mk(NAME, "incomplete.endpoint", f"Incomplete API endpoint '{node.name}'", CAT, "HIGH", 85,
                              f.rel, node.lineno, snippet(lines, node.lineno),
                              f"The route handler body is a stub ({label}); the endpoint is declared but does nothing real.",
                              "Implement the handler or remove the route.", KIND_STATIC))
                continue
            if label in ("pass", "ellipsis", "docstring-only", "not-implemented"):
                title = {"not-implemented": "Function raises NotImplementedError", "pass": "Empty function body (pass)",
                         "ellipsis": "Empty function body (...)", "docstring-only": "Function has only a docstring"}[label]
                conf = 90 if label != "docstring-only" else 80
                sev = "MEDIUM" if label == "not-implemented" else "LOW"
                res.append(mk(NAME, f"stub.{label}", f"{title}: {node.name}", CAT, sev, conf, f.rel, node.lineno,
                              snippet(lines, node.lineno), "The function has no implementation.",
                              "Implement the function, or mark intentional interface stubs with @abstractmethod.", KIND_STATIC))
            elif label in ("placeholder-return", "return-none") and PLACEHOLDER_NAMES.match(node.name) and \
                    (node.args.args or node.args.kwonlyargs):
                res.append(mk(NAME, "stub.placeholder-return", f"Placeholder return value in '{node.name}'", CAT, "LOW", 60,
                              f.rel, node.lineno, snippet(lines, node.lineno),
                              "A function whose name implies real work just returns a constant empty/placeholder value.",
                              "Implement the logic or document why a constant is correct.", KIND_HEURISTIC))
        return res

    def _brace(self, ctx, f):
        lang = ctx.lang(f)
        res, lines = [], f.text.splitlines()
        if lang is None or is_test_path(f.rel):
            return res
        pats = []
        if lang in ("JavaScript", "TypeScript"):
            pats.append(r"function\s+(\w+)\s*\([^)]*\)\s*(?::\s*[\w<>\[\]|]+\s*)?\{\s*(?://[^\n]*\n\s*)*\}")
            pats.append(r"const\s+(\w+)\s*=\s*(?:async\s*)?\([^)]*\)\s*=>\s*\{\s*\}")
        elif lang == "PHP":
            pats.append(r"function\s+(\w+)\s*\([^)]*\)\s*\{\s*(?://[^\n]*\n\s*)*\}")
        elif lang == "Go":
            pats.append(r"func\s+(?:\([^)]*\)\s*)?(\w+)\s*\([^)]*\)[^{\n]*\{\s*\}")
        elif lang in ("Java", "C", "C++"):
            pats.append(r"(?m)^[ \t]*(?:public|private|protected|static|final|virtual|inline|\w+[\w<>\[\]*&]*)\s+(?:[\w<>\[\]*&]+\s+)?(\w+)\s*\([^)]*\)\s*(?:throws [\w, .]+)?\s*\{\s*(?://[^\n]*\n\s*)*\}")
        for p in pats:
            for m in re.finditer(p, f.text):
                name = m.group(1)
                if name in ("if", "for", "while", "switch", "catch", "else", "main") or (lang == "Java" and name[0].isupper()):
                    continue
                ln = line_of(f.text, m.start())
                res.append(mk(NAME, "stub.empty-body", f"Empty function body: {name}", CAT, "LOW", 75, f.rel, ln,
                              snippet(lines, ln), "The function body is empty.",
                              "Implement the function or remove it.", KIND_HEURISTIC))
        for ln_i, line in enumerate(lines, 1):
            if re.search(r"throw new (UnsupportedOperationException|NotImplementedException)|panic\(\s*\"(todo|not implemented)", line, re.I) \
                    or re.search(r"(?i)\bthrow\s+new\s+\\?Exception\(\s*['\"]not implemented", line):
                res.append(mk(NAME, "stub.not-implemented", "Not-implemented stub", CAT, "MEDIUM", 85, f.rel, ln_i,
                              snippet(lines, ln_i), "The code path throws a 'not implemented' error.",
                              "Implement the missing behaviour.", KIND_STATIC))
        if lang in ("JavaScript", "TypeScript"):
            rx = re.compile(r"\.(get|post|put|delete|patch)\(\s*['\"][^'\"]+['\"]\s*,\s*(?:async\s*)?\(?[\w\s,]*\)?\s*=>\s*(?:\{\s*\}|\{\s*res\.(?:send|json)\(\s*['\"](todo|not implemented)[^'\"]*['\"]\s*\);?\s*\})", re.I)
            for m in rx.finditer(f.text):
                ln = line_of(f.text, m.start())
                res.append(mk(NAME, "incomplete.endpoint", "Incomplete API endpoint", CAT, "HIGH", 80, f.rel, ln,
                              snippet(lines, ln), "The route handler is empty or returns a placeholder.",
                              "Implement the handler or remove the route.", KIND_HEURISTIC))
        return res

    def _repo_level(self, ctx):
        res = []
        paths = {f.rel for f in ctx.files}
        names = {os.path.basename(p).lower() for p in paths}
        code = [f for f in ctx.files if ctx.lang(f) in CODE_LANGS]
        if not code:
            return res
        langs = list(ctx.languages)
        if not any(n.startswith("readme") for n in names):
            res.append(mk(NAME, "missing.readme", "Missing README", CAT, "LOW", 95, "(repository)", None, "No README file found",
                          "A README is the first thing contributors and users look for.", "Add a README describing purpose, setup and usage.", KIND_STATIC))
        if ".gitignore" not in names:
            res.append(mk(NAME, "missing.gitignore", "Missing .gitignore", CAT, "LOW", 85, "(repository)", None, "No .gitignore found",
                          "Without it, build artifacts and secrets can be committed accidentally.", "Add a .gitignore for your language/tooling.", KIND_STATIC))
        for lang in langs[:2]:
            wanted = MANIFESTS.get(lang)
            if wanted and not any(os.path.basename(p) in wanted for p in paths):
                res.append(mk(NAME, "missing.manifest", f"No dependency/build manifest for {lang}", CAT, "LOW", 70, "(repository)", None,
                              f"Expected one of: {', '.join(wanted)}", "Without a manifest, the project cannot be reproducibly built or installed.",
                              f"Add {wanted[0]} (or equivalent).", KIND_STATIC))
        tests = [f for f in code if is_test_path(f.rel)]
        src = [f for f in code if not is_test_path(f.rel)]
        if len(src) >= 3 and not tests:
            res.append(mk(NAME, "missing.tests", "No tests found", CAT, "MEDIUM", 85, "(repository)", None,
                          f"{len(src)} source files, 0 test files",
                          "No automated tests were detected, so regressions will go unnoticed.", "Add unit tests for core logic and run them in CI.", KIND_STATIC))
        elif len(src) >= 10 and len(tests) / len(src) < 0.1:
            res.append(mk(NAME, "missing.tests-low", "Very low test coverage by file count", CAT, "LOW", 60, "(repository)", None,
                          f"{len(tests)} test files for {len(src)} source files",
                          "Test files are scarce relative to the amount of source code (file count only, not line coverage).",
                          "Add tests for the most critical modules.", KIND_HEURISTIC))
        return res
