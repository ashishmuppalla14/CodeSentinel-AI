"""Agent 4: Code quality. Long/complex/nested functions, duplicates, unused imports, dead code, naming."""
from __future__ import annotations

import ast
import hashlib
import re
from collections import defaultdict

from core.context import AnalysisContext, is_test_path, mk, snippet
from core.models import KIND_HEURISTIC, KIND_STATIC

NAME = "Code Quality Agent"
CAT = "Code Quality"

LONG_LOW, LONG_MED = 60, 120
CX_LOW, CX_MED = 10, 20
NEST_MAX = 4
BIG_FILE = 800
MAX_PARAMS = 7
DUP_WINDOW = 6
MAX_DUP_FINDINGS = 25
BAD_NAMES = re.compile(r"^(foo|bar|baz|tmp|temp|stuff|thing|data\d+|var\d+|func\d*|test\d+|doit|do_stuff|dostuff|aaa|asdf)$", re.I)

BRACE_FN = re.compile(
    r"(?:function\s+(\w+)\s*\(|(?:public|private|protected|static|final|async|func)\s+[\w<>\[\],.*&\s()]*?\b(\w+)\s*\([^;{)]*\)[^;{]*\{|"
    r"(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s*)?(?:function\s*)?\([^)]*\)\s*(?:=>)?\s*\{)")
BRACE_LANGS = {"JavaScript", "TypeScript", "Java", "C", "C++", "Go", "PHP"}
CTRL_WORDS = re.compile(r"\b(if|for|foreach|while|case|catch)\b|&&|\|\||\?\s*[^:?]+:")


def _complexity(fn) -> int:
    c = 1
    for n in ast.walk(fn):
        if isinstance(n, (ast.If, ast.For, ast.AsyncFor, ast.While, ast.ExceptHandler, ast.IfExp, ast.Assert)):
            c += 1
        elif isinstance(n, ast.BoolOp):
            c += len(n.values) - 1
        elif isinstance(n, ast.comprehension):
            c += 1 + len(n.ifs)
    return c


def _depth(node, d=0) -> int:
    best = d
    for ch in ast.iter_child_nodes(node):
        if isinstance(ch, (ast.If, ast.For, ast.AsyncFor, ast.While, ast.Try, ast.With, ast.AsyncWith)):
            best = max(best, _depth(ch, d + 1))
        elif isinstance(ch, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        else:
            best = max(best, _depth(ch, d))
    return best


def _brace_end(text: str, start: int):
    """Index of matching closing brace for the first '{' at/after start (naive; ignores strings/comments)."""
    i = text.find("{", start)
    if i < 0:
        return None
    depth = 0
    for j in range(i, len(text)):
        c = text[j]
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return j
    return None


class QualityAgent:
    name = NAME
    description = "Long or complex functions, deep nesting, duplicate blocks, unused imports, dead/unreachable code and naming issues."

    def run(self, ctx: AnalysisContext) -> list:
        out = []
        for f in ctx.files:
            if f.sensitive or not ctx.lang(f):
                continue
            try:
                out += self._size(ctx, f)
                if f.rel.endswith(".py"):
                    out += self._python(ctx, f)
                elif ctx.lang(f) in BRACE_LANGS:
                    out += self._brace(ctx, f)
                    out += self._unused_imports_other(ctx, f)
                out += self._commented_code(ctx, f)
            except Exception as e:
                ctx.settings.setdefault("_warnings", []).append(f"QualityAgent skipped {f.rel}: {e}")
        for fn in (self._duplicates, self._dead_python, self._dead_js):
            try:
                out += fn(ctx)
            except Exception as e:
                ctx.settings.setdefault("_warnings", []).append(f"QualityAgent {fn.__name__} failed: {e}")
        return out

    def _size(self, ctx, f):
        n = len(f.text.splitlines())
        if n > BIG_FILE:
            return [mk(NAME, "quality.big-file", f"Very large file ({n} lines)", CAT, "LOW", 80, f.rel, 1, f"{n} lines",
                       "Large files are harder to understand, review and test.", "Split into cohesive modules.", KIND_STATIC)]
        return []

    def _python(self, ctx, f):
        tree = ctx.tree(f)
        if tree is None:
            return []
        res, lines = [], f.text.splitlines()
        used = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)} | \
               {n.value.id for n in ast.walk(tree) if isinstance(n, ast.Attribute) and isinstance(n.value, ast.Name)}
        used |= {n.value for n in ast.walk(tree) if isinstance(n, ast.Constant) and isinstance(n.value, str)}  # __all__, string annotations
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                end = getattr(node, "end_lineno", node.lineno)
                length = end - node.lineno + 1
                if length > LONG_LOW:
                    res.append(mk(NAME, "quality.long-function", f"Long function '{node.name}' ({length} lines)", CAT,
                                  "MEDIUM" if length > LONG_MED else "LOW", 90, f.rel, node.lineno, snippet(lines, node.lineno),
                                  "Long functions mix responsibilities and are hard to test and review.",
                                  "Extract cohesive steps into smaller functions.", KIND_STATIC))
                cx = _complexity(node)
                if cx > CX_LOW:
                    res.append(mk(NAME, "quality.complexity", f"High cyclomatic complexity in '{node.name}' ({cx})", CAT,
                                  "MEDIUM" if cx > CX_MED else "LOW", 90, f.rel, node.lineno, snippet(lines, node.lineno),
                                  f"Cyclomatic complexity is {cx} (threshold {CX_LOW}); many branches make behaviour hard to reason about.",
                                  "Simplify branching, use early returns or lookup tables, split the function.", KIND_STATIC))
                d = _depth(node)
                if d > NEST_MAX:
                    res.append(mk(NAME, "quality.nesting", f"Deep nesting in '{node.name}' (depth {d})", CAT, "MEDIUM", 90,
                                  f.rel, node.lineno, snippet(lines, node.lineno),
                                  f"Control structures are nested {d} levels deep.", "Use guard clauses and extract inner blocks.", KIND_STATIC))
                nparams = len(node.args.args) + len(node.args.kwonlyargs) - (1 if node.args.args and node.args.args[0].arg in ("self", "cls") else 0)
                if nparams > MAX_PARAMS:
                    res.append(mk(NAME, "quality.params", f"Too many parameters in '{node.name}' ({nparams})", CAT, "LOW", 85,
                                  f.rel, node.lineno, snippet(lines, node.lineno), "Many parameters make call sites error-prone.",
                                  "Group related values in a dataclass or object.", KIND_STATIC))
                for dflt in list(node.args.defaults) + [x for x in node.args.kw_defaults if x]:
                    if isinstance(dflt, (ast.List, ast.Dict, ast.Set)) or (isinstance(dflt, ast.Call) and getattr(dflt.func, "id", "") in ("list", "dict", "set")):
                        res.append(mk(NAME, "quality.mutable-default", f"Mutable default argument in '{node.name}'", CAT, "MEDIUM", 95,
                                      f.rel, node.lineno, snippet(lines, node.lineno),
                                      "Mutable defaults are created once and shared between calls, a classic source of bugs.",
                                      "Default to None and create the object inside the function.", KIND_STATIC))
                        break
                nm = node.name
                if BAD_NAMES.match(nm) or (len(nm) <= 2 and nm not in ("_", "__")) or (re.search(r"[a-z][A-Z]", nm) and not nm.startswith("__")
                                                                                          and not is_test_path(f.rel)):
                    res.append(mk(NAME, "quality.naming", f"Poor function name '{nm}'", CAT, "LOW", 65, f.rel, node.lineno,
                                  snippet(lines, node.lineno), "Name is non-descriptive or not snake_case (PEP 8).",
                                  "Use a descriptive snake_case name.", KIND_HEURISTIC))
            elif isinstance(node, ast.ClassDef) and not re.match(r"^_?[A-Z][A-Za-z0-9]*$", node.name):
                res.append(mk(NAME, "quality.naming", f"Class '{node.name}' is not PascalCase", CAT, "LOW", 70, f.rel, node.lineno,
                              snippet(lines, node.lineno), "Class names should follow PascalCase (PEP 8).", "Rename the class.", KIND_HEURISTIC))
            elif isinstance(node, ast.ImportFrom) and any(a.name == "*" for a in node.names):
                res.append(mk(NAME, "quality.star-import", "Wildcard import", CAT, "LOW", 90, f.rel, node.lineno, snippet(lines, node.lineno),
                              "Star imports pollute the namespace and hide where names come from.", "Import explicit names.", KIND_STATIC))
        # unused imports (skip __init__ re-exports)
        if not f.rel.endswith("__init__.py"):
            for node in ast.walk(tree):
                if isinstance(node, (ast.Import, ast.ImportFrom)):
                    if isinstance(node, ast.ImportFrom) and node.module == "__future__":
                        continue
                    for a in node.names:
                        if a.name == "*":
                            continue
                        bound = (a.asname or a.name).split(".")[0]
                        if bound not in used:
                            res.append(mk(NAME, "quality.unused-import", f"Unused import '{bound}'", CAT, "LOW", 85, f.rel,
                                          node.lineno, snippet(lines, node.lineno), "The imported name is never referenced in this file.",
                                          "Remove the import.", KIND_STATIC))
        res += self._unreachable(f, tree, lines)
        return res

    def _unreachable(self, f, tree, lines):
        res = []
        for node in ast.walk(tree):
            for field in ("body", "orelse", "finalbody"):
                blk = getattr(node, field, None)
                if not isinstance(blk, list):
                    continue
                for i, st in enumerate(blk[:-1]):
                    if isinstance(st, (ast.Return, ast.Raise, ast.Continue, ast.Break)):
                        nxt = blk[i + 1]
                        res.append(mk(NAME, "dead.unreachable", "Unreachable code after return/raise/break", CAT, "LOW", 95, f.rel,
                                      nxt.lineno, snippet(lines, nxt.lineno), "Statements after a terminating statement can never run.",
                                      "Delete the dead statements or fix the control flow.", KIND_STATIC))
                        break
        return res

    def _brace(self, ctx, f):
        res, lines, text = [], f.text.splitlines(), f.text
        lang = ctx.lang(f)
        for m in BRACE_FN.finditer(text):
            name = next((g for g in m.groups() if g), "?")
            if name in ("if", "for", "while", "switch", "catch", "return", "else"):
                continue
            end = _brace_end(text, m.start())
            if end is None:
                continue
            ln = text.count("\n", 0, m.start()) + 1
            length = text.count("\n", m.start(), end) + 1
            body = text[m.start():end]
            if length > LONG_LOW:
                res.append(mk(NAME, "quality.long-function", f"Long function '{name}' (~{length} lines)", CAT,
                              "MEDIUM" if length > LONG_MED else "LOW", 65, f.rel, ln, snippet(lines, ln),
                              "Long functions mix responsibilities and are hard to test.", "Extract smaller functions.", KIND_HEURISTIC))
            cx = 1 + len(CTRL_WORDS.findall(body))
            if cx > CX_LOW + 5:
                res.append(mk(NAME, "quality.complexity", f"High estimated complexity in '{name}' (~{cx})", CAT,
                              "MEDIUM" if cx > CX_MED + 5 else "LOW", 55, f.rel, ln, snippet(lines, ln),
                              "Keyword-count estimate of cyclomatic complexity is high.", "Split into smaller functions.", KIND_HEURISTIC))
        # nesting by brace depth (naive)
        thr = 7 if lang in ("Java", "C++", "PHP") else 6
        depth = 0
        reported = 0
        for i, line in enumerate(lines, 1):
            s = re.sub(r'"[^"]*"|\'[^\']*\'', "", line)
            s = s.split("//")[0]
            depth += s.count("{") - s.count("}")
            if depth >= thr and reported < 3:
                res.append(mk(NAME, "quality.nesting", f"Deep block nesting (depth {depth})", CAT, "MEDIUM", 50, f.rel, i,
                              snippet(lines, i), "Code is nested very deeply, which hurts readability.",
                              "Use early returns and extract inner blocks.", KIND_HEURISTIC))
                reported += 1
                depth = 0 if depth > 30 else depth
                break
        return res

    def _unused_imports_other(self, ctx, f):
        res, lines = [], f.text.splitlines()
        lang = ctx.lang(f)
        if lang in ("JavaScript", "TypeScript"):
            for i, line in enumerate(lines, 1):
                m = re.match(r"\s*import\s+(?:(\w+)\s*,?\s*)?(?:\{([^}]*)\})?(?:\*\s+as\s+(\w+))?\s*from\s+['\"]", line)
                if not m or "type " in line.split("from")[0]:
                    continue
                names = [m.group(1), m.group(3)] + [p.split(" as ")[-1].strip() for p in (m.group(2) or "").split(",")]
                for n in [x for x in names if x]:
                    if len(re.findall(r"\b" + re.escape(n) + r"\b", f.text)) == 1:
                        res.append(mk(NAME, "quality.unused-import", f"Unused import '{n}'", CAT, "LOW", 70, f.rel, i, snippet(lines, i),
                                      "The imported name appears only in its import statement.", "Remove it.", KIND_HEURISTIC))
        elif lang == "Java":
            for i, line in enumerate(lines, 1):
                m = re.match(r"\s*import\s+(?:static\s+)?[\w.]+\.(\w+)\s*;", line)
                if m and len(re.findall(r"\b" + m.group(1) + r"\b", f.text)) == 1:
                    res.append(mk(NAME, "quality.unused-import", f"Unused import '{m.group(1)}'", CAT, "LOW", 70, f.rel, i, snippet(lines, i),
                                  "The imported class is never used in this file.", "Remove it.", KIND_HEURISTIC))
        return res

    def _commented_code(self, ctx, f):
        lines = f.text.splitlines()
        marker = "#" if f.rel.endswith(".py") or f.rel.endswith(".sh") else "//"
        codey = re.compile(r"^\s*" + re.escape(marker) + r"\s*(def |class |if .*:|for .*:|return\b|import |from .* import|\w+\s*=\s*\S|.*[;{}]\s*$|\w+\(.*\)\s*$)")
        run = 0
        start = 0
        res = []
        for i, line in enumerate(lines + [""], 1):
            if codey.match(line):
                if run == 0:
                    start = i
                run += 1
            else:
                if run >= 5:
                    res.append(mk(NAME, "quality.commented-code", f"Block of commented-out code ({run} lines)", CAT, "LOW", 65, f.rel,
                                  start, snippet(lines, start), "Commented-out code clutters the file; version control already keeps history.",
                                  "Delete it.", KIND_HEURISTIC))
                run = 0
        return res[:3]

    def _duplicates(self, ctx):
        idx = defaultdict(list)
        per_file = {}
        for f in ctx.files:
            if not ctx.lang(f) or f.sensitive or is_test_path(f.rel):
                continue
            seq = []
            for i, l in enumerate(f.text.splitlines(), 1):
                s = l.strip()
                if len(s) < 12 or s.startswith(("#", "//", "*", "/*", "import ", "from ", "using ", "package ", "include")) or s in ("{", "}", "});", "end"):
                    continue
                seq.append((i, re.sub(r"\s+", " ", s)))
            per_file[f.rel] = seq
            for k in range(len(seq) - DUP_WINDOW + 1):
                h = hashlib.md5("\n".join(x[1] for x in seq[k:k + DUP_WINDOW]).encode()).hexdigest()
                idx[h].append((f.rel, seq[k][0], k))
        res, seen_cover = [], set()
        for h, locs in idx.items():
            if len({(a, b) for a, b, _ in locs}) < 2:
                continue
            locs = sorted(set(locs))
            first = locs[0]
            for rel, ln, k in locs[1:]:
                if (rel, k // DUP_WINDOW) in seen_cover or (rel == first[0] and abs(ln - first[1]) < DUP_WINDOW):
                    continue
                seen_cover.add((rel, k // DUP_WINDOW))
                src = next(f for f in ctx.files if f.rel == rel)
                res.append(mk(NAME, "quality.duplicate-block", f"Duplicated code block ({DUP_WINDOW}+ lines)", CAT, "LOW", 75, rel, ln,
                              snippet(src.text, ln), f"A block of {DUP_WINDOW} or more meaningful lines is repeated from {first[0]}:{first[1]}.",
                              "Extract the shared logic into a function/module.", KIND_STATIC))
                if len(res) >= MAX_DUP_FINDINGS:
                    return res
        return res

    # --- dead code ------------------------------------------------------
    def _dead_python(self, ctx):
        defs, refs = [], set()
        for f in ctx.py_files():
            tree = ctx.tree(f)
            if tree is None:
                continue
            for n in ast.walk(tree):
                if isinstance(n, ast.Name):
                    refs.add(n.id)
                elif isinstance(n, ast.Attribute):
                    refs.add(n.attr)
                elif isinstance(n, ast.Constant) and isinstance(n.value, str) and n.value.isidentifier():
                    refs.add(n.value)
                elif isinstance(n, (ast.Import, ast.ImportFrom)):
                    for a in n.names:
                        refs.add(a.name.split(".")[-1])
            for n in tree.body:
                if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    defs.append((f, n))
                elif isinstance(n, ast.ClassDef):
                    for m in n.body:
                        if isinstance(m, (ast.FunctionDef, ast.AsyncFunctionDef)):
                            defs.append((f, m))
        words = set(re.findall(r"[A-Za-z_]\w+", " ".join(x.text for x in ctx.files if not x.rel.endswith(".py") and not x.sensitive)))
        res = []
        for f, n in defs:
            nm = n.name
            if nm in refs or nm in words or (nm.startswith("__") and nm.endswith("__")) or nm in ("main", "setUp", "tearDown", "run", "name", "description") \
                    or nm.startswith(("test", "pytest_")) or n.decorator_list or is_test_path(f.rel) or f.rel.endswith("conftest.py"):
                continue
            lines = f.text.splitlines()
            res.append(mk(NAME, "dead.unused-function", f"Function '{nm}' appears unused", CAT, "LOW", 60, f.rel, n.lineno,
                          snippet(lines, n.lineno),
                          "No reference to this name was found anywhere in the scanned repository. It may still be used dynamically or by external callers.",
                          "Verify it is not part of a public API, then remove it.", KIND_HEURISTIC))
        return res[:40]

    def _dead_js(self, ctx):
        files = [f for f in ctx.files if ctx.lang(f) in ("JavaScript", "TypeScript") and not f.sensitive]
        if not files:
            return []
        blob = "\n".join(f.text for f in files)
        counts = defaultdict(int)
        for w in re.findall(r"\b[A-Za-z_$][\w$]*\b", blob):
            counts[w] += 1
        res = []
        for f in files:
            if is_test_path(f.rel):
                continue
            lines = f.text.splitlines()
            for i, line in enumerate(lines, 1):
                m = re.match(r"\s*(?:async\s+)?function\s+(\w+)\s*\(", line)
                if m and counts[m.group(1)] == 1 and "export" not in line:
                    res.append(mk(NAME, "dead.unused-function", f"Function '{m.group(1)}' appears unused", CAT, "LOW", 50, f.rel, i,
                                  snippet(lines, i), "The function name appears only once across all JS/TS files.",
                                  "Remove it if it is not invoked from HTML or other entry points.", KIND_HEURISTIC))
        return res[:20]
