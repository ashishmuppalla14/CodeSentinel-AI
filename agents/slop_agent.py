"""Agent 2: AI-slop / suspicious-pattern detector.

These are code-quality smells often seen in low-effort or auto-generated code.
They are NOT proof that code was AI-generated; every finding is a heuristic.
"""
from __future__ import annotations

import ast
import hashlib
import re

from core.context import AnalysisContext, is_test_path, mk, snippet
from core.models import KIND_HEURISTIC, KIND_STATIC

NAME = "AI Slop Detector"
CAT = "AI Slop"

REDUNDANT_COMMENT = re.compile(
    r"^\s*(#|//)\s*(this (function|method|class|variable|code|line)\b|initialize (the )?\w+|increment\b|decrement\b|"
    r"loop (through|over)\b|iterate (through|over)\b|return(s)? the (result|value)\b|import(s)? (the )?\w+|"
    r"define (a |the )?(function|variable|class)\b|create (a |an |the )?(new )?(variable|list|dictionary|object)\b|"
    r"set (the )?\w+ to\b|call (the )?\w+ function\b|print(s)? (the )?\w+)", re.I)
PLACEHOLDER_STR = re.compile(r"(?i)['\"](lorem ipsum[^'\"]*|your[_ -](api[_ -]?key|token|name|email)[_ a-z]*here|replace[_ -]?me|insert[_ -]\w+[_ -]here|foo ?bar|dummy[_ -]?(data|value|text)|sample[_ -]?(data|text))['\"]")
GENERIC_NAME = re.compile(r"(Manager|Handler|Helper|Util|Utils|Wrapper|Factory|Processor|Service|Provider)$")


def _body_wo_doc(fn):
    b = list(fn.body)
    if b and isinstance(b[0], ast.Expr) and isinstance(getattr(b[0], "value", None), ast.Constant) and isinstance(b[0].value.value, str):
        b = b[1:]
    return b


class SlopAgent:
    name = NAME
    description = "Flags generic exception handling, trivial wrappers, redundant comments, near-duplicate functions and over-abstraction (heuristic smells, not proof of AI authorship)."

    def run(self, ctx: AnalysisContext) -> list:
        out = []
        dup_index = {}
        for f in ctx.files:
            if f.sensitive:
                continue
            try:
                out += self._generic(ctx, f)
                if f.rel.endswith(".py"):
                    out += self._python(ctx, f, dup_index)
                else:
                    out += self._brace_langs(ctx, f)
            except Exception as e:
                ctx.settings.setdefault("_warnings", []).append(f"SlopAgent skipped {f.rel}: {e}")
        out += self._dups(dup_index)
        return out

    # language-independent
    def _generic(self, ctx, f):
        res, lines = [], f.text.splitlines()
        if not ctx.lang(f) and not f.rel.endswith((".sh",)):
            return res
        n_red = 0
        first = None
        comment_lines = 0
        for i, line in enumerate(lines, 1):
            s = line.strip()
            if s.startswith(("#", "//")):
                comment_lines += 1
            if REDUNDANT_COMMENT.match(line):
                n_red += 1
                first = first or i
            if PLACEHOLDER_STR.search(line) and not is_test_path(f.rel):
                res.append(mk(NAME, "slop.placeholder-string", "Placeholder / filler string in source", CAT, "LOW", 60,
                              f.rel, i, snippet(lines, i),
                              "Filler text such as 'lorem ipsum' or 'your_api_key_here' usually means unfinished or template-copied code.",
                              "Replace with real configuration or remove the dead filler.", KIND_HEURISTIC))
        if n_red >= 3:
            res.append(mk(NAME, "slop.redundant-comments", f"Redundant comments restating code ({n_red} found)", CAT, "LOW", 55,
                          f.rel, first, snippet(lines, first),
                          "Several comments merely narrate what the next line obviously does. This is a common pattern in boilerplate-heavy or auto-generated code.",
                          "Delete comments that restate the code; keep comments that explain why.", KIND_HEURISTIC))
        if len(lines) >= 40 and comment_lines / len(lines) > 0.5:
            res.append(mk(NAME, "slop.comment-heavy", "File is more than half comments", CAT, "INFO", 40,
                          f.rel, 1, f"{comment_lines}/{len(lines)} lines are comments",
                          "An unusually high comment ratio can indicate commented-out code or verbose generated scaffolding.",
                          "Remove commented-out code and trim boilerplate comments.", KIND_HEURISTIC))
        return res

    def _brace_langs(self, ctx, f):
        res, lines = [], f.text.splitlines()
        lang = ctx.lang(f)
        if lang in ("JavaScript", "TypeScript"):
            rx = re.compile(r"catch\s*(\([^)]*\))?\s*\{\s*(//[^\n]*)?\s*\}")
            for m in rx.finditer(f.text):
                ln = f.text.count("\n", 0, m.start()) + 1
                res.append(mk(NAME, "slop.empty-catch", "Empty catch block swallows errors", CAT, "MEDIUM", 75, f.rel, ln,
                              snippet(lines, ln), "Errors are silently ignored, hiding failures.",
                              "Handle, log or re-raise the error.", KIND_HEURISTIC))
        elif lang in ("Java", "PHP", "C#"):
            rx = re.compile(r"catch\s*\(\s*(Exception|Throwable|\\Exception)\s+\$?\w+\s*\)\s*\{\s*(//[^\n]*)?\s*\}")
            for m in rx.finditer(f.text):
                ln = f.text.count("\n", 0, m.start()) + 1
                res.append(mk(NAME, "slop.empty-catch", "Generic catch with empty body", CAT, "MEDIUM", 80, f.rel, ln,
                              snippet(lines, ln), "Catching the base exception type and ignoring it hides real failures.",
                              "Catch specific exceptions and handle or log them.", KIND_HEURISTIC))
        elif lang == "Go":
            for i, line in enumerate(lines, 1):
                if re.match(r"\s*_\s*=\s*err\b", line):
                    res.append(mk(NAME, "slop.go-ignored-error", "Go error explicitly discarded", CAT, "LOW", 70, f.rel, i,
                                  snippet(lines, i), "Assigning err to _ discards a failure.", "Handle or return the error.", KIND_HEURISTIC))
        return res

    def _python(self, ctx, f, dup_index):
        tree = ctx.tree(f)
        if tree is None:
            return []
        res, lines = [], f.text.splitlines()
        for node in ast.walk(tree):
            if isinstance(node, ast.ExceptHandler):
                t = node.type
                bare = t is None
                broad = isinstance(t, ast.Name) and t.id in ("Exception", "BaseException")
                body = [b for b in node.body]
                swallow = all(isinstance(b, (ast.Pass, ast.Continue)) or
                              (isinstance(b, ast.Expr) and isinstance(b.value, ast.Constant)) for b in body)
                printed = len(body) == 1 and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Call) \
                    and getattr(body[0].value.func, "id", "") == "print"
                if (bare or broad) and (swallow or printed):
                    res.append(mk(NAME, "slop.generic-except", "Overly generic exception handler that hides errors", CAT,
                                  "MEDIUM", 90, f.rel, node.lineno, snippet(lines, node.lineno),
                                  "A bare/broad except that does nothing (or only prints) swallows every failure, including bugs and KeyboardInterrupt.",
                                  "Catch specific exceptions and log or re-raise.", KIND_STATIC))
                elif swallow and not bare and not broad:
                    res.append(mk(NAME, "slop.silent-except", "Exception silently ignored", CAT, "LOW", 60, f.rel,
                                  node.lineno, snippet(lines, node.lineno),
                                  "The handler ignores the error without logging; sometimes intentional, often not.",
                                  "Add a comment explaining why or log the exception.", KIND_STATIC))
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                body = _body_wo_doc(node)
                # wrapper: single `return other(<same params>)`
                if len(body) == 1 and isinstance(body[0], ast.Return) and isinstance(body[0].value, ast.Call) \
                        and not node.decorator_list and not node.name.startswith("__"):
                    call = body[0].value
                    params = [a.arg for a in node.args.args if a.arg not in ("self", "cls")]
                    args = [a.id for a in call.args if isinstance(a, ast.Name)]
                    if params and args == params and len(call.args) == len(params) and not call.keywords:
                        tgt = ast.unparse(call.func)
                        res.append(mk(NAME, "slop.wrapper", f"Meaningless wrapper function '{node.name}'", CAT, "LOW", 70,
                                      f.rel, node.lineno, snippet(lines, node.lineno),
                                      f"'{node.name}' only forwards its arguments to '{tgt}' without adding behaviour.",
                                      "Call the target directly or add real logic/validation to the wrapper.", KIND_STATIC))
                # near-duplicate functions via normalized AST hash
                if len(body) >= 3 and not node.name.startswith("__") and not is_test_path(f.rel):
                    norm = ast.dump(ast.Module(body=body, type_ignores=[]), annotate_fields=False)
                    if len(norm) > 200:
                        h = hashlib.md5(norm.encode()).hexdigest()
                        dup_index.setdefault(h, []).append((f.rel, node.lineno, node.name, snippet(lines, node.lineno)))
            if isinstance(node, ast.ClassDef):
                meths = [n for n in node.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name != "__init__"]
                if GENERIC_NAME.search(node.name) and len(meths) == 1 and not node.bases and not node.decorator_list:
                    res.append(mk(NAME, "slop.thin-class", f"Class '{node.name}' wraps a single method", CAT, "LOW", 50,
                                  f.rel, node.lineno, snippet(lines, node.lineno),
                                  "A *Manager/*Handler/*Helper style class with one method is often an unnecessary abstraction.",
                                  "Consider a plain function unless the class holds meaningful state.", KIND_HEURISTIC))
        return res

    def _dups(self, idx):
        res = []
        for h, locs in idx.items():
            if len(locs) < 2:
                continue
            for rel, ln, name, snip in locs[1:]:
                first = locs[0]
                res.append(mk(NAME, "slop.dup-function", f"Function '{name}' is structurally identical to '{first[2]}'", CAT,
                              "MEDIUM", 80, rel, ln, snip,
                              f"The body matches {first[0]}:{first[1]} exactly (ignoring whitespace, comments and docstrings), which indicates copy-pasted logic.",
                              "Extract the shared logic into one function and reuse it.", KIND_STATIC))
        return res
