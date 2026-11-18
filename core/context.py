"""Shared analysis context passed to every agent."""
from __future__ import annotations

import ast
import os
import re
from dataclasses import dataclass, field

from core.language_detector import language_of
from core.models import Finding
from utils.security_utils import redact

TEST_RE = re.compile(r"(^|/)(tests?|__tests__|spec|specs)(/|$)|(^|/)(test_[^/]*|[^/]*_test\.\w+|[^/]*\.(test|spec)\.\w+|[^/]*Test\.java)$", re.I)


def is_test_path(rel: str) -> bool:
    return bool(TEST_RE.search(rel))


@dataclass
class AnalysisContext:
    root: str
    files: list
    languages: dict
    settings: dict = field(default_factory=dict)
    _ast: dict = field(default_factory=dict)

    def lang(self, f) -> str | None:
        return language_of(f.rel)

    def py_files(self):
        return [f for f in self.files if f.rel.endswith(".py")]

    def tree(self, f):
        """Parsed Python AST (cached); None on syntax error."""
        if f.rel not in self._ast:
            try:
                self._ast[f.rel] = ast.parse(f.text)
            except (SyntaxError, ValueError, RecursionError):
                self._ast[f.rel] = None
        return self._ast[f.rel]


def snippet(text_or_lines, line: int | None, width: int = 220) -> str:
    """Redacted one-line evidence snippet for a 1-based line number."""
    lines = text_or_lines.splitlines() if isinstance(text_or_lines, str) else text_or_lines
    if not line or line < 1 or line > len(lines):
        return ""
    s = lines[line - 1].strip()
    if len(s) > width:
        s = s[:width] + "…"
    return redact(s)


def mk(agent: str, rule_id: str, title: str, category: str, severity: str, confidence: int,
       f_rel: str, line, evidence: str, explanation: str, remediation: str, kind: str) -> Finding:
    return Finding(title=title, category=category, severity=severity, confidence=confidence,
                   file=f_rel, line=line, evidence=evidence, explanation=explanation,
                   remediation=remediation, agent=agent, rule_id=rule_id, kind=kind)


def line_of(text: str, index: int) -> int:
    return text.count("\n", 0, index) + 1
