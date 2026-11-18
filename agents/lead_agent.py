"""Agent 5: Lead Review. Deduplicate, verify evidence, classify severity, prioritize."""
from __future__ import annotations

import re

from core.models import KIND_STATIC, SEVERITIES, SEVERITY_RANK, Finding
from utils.security_utils import redact

NAME = "Lead Review Agent"
CRITICAL_FAMILIES = {"sqli", "cmd", "secret", "deser", "file"}
# rules whose evidence is a file metric rather than a literal source line
NO_LINE_EVIDENCE = ("quality.big-file", "empty.", "missing.", "slop.comment-heavy", "integration.")


def _family(f: Finding) -> str:
    """Grouping key for dedupe. Security rule families (sqli, cmd, ...) merge across detectors;
    every other rule stays distinct so unrelated issues on one line are not collapsed."""
    rid = f.rule_id or f.title
    head = rid.split(".")[0]
    return head if f.category == "Security" and head in CRITICAL_FAMILIES | {"xss"} else rid


def dedupe(findings: list) -> list:
    """Collapse findings describing the same issue (same file+line+rule family).
    The best one is kept (static-analysis > heuristic, then confidence, then severity);
    independent agreement from a second detector raises confidence."""
    groups: dict = {}
    for f in findings:
        if f.line is None:
            key = (f.file, None, f.category, f.rule_id or f.title)
        else:
            key = (f.file, f.line, f.category, _family(f))
        groups.setdefault(key, []).append(f)
    out = []
    for grp in groups.values():
        grp.sort(key=lambda x: (x.kind != KIND_STATIC, -x.confidence, SEVERITY_RANK.get(x.severity, 9)))
        best = grp[0]
        detectors = {g.agent for g in grp}
        if len(grp) > 1 and len(detectors) > 1:
            best.confidence = min(99, best.confidence + 5)
            best.severity = min((g.severity for g in grp), key=lambda x: SEVERITY_RANK.get(x, 9))
            best.explanation += f" (Also flagged by: {', '.join(sorted(detectors - {best.agent}))}.)"
        out.append(best)
    return out


def classify_severity(f: Finding) -> str:
    """Final severity: escalate high-confidence critical-family security issues,
    downgrade low-confidence HIGH/CRITICAL findings, never escalate test-only code."""
    sev = f.severity if f.severity in SEVERITY_RANK else "INFO"
    in_test = bool(re.search(r"(^|/)(tests?|__tests__|spec)(/|$)|test_[^/]*$|_test\.", f.file))
    if f.category == "Security" and sev == "HIGH" and f.confidence >= 85 and _family(f) in CRITICAL_FAMILIES and not in_test:
        return "CRITICAL"
    if f.confidence < 50 and sev in ("CRITICAL", "HIGH"):
        return SEVERITIES[SEVERITY_RANK[sev] + 1]
    return sev


def verify(f: Finding, file_lines: dict) -> Finding:
    """Re-check that the cited evidence exists at file:line in the scanned content."""
    if f.file == "(repository)" or f.line is None or (f.rule_id or "").startswith(NO_LINE_EVIDENCE):
        f.verified = True
        return f
    lines = file_lines.get(f.file)
    if not lines or not (1 <= f.line <= len(lines)):
        f.verified = False
        f.confidence = max(10, f.confidence - 30)
        return f
    actual = " ".join(lines[f.line - 1].split())
    ev = f.evidence.replace("…", "")
    pieces = [" ".join(p.split()) for p in re.split(r"\*{3}REDACTED\*{3}", ev) if p.strip()]
    if pieces and all(p in actual for p in pieces):
        f.verified = True
    else:
        f.verified = False
        f.confidence = max(10, f.confidence - 20)
    return f


def review(findings: list, file_lines: dict) -> list:
    """Full lead-review pipeline: dedupe -> verify -> classify -> redact -> prioritize."""
    merged = dedupe(findings)
    for f in merged:
        verify(f, file_lines)
        f.severity = classify_severity(f)
        f.evidence = redact(f.evidence)
        f.title, f.explanation, f.remediation = redact(f.title), redact(f.explanation), redact(f.remediation)
    merged.sort(key=lambda x: (SEVERITY_RANK.get(x.severity, 9), -x.confidence, x.file, x.line or 0))
    return merged
