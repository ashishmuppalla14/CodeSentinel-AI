"""JSON / Markdown / SARIF report generation, always from actual scan results."""
from __future__ import annotations

import json
from collections import Counter

from core.models import CATEGORIES, SEVERITIES, ScanResult
from utils.security_utils import redact

TOOL_NAME = "CodeSentinel AI"
TOOL_VERSION = "1.0.0"
SARIF_LEVEL = {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning", "LOW": "note", "INFO": "note"}


def summarize(result: ScanResult) -> dict:
    sev = Counter(f.severity for f in result.findings)
    cat = {c: Counter(f.severity for f in result.findings if f.category == c) for c in CATEGORIES}
    return {
        "total": len(result.findings),
        "by_severity": {s: sev.get(s, 0) for s in SEVERITIES},
        "by_category": {c: sum(v.values()) for c, v in cat.items()},
        "by_category_severity": {c: {s: v.get(s, 0) for s in SEVERITIES if v.get(s, 0)} for c, v in cat.items()},
        "static_analysis": sum(1 for f in result.findings if f.kind == "static-analysis"),
        "heuristic": sum(1 for f in result.findings if f.kind != "static-analysis"),
    }


def to_json(result: ScanResult) -> str:
    d = result.to_dict()
    d["summary"] = summarize(result)
    d["tool"] = {"name": TOOL_NAME, "version": TOOL_VERSION}
    for f in d["findings"]:
        f["evidence"] = redact(f["evidence"])
    return json.dumps(d, indent=2, ensure_ascii=False)


def to_markdown(result: ScanResult) -> str:
    s = summarize(result)
    sec = s["by_category_severity"]["Security"]
    L = [f"# {TOOL_NAME} Report", "",
         f"**Repository:** {result.repo_name}  ", f"**Scanned:** {result.started_at} ({result.duration_s}s)  ",
         f"**Files scanned:** {result.files_scanned} (skipped {result.files_skipped})  ",
         f"**Languages:** {', '.join(f'{k} ({v})' for k, v in result.languages.items()) or 'none detected'}  ", "",
         f"## Repository Health Score: {result.health_score}/100", f"Code quality score: {result.quality_score}/100", "",
         "## Summary", "", "**Security Findings:**"]
    L += [f"- {n} {sv}" for sv, n in sec.items()] or ["- none"]
    L += ["", f"**Code Quality:** {s['by_category']['Code Quality']} issues",
          f"**Completeness:** {s['by_category']['Completeness']} unfinished implementations",
          f"**AI Slop Indicators:** {s['by_category']['AI Slop']} suspicious patterns", "",
          f"Evidence types: {s['static_analysis']} from static analysis (Bandit/Semgrep/AST/markers), "
          f"{s['heuristic']} heuristic (pattern-based, need human review). Findings are suspected, not proven exploitable.", ""]
    if result.warnings:
        L += ["## Warnings", ""] + [f"- {w}" for w in result.warnings[:20]] + [""]
    L += ["## Agents", "", "| Agent | Status | Findings |", "|---|---|---|"]
    for n, r in result.agent_results.items():
        L.append(f"| {n} | {r['status']} | {r['count']} |")
    L += ["", "## Findings", ""]
    if not result.findings:
        L.append("No findings.")
    for i, f in enumerate(result.findings, 1):
        loc = f"{f.file}:{f.line}" if f.line else f.file
        label = "Static analysis" if f.kind == "static-analysis" else "Heuristic"
        L += [f"### {i}. {f.title}", "", f"- **Severity:** {f.severity}", f"- **Category:** {f.category}",
              f"- **Confidence:** {f.confidence}% ({label}{'' if f.verified else ', evidence not re-verified'})",
              f"- **Location:** `{loc}`", f"- **Detected by:** {f.agent} (`{f.rule_id}`)", "",
              "**Evidence:**", "```", redact(f.evidence) or "(none)", "```", "",
              f"**Explanation:** {f.explanation}", "", f"**Suggested fix:** {f.remediation}", ""]
        if f.ai_note:
            L += [f"**AI-assisted note (unverified):** {f.ai_note}", ""]
    return "\n".join(L)


def to_sarif(result: ScanResult) -> str:
    rules, seen = [], set()
    results = []
    for f in result.findings:
        rid = f.rule_id or f.title
        if rid not in seen:
            seen.add(rid)
            rules.append({"id": rid, "name": f.title[:80], "shortDescription": {"text": f.title},
                          "fullDescription": {"text": f.explanation}, "help": {"text": f.remediation},
                          "properties": {"category": f.category, "tags": [f.category, f.kind]}})
        r = {"ruleId": rid, "level": SARIF_LEVEL.get(f.severity, "note"),
             "message": {"text": f"{f.title}. {f.explanation} Fix: {f.remediation}"},
             "properties": {"severity": f.severity, "confidence": f.confidence, "kind": f.kind, "category": f.category,
                            "agent": f.agent, "evidence": redact(f.evidence), "verified": f.verified}}
        if f.file and f.file != "(repository)":
            loc = {"physicalLocation": {"artifactLocation": {"uri": f.file}}}
            if f.line:
                loc["physicalLocation"]["region"] = {"startLine": int(f.line)}
            r["locations"] = [loc]
        results.append(r)
    doc = {"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
           "runs": [{"tool": {"driver": {"name": TOOL_NAME, "version": TOOL_VERSION,
                                         "informationUri": "https://github.com/your-username/CodeSentinel-AI", "rules": rules}},
                     "results": results}]}
    return json.dumps(doc, indent=2)
