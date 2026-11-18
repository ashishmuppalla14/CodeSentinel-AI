"""Shared data models."""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Optional

SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITIES)}  # lower = more severe

CATEGORIES = ["Security", "AI Slop", "Completeness", "Code Quality"]

# Evidence types: static analysis = deterministic rule/tool match;
# heuristic = pattern-based suspicion that needs human review.
KIND_STATIC = "static-analysis"
KIND_HEURISTIC = "heuristic"


@dataclass
class Finding:
    title: str
    category: str
    severity: str
    confidence: int  # 0-100
    file: str
    line: Optional[int]
    evidence: str
    explanation: str
    remediation: str
    agent: str = ""
    rule_id: str = ""
    kind: str = KIND_HEURISTIC
    verified: bool = False  # True when lead agent re-checked evidence on disk
    ai_note: str = ""  # optional AI-assisted explanation (clearly separated from static evidence)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ScanResult:
    repo_name: str
    source: str
    languages: dict = field(default_factory=dict)
    files_scanned: int = 0
    files_skipped: int = 0
    findings: list = field(default_factory=list)
    agent_results: dict = field(default_factory=dict)  # agent -> {status, count, error, duration}
    health_score: int = 100
    quality_score: int = 100
    warnings: list = field(default_factory=list)
    started_at: str = ""
    duration_s: float = 0.0
    ai_enabled: bool = False

    def to_dict(self) -> dict:
        d = asdict(self)
        return d
