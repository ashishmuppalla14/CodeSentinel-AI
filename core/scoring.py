"""Repository health scoring (deterministic, size-normalized)."""
from __future__ import annotations

import math

WEIGHTS = {"CRITICAL": 15.0, "HIGH": 8.0, "MEDIUM": 3.0, "LOW": 1.0, "INFO": 0.2}


def _score(findings, n_files: int) -> int:
    raw = sum(WEIGHTS.get(f.severity, 0) * (f.confidence / 100.0) for f in findings)
    k = 40 + 4 * math.sqrt(max(n_files, 1))
    return max(0, min(100, round(100 / (1 + raw / k))))


def health_score(findings: list, n_files: int) -> int:
    """Overall repository health 0-100 (100 = no findings)."""
    return _score(findings, n_files)


def quality_score(findings: list, n_files: int) -> int:
    """Maintainability score: ignores Security findings."""
    return _score([f for f in findings if f.category != "Security"], n_files)


def security_score(findings: list, n_files: int) -> int:
    return _score([f for f in findings if f.category == "Security"], n_files)
