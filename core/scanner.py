"""Orchestrator: acquisition -> filtering -> language detection -> agents -> lead review -> scoring."""
from __future__ import annotations

import time
from datetime import datetime, timezone

from agents.completeness_agent import CompletenessAgent
from agents.lead_agent import review
from agents.quality_agent import QualityAgent
from agents.security_agent import SecurityAgent
from agents.slop_agent import SlopAgent
from core import ai_assist
from core.context import AnalysisContext
from core.language_detector import detect_languages
from core.models import ScanResult
from core.repository import RepositoryError, acquire
from core.scoring import health_score, quality_score
from utils.file_filter import collect_files

DEFAULT_SETTINGS = {
    "use_bandit": True, "use_semgrep": True, "semgrep_config": "", "tool_timeout": 120,
    "max_file_bytes": 500_000, "max_repo_bytes": 50_000_000, "max_files": 3000,
    "ai_provider": "none", "groq_api_key": "", "groq_model": "", "ollama_endpoint": "http://localhost:11434", "ollama_model": "",
    "keep_source": False,
}

AGENTS = [SecurityAgent(), SlopAgent(), CompletenessAgent(), QualityAgent()]


def scan_directory(root: str, repo_name: str, source: str, settings: dict | None = None, progress=None) -> ScanResult:
    """Scan an already-acquired directory. A failing agent is recorded and the scan continues."""
    cfg = {**DEFAULT_SETTINGS, **(settings or {})}
    prog = progress or (lambda p, m: None)
    t0 = time.time()
    res = ScanResult(repo_name=repo_name, source=source, started_at=datetime.now(timezone.utc).isoformat(timespec="seconds"))
    prog(0.05, "Filtering files and running safety checks")
    fs = collect_files(root, {k: cfg[k] for k in ("max_file_bytes", "max_repo_bytes", "max_files")})
    res.files_scanned, res.files_skipped, res.warnings = len(fs.files), fs.skipped, list(fs.warnings)
    prog(0.15, "Detecting languages")
    res.languages = detect_languages(fs.files)
    ctx = AnalysisContext(root=root, files=fs.files, languages=res.languages, settings=dict(cfg))
    raw = []
    for i, agent in enumerate(AGENTS):
        prog(0.2 + 0.15 * i, f"Running {agent.name}")
        a0 = time.time()
        try:
            found = agent.run(ctx)
            res.agent_results[agent.name] = {"status": "ok", "count": len(found), "error": "", "duration_s": round(time.time() - a0, 2),
                                             "description": agent.description}
            raw += found
        except Exception as e:  # isolate analyzer failures
            res.agent_results[agent.name] = {"status": "failed", "count": 0, "error": f"{type(e).__name__}: {e}"[:200],
                                             "duration_s": round(time.time() - a0, 2), "description": agent.description}
            res.warnings.append(f"{agent.name} failed and was skipped: {type(e).__name__}")
    res.warnings += [w for w in ctx.settings.get("_warnings", [])]
    prog(0.85, "Lead review: deduplicating, verifying evidence, prioritizing")
    lines = {f.rel: f.text.splitlines() for f in fs.files}
    try:
        res.findings = review(raw, lines)
        res.agent_results["Lead Review Agent"] = {"status": "ok", "count": len(res.findings), "error": "", "duration_s": 0.0,
                                                  "description": f"Merged {len(raw)} raw findings into {len(res.findings)} (dedupe, evidence check, severity, ranking)"}
    except Exception as e:
        res.findings = raw
        res.agent_results["Lead Review Agent"] = {"status": "failed", "count": len(raw), "error": f"{type(e).__name__}: {e}"[:200],
                                                  "duration_s": 0.0, "description": "Lead review failed; showing unreviewed findings"}
        res.warnings.append("Lead review failed; findings are not deduplicated")
    if cfg.get("ai_provider", "none") != "none":
        prog(0.92, "Optional AI-assisted explanations")
        n = ai_assist.annotate(res.findings, cfg, res.warnings)
        res.ai_enabled = n > 0
    res.health_score = health_score(res.findings, res.files_scanned)
    res.quality_score = quality_score(res.findings, res.files_scanned)
    res.duration_s = round(time.time() - t0, 2)
    prog(1.0, "Done")
    return res


def scan(source_type: str, value, settings: dict | None = None, progress=None) -> ScanResult:
    """Acquire a repository (github/zip/local), scan it, and always clean up temp files.
    Raises RepositoryError for user-facing acquisition problems."""
    cfg = {**DEFAULT_SETTINGS, **(settings or {})}
    if progress:
        progress(0.0, "Acquiring repository")
    with acquire(source_type, value, keep=cfg.get("keep_source", False)) as (root, name):
        return scan_directory(root, name, f"{source_type}:{value if source_type != 'zip' else name}", cfg, progress)


__all__ = ["scan", "scan_directory", "RepositoryError", "DEFAULT_SETTINGS"]
