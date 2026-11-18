"""Optional AI-assisted explanations (Groq cloud or Ollama local). Off by default.

Privacy rules enforced here:
- Only the finding title, rule, a redacted single-line evidence snippet and the static explanation are sent. Never whole files.
- Findings in sensitive files and secret findings are never sent.
- API keys are never logged, stored in reports or returned in errors.
"""
from __future__ import annotations

import json
import urllib.error
import urllib.request

from utils.file_filter import is_sensitive
from utils.security_utils import redact

GROQ_URL = "https://api.groq.com/openai/v1/chat/completions"
DEFAULT_GROQ_MODEL = "llama-3.1-8b-instant"
DEFAULT_OLLAMA_MODEL = "llama3.2"


def _prompt(f) -> str:
    return (
        "You are a code security reviewer. In at most 3 short sentences, explain why this static-analysis "
        "finding matters and give a concrete fix. Do not claim the issue is confirmed exploitable.\n"
        f"Finding: {f.title}\nRule: {f.rule_id}\nFile: {f.file}:{f.line}\n"
        f"Evidence (one line): {redact(f.evidence)}\nStatic explanation: {f.explanation[:300]}"
    )


def _post(url: str, payload: dict, headers: dict, timeout: int = 40) -> dict:
    req = urllib.request.Request(url, data=json.dumps(payload).encode(), headers={"Content-Type": "application/json", **headers})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode())


def ask(provider: str, prompt: str, settings: dict) -> str:
    if provider == "groq":
        key = settings.get("groq_api_key", "")
        if not key:
            raise RuntimeError("Groq selected but no API key set")
        data = _post(GROQ_URL, {"model": settings.get("groq_model") or DEFAULT_GROQ_MODEL, "temperature": 0.2, "max_tokens": 220,
                                "messages": [{"role": "user", "content": prompt}]},
                     {"Authorization": f"Bearer {key}", "User-Agent": "CodeSentinel-AI"})
        return data["choices"][0]["message"]["content"].strip()
    if provider == "ollama":
        ep = (settings.get("ollama_endpoint") or "http://localhost:11434").rstrip("/")
        data = _post(f"{ep}/api/generate", {"model": settings.get("ollama_model") or DEFAULT_OLLAMA_MODEL, "prompt": prompt, "stream": False}, {})
        return data.get("response", "").strip()
    raise RuntimeError(f"Unknown AI provider: {provider}")


def annotate(findings: list, settings: dict, warnings: list, limit: int = 8) -> int:
    """Add ai_note to the top findings. Returns number annotated. Never raises."""
    provider = settings.get("ai_provider", "none")
    if provider not in ("groq", "ollama"):
        return 0
    n = 0
    for f in findings:
        if n >= limit:
            break
        if f.severity not in ("CRITICAL", "HIGH", "MEDIUM") or f.rule_id.startswith("secret") or is_sensitive(f.file):
            continue
        try:
            f.ai_note = ask(provider, _prompt(f), settings)
            n += 1
        except urllib.error.HTTPError as e:
            warnings.append(f"AI assistance stopped: provider returned HTTP {e.code}")
            break
        except Exception as e:
            msg = redact(str(e))
            for k in ("groq_api_key",):
                if settings.get(k):
                    msg = msg.replace(settings[k], "***")
            warnings.append(f"AI assistance stopped: {type(e).__name__}: {msg[:120]}")
            break
    return n
