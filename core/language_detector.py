"""Extension-based language detection."""
from __future__ import annotations

from collections import Counter

EXT_LANG = {
    ".py": "Python", ".js": "JavaScript", ".jsx": "JavaScript", ".mjs": "JavaScript",
    ".ts": "TypeScript", ".tsx": "TypeScript", ".java": "Java", ".c": "C", ".h": "C",
    ".cpp": "C++", ".cc": "C++", ".cxx": "C++", ".hpp": "C++", ".go": "Go", ".php": "PHP",
    ".rb": "Ruby", ".rs": "Rust", ".cs": "C#", ".kt": "Kotlin", ".swift": "Swift",
    ".sh": "Shell", ".html": "HTML", ".css": "CSS", ".sql": "SQL",
}
CODE_LANGS = {v for k, v in EXT_LANG.items() if v not in ("HTML", "CSS")}


def language_of(path: str) -> str | None:
    import os
    return EXT_LANG.get(os.path.splitext(path.lower())[1])


def detect_languages(files) -> dict:
    """Return {language: file_count}, most common first."""
    c = Counter()
    for f in files:
        lang = language_of(f.rel)
        if lang:
            c[lang] += 1
    return dict(c.most_common())
