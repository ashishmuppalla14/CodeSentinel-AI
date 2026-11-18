"""CodeSentinel AI - Secure. Inspect. Improve.  (Streamlit entry point: streamlit run app.py)"""
from __future__ import annotations

import html
import os
import tempfile
from collections import Counter

import streamlit as st

from core.models import CATEGORIES, SEVERITIES
from core.report_generator import summarize, to_json, to_markdown, to_sarif
from core.repository import RepositoryError
from core.scanner import DEFAULT_SETTINGS, scan

st.set_page_config(page_title="CodeSentinel AI", page_icon="🛡️", layout="wide")

SEV_COLOR = {"CRITICAL": "#ff4d6d", "HIGH": "#ff8c42", "MEDIUM": "#f5c542", "LOW": "#4cc9f0", "INFO": "#8d99ae"}
AGENT_GROUPS = {
    "Security Agent": {"Security Agent", "Bandit", "Semgrep"},
    "AI Slop Detector": {"AI Slop Detector"},
    "Completeness Agent": {"Completeness Agent"},
    "Code Quality Agent": {"Code Quality Agent"},
    "Lead Review Agent": set(),
}
ALLOW_LOCAL = os.environ.get("CODESENTINEL_ALLOW_LOCAL", "0") == "1"

CSS = """
<style>
.block-container{padding-top:2rem;max-width:1250px}
.cs-hero h1{margin:0;font-size:2rem;letter-spacing:.3px}
.cs-hero p{margin:.1rem 0 1.2rem;color:#8b98a9;font-size:1.02rem}
.cs-card{background:#161b26;border:1px solid #232b3b;border-radius:12px;padding:16px 18px;height:100%}
.cs-card .l{color:#8b98a9;font-size:.78rem;text-transform:uppercase;letter-spacing:.08em}
.cs-card .v{font-size:1.9rem;font-weight:700;line-height:1.25}
.cs-card .s{color:#8b98a9;font-size:.8rem}
.cs-badge{display:inline-block;padding:2px 9px;border-radius:999px;font-size:.72rem;font-weight:700;color:#0b0f17}
.cs-tag{display:inline-block;padding:1px 8px;border-radius:6px;font-size:.72rem;border:1px solid #2d3750;color:#a8b3c7;margin-left:6px}
.cs-muted{color:#8b98a9;font-size:.85rem}
</style>
"""
st.markdown(CSS, unsafe_allow_html=True)


# ---------- helpers ----------
def card(label: str, value, sub: str = "", color: str = "#e6edf7") -> str:
    return (f'<div class="cs-card"><div class="l">{html.escape(label)}</div>'
            f'<div class="v" style="color:{color}">{html.escape(str(value))}</div><div class="s">{html.escape(sub)}</div></div>')


def badge(sev: str) -> str:
    return f'<span class="cs-badge" style="background:{SEV_COLOR.get(sev, "#8d99ae")}">{html.escape(sev)}</span>'


def score_color(s: int) -> str:
    return "#3ddc97" if s >= 75 else "#f5c542" if s >= 50 else "#ff4d6d"


def init_state():
    ss = st.session_state
    ss.setdefault("history", [])  # list of ScanResult (in memory only, cleared when the session ends)
    ss.setdefault("current", None)
    ss.setdefault("settings", {"ai_provider": "none", "groq_api_key": "", "groq_model": "", "ollama_endpoint": "http://localhost:11434",
                               "ollama_model": "", "use_bandit": True, "use_semgrep": True, "semgrep_config": "",
                               "max_file_bytes": DEFAULT_SETTINGS["max_file_bytes"], "max_repo_bytes": DEFAULT_SETTINGS["max_repo_bytes"],
                               "keep_source": False})
    if not ss.settings["groq_api_key"]:
        env = os.environ.get("GROQ_API_KEY", "")
        if not env:
            try:
                env = st.secrets.get("GROQ_API_KEY", "")
            except Exception:
                env = ""
        ss.settings["groq_api_key"] = env


def need_scan() -> bool:
    if st.session_state.current is None:
        st.info("No scan yet. Open **Scan Repository** to analyze a project, or scan the bundled `sample_project` to see results.")
        return False
    return True


# ---------- pages ----------
def page_dashboard():
    hist = st.session_state.history
    cur = st.session_state.current
    all_f = [f for r in hist for f in r.findings]
    crit = sum(1 for f in all_f if f.severity == "CRITICAL")
    high = sum(1 for f in all_f if f.severity == "HIGH")
    c = st.columns(6)
    vals = [("Repositories scanned", len(hist), "this session", "#e6edf7"), ("Total findings", len(all_f), "all scans", "#e6edf7"),
            ("Critical", crit, "vulnerabilities & flaws", SEV_COLOR["CRITICAL"] if crit else "#e6edf7"),
            ("High risk", high, "findings", SEV_COLOR["HIGH"] if high else "#e6edf7"),
            ("Code quality score", f"{cur.quality_score}/100" if cur else "-", "latest scan", score_color(cur.quality_score) if cur else "#8d99ae"),
            ("Repository health", f"{cur.health_score}/100" if cur else "-", "latest scan", score_color(cur.health_score) if cur else "#8d99ae")]
    for col, v in zip(c, vals):
        col.markdown(card(*v), unsafe_allow_html=True)
    st.write("")
    left, right = st.columns([3, 2])
    with left:
        st.subheader("Recent scans")
        if not hist:
            st.caption("No scans yet. Results are kept in memory for this browser session only.")
        else:
            rows = [{"Repository": r.repo_name, "Health": r.health_score, "Quality": r.quality_score, "Findings": len(r.findings),
                     "Critical": sum(f.severity == "CRITICAL" for f in r.findings), "High": sum(f.severity == "HIGH" for f in r.findings),
                     "Files": r.files_scanned, "Time (s)": r.duration_s, "Scanned (UTC)": r.started_at.replace("T", " ")} for r in reversed(hist[-10:])]
            st.dataframe(rows, width="stretch", hide_index=True)
    with right:
        st.subheader("Severity breakdown (latest)")
        if cur:
            sev = summarize(cur)["by_severity"]
            st.bar_chart({"count": sev}, color="#4cc9f0")
        else:
            st.caption("Run a scan to see the breakdown.")


def page_scan():
    st.subheader("Scan a repository")
    st.caption("Scanning is static: repository code is only read as text and never executed. Temporary files are deleted after analysis.")
    options = ["GitHub URL", "Upload ZIP"] + (["Local path"] if ALLOW_LOCAL else [])
    mode = st.radio("Source", options, horizontal=True)
    url = zip_file = path = None
    if mode == "GitHub URL":
        url = st.text_input("Public GitHub repository URL", placeholder="https://github.com/owner/repo")
    elif mode == "Upload ZIP":
        zip_file = st.file_uploader("Repository ZIP (max 50 MB)", type=["zip"])
    else:
        path = st.text_input("Local directory path")
    use_sample = st.checkbox("Or scan the bundled demo project (intentionally vulnerable, synthetic)")
    if st.button("Start scan", type="primary"):
        bar, status = st.progress(0.0), st.empty()

        def cb(p, m):
            bar.progress(min(max(p, 0.0), 1.0))
            status.info(f"⏳ {m}")
        try:
            if use_sample:
                sample = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sample_project")
                result = scan("local", sample, st.session_state.settings, cb)
            elif mode == "GitHub URL":
                if not url:
                    st.warning("Enter a GitHub URL first.")
                    return
                result = scan("github", url.strip(), st.session_state.settings, cb)
            elif mode == "Upload ZIP":
                if zip_file is None:
                    st.warning("Upload a ZIP file first.")
                    return
                with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as tf:
                    tf.write(zip_file.getvalue())
                    tmp = tf.name
                try:
                    result = scan("zip", tmp, st.session_state.settings, cb)
                    result.repo_name = os.path.splitext(zip_file.name)[0]
                finally:
                    os.unlink(tmp)
            else:
                result = scan("local", path, st.session_state.settings, cb)
        except RepositoryError as e:
            bar.empty()
            status.error(f"Could not scan: {e}")
            return
        except Exception as e:  # never show a traceback with possible secrets
            bar.empty()
            status.error(f"Unexpected error: {type(e).__name__}. The scan was aborted and temporary files were removed.")
            return
        st.session_state.current = result
        st.session_state.history.append(result)
        status.success(f"✅ Scan complete in {result.duration_s}s")
    cur = st.session_state.current
    if cur:
        st.divider()
        st.markdown(f"**Latest result: `{cur.repo_name}`** - {cur.files_scanned} files scanned, {len(cur.findings)} findings, health **{cur.health_score}/100**")
        c1, c2 = st.columns(2)
        with c1:
            st.markdown("**Detected languages**")
            st.dataframe([{"Language": k, "Files": v} for k, v in cur.languages.items()] or [{"Language": "none detected", "Files": 0}],
                         hide_index=True, width="stretch")
        with c2:
            st.markdown("**Analysis status**")
            st.dataframe([{"Agent": n, "Status": r["status"], "Findings": r["count"], "Seconds": r["duration_s"]} for n, r in cur.agent_results.items()],
                         hide_index=True, width="stretch")
        for w in cur.warnings[:10]:
            st.warning(w)


def page_findings():
    if not need_scan():
        return
    r = st.session_state.current
    st.subheader(f"Findings - {r.repo_name}")
    c1, c2, c3 = st.columns(3)
    sev = c1.multiselect("Severity", SEVERITIES, default=SEVERITIES)
    cat = c2.multiselect("Category", CATEGORIES, default=CATEGORIES)
    kind = c3.selectbox("Evidence type", ["All", "Static analysis only", "Heuristic only"])
    q = st.text_input("Search (title, file, rule)", "")
    items = [f for f in r.findings if f.severity in sev and f.category in cat
             and (kind == "All" or (kind.startswith("Static") == (f.kind == "static-analysis")))
             and (not q or q.lower() in (f.title + f.file + f.rule_id).lower())]
    st.caption(f"{len(items)} of {len(r.findings)} findings shown. **Static analysis** = Bandit/Semgrep/AST/marker match. "
               "**Heuristic** = pattern-based suspicion that needs human review. Nothing here is a proven exploit.")
    for f in items[:200]:
        loc = f"{f.file}:{f.line}" if f.line else f.file
        label = "static analysis" if f.kind == "static-analysis" else "heuristic"
        with st.expander(f"{f.severity} · {f.title} · {loc}"):
            st.markdown(f"{badge(f.severity)} <span class='cs-tag'>{html.escape(f.category)}</span>"
                        f"<span class='cs-tag'>{label}</span><span class='cs-tag'>confidence {f.confidence}%</span>"
                        f"<span class='cs-tag'>{'evidence verified' if f.verified else 'evidence not re-verified'}</span>", unsafe_allow_html=True)
            st.markdown(f"**File:** `{loc}`  \n**Detected by:** {f.agent} (`{f.rule_id}`)")
            st.markdown("**Evidence**")
            st.code(f.evidence or "(none)", language=None)
            st.markdown(f"**Explanation:** {f.explanation}")
            st.markdown(f"**Suggested fix:** {f.remediation}")
            if f.ai_note:
                st.info(f"AI-assisted note (generated, unverified): {f.ai_note}")
    if len(items) > 200:
        st.caption("Showing the first 200. Download a report for the full list.")


def page_agents():
    if not need_scan():
        return
    r = st.session_state.current
    st.subheader("Agent insights")
    for name, members in AGENT_GROUPS.items():
        info = r.agent_results.get(name, {"status": "not run", "count": 0, "error": "", "duration_s": 0, "description": ""})
        mine = [f for f in r.findings if f.agent in members]
        ok = info["status"] == "ok"
        with st.container(border=True):
            a, b = st.columns([4, 1])
            a.markdown(f"**{name}**  \n<span class='cs-muted'>{html.escape(info.get('description', ''))}</span>", unsafe_allow_html=True)
            b.markdown(f"{'🟢' if ok else '🔴'} {info['status']} · {info['count']} · {info['duration_s']}s")
            if info.get("error"):
                st.error(info["error"])
            if name != "Lead Review Agent" and mine:
                sev = Counter(f.severity for f in mine)
                st.markdown(" ".join(f"{badge(s)} {sev[s]}" for s in SEVERITIES if sev.get(s)), unsafe_allow_html=True)
                for f in mine[:3]:
                    st.caption(f"{f.severity} · {f.title} · {f.file}:{f.line or '-'}")
            elif name == "Lead Review Agent":
                s = summarize(r)
                st.caption(f"Health {r.health_score}/100 · {s['static_analysis']} static-analysis findings · {s['heuristic']} heuristic findings")
    s = summarize(r)
    st.markdown("**By category**")
    st.bar_chart(s["by_category"], color="#4cc9f0")


def page_reports():
    if not need_scan():
        return
    r = st.session_state.current
    st.subheader("Reports")
    st.caption("Generated from the latest actual scan. Evidence is redacted and API keys are never included.")
    base = "".join(ch if ch.isalnum() or ch in "-_" else "_" for ch in r.repo_name) or "report"
    md = to_markdown(r)
    c1, c2, c3 = st.columns(3)
    c1.download_button("⬇ JSON report", to_json(r), f"{base}-codesentinel.json", "application/json", width="stretch")
    c2.download_button("⬇ Markdown report", md, f"{base}-codesentinel.md", "text/markdown", width="stretch")
    c3.download_button("⬇ SARIF report", to_sarif(r), f"{base}-codesentinel.sarif", "application/sarif+json", width="stretch")
    with st.expander("Preview Markdown report", expanded=True):
        st.markdown(md)


def page_settings():
    st.subheader("Settings")
    s = st.session_state.settings
    st.markdown("**AI assistance (optional)** - the scanner is fully functional without it.")
    s["ai_provider"] = st.selectbox("Provider", ["none", "ollama", "groq"], index=["none", "ollama", "groq"].index(s["ai_provider"]),
                                    help="'none' keeps everything local and deterministic.")
    if s["ai_provider"] == "groq":
        st.warning("Groq is a cloud service. Only finding titles and single redacted evidence lines are sent, never whole files, secrets or .env content.")
        new = st.text_input("Groq API key", type="password", placeholder="Configured" if s["groq_api_key"] else "gsk_...",
                            help="Kept in this session's memory only. Never displayed, logged or written to reports.")
        if new:
            s["groq_api_key"] = new
        st.caption("Key status: " + ("configured ✅" if s["groq_api_key"] else "not set"))
        s["groq_model"] = st.text_input("Model (optional)", s["groq_model"], placeholder="llama-3.1-8b-instant")
    elif s["ai_provider"] == "ollama":
        s["ollama_endpoint"] = st.text_input("Ollama endpoint", s["ollama_endpoint"])
        s["ollama_model"] = st.text_input("Model (optional)", s["ollama_model"], placeholder="llama3.2")
        st.caption("Ollama must be running where this app runs. It is not available on Streamlit Community Cloud.")
    st.divider()
    st.markdown("**Local analysis**")
    s["use_bandit"] = st.checkbox("Run Bandit on Python code", s["use_bandit"])
    s["use_semgrep"] = st.checkbox("Run Semgrep if installed", s["use_semgrep"])
    s["semgrep_config"] = st.text_input("Semgrep rules (path or registry pack, e.g. p/security-audit)", s["semgrep_config"],
                                        help="Empty = Semgrep skipped. Registry packs download rules only; your code is not uploaded.")
    s["max_file_bytes"] = st.number_input("Max file size (bytes)", 10_000, 5_000_000, int(s["max_file_bytes"]), 10_000)
    s["max_repo_bytes"] = st.number_input("Max repository size (bytes)", 1_000_000, 200_000_000, int(s["max_repo_bytes"]), 1_000_000)
    s["keep_source"] = st.checkbox("Retain downloaded source after analysis (off = delete immediately)", s["keep_source"])
    st.caption("Settings live in memory for this session and are not saved to disk.")


def main():
    init_state()
    st.markdown('<div class="cs-hero"><h1>🛡️ CodeSentinel AI</h1><p>Secure. Inspect. Improve.</p></div>', unsafe_allow_html=True)
    pages = {"Dashboard": page_dashboard, "Scan Repository": page_scan, "Findings": page_findings,
             "Agent Insights": page_agents, "Reports": page_reports, "Settings": page_settings}
    with st.sidebar:
        st.markdown("### Navigation")
        choice = st.radio("Go to", list(pages), label_visibility="collapsed")
        st.divider()
        st.caption("Privacy-first: local static analysis, no mandatory API keys, no code execution.")
    pages[choice]()


main()
