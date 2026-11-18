# Deployment Guide

## 1. Run locally

```bash
python -m venv .venv && source .venv/bin/activate    # Windows: .venv\Scripts\activate
pip install -r requirements.txt
streamlit run app.py                                 # opens http://localhost:8501
```

Requires Python 3.11+. No database, Docker, Ollama or API key needed.

## 2. Push to GitHub

1. Create an empty repository named `CodeSentinel-AI` on github.com (no README/license; they already exist).
2. From the project folder:

```bash
git init
git add .
git commit -m "Initial commit: CodeSentinel AI"
git branch -M main
git remote add origin https://github.com/<your-username>/CodeSentinel-AI.git
git push -u origin main
```

`.gitignore` already excludes `.env`, caches and `.streamlit/secrets.toml`. Never commit real keys. (`sample_project/` contains only fake demo credentials.)

## 3. Deploy on Streamlit Community Cloud (free)

1. Go to <https://share.streamlit.io> and sign in with GitHub.
2. Click **Create app** > **Deploy a public app from GitHub**.
3. Choose repository `<your-username>/CodeSentinel-AI`, branch `main`, main file path `app.py`.
4. Under **Advanced settings**, pick Python **3.11** (or newer).
5. (Optional) In **Secrets**, add `GROQ_API_KEY = "gsk_..."` to pre-enable Groq explanations. Skip it to stay fully local.
6. Click **Deploy**. The first build installs `requirements.txt` (Streamlit + Bandit).

Do **not** set `CODESENTINEL_ALLOW_LOCAL=1` on a public deployment; it would let visitors scan the server's filesystem.

## Deployment limitations (honest notes)

- **Ollama is not available** on Streamlit Community Cloud (no local model server). Use deterministic mode or Groq there; Ollama works when you run the app on your own machine.
- **Semgrep is not in `requirements.txt`** because it is a heavy install that is unreliable on the free tier. Add `semgrep` to requirements yourself if you want it, then set a rules config in Settings.
- Free-tier apps have limited memory and sleep when idle. Very large repositories may hit the built-in limits (50 MB, 3000 files) and are partially scanned with a warning.
- GitHub downloads are unauthenticated and can be rate limited (HTTP 403/429); the app shows a clear message and you can upload a ZIP instead. Private repositories are not supported.
- Results and settings live in session memory only and disappear when the session ends or the app restarts.
- Groq is a cloud service: only finding titles and single redacted evidence lines are sent, never whole files or secrets. If that is unacceptable for your data, leave AI off.

## Troubleshooting

| Symptom | Fix |
|---|---|
| `ModuleNotFoundError: core` | Run `streamlit run app.py` from the project root. |
| "Bandit not installed" warning | `pip install bandit` (it is in requirements.txt). |
| GitHub scan fails with rate limit | Wait, or download the repo as ZIP and upload it. |
| `use_container_width`/`width` errors | Upgrade Streamlit: `pip install -U "streamlit>=1.50"`. |
