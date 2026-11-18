# CodeSentinel AI 🛡️

### Privacy-First Multi-Agent Code Security & Quality Analyzer

CodeSentinel AI is an architecture-agnostic code analysis platform that uses five specialized agents to identify security vulnerabilities, AI-generated code slop, incomplete implementations and code quality issues.

## 🚀 Live Demo

https://codesentinel-ai-ashish.streamlit.app/

## ✨ Key Features

- **Security Analysis:** Detects hardcoded secrets, unsafe operations and potential vulnerabilities.
- **AI Slop Detection:** Identifies redundant code patterns, unnecessary abstractions and suspicious coding practices.
- **Completeness Analysis:** Finds TODOs, unfinished functions and incomplete implementations.
- **Code Quality Analysis:** Detects duplication, complexity and maintainability issues.
- **Lead Review Agent:** Consolidates findings and prioritizes issues.
- **Multiple Reports:** Export findings in JSON, Markdown and SARIF formats.

## 🤖 Multi-Agent Architecture

1. Security Agent
2. AI Slop Detector
3. Completeness Agent
4. Code Quality Agent
5. Lead Review Agent

## 🛠️ Technology Stack

- Python
- Streamlit
- Bandit
- Python AST
- Static analysis and pattern-based detection
- Optional Groq/Ollama integration

## 🔒 Privacy First

- Does not execute scanned repository code.
- Supports deterministic analysis without mandatory API keys.
- Provides optional AI assistance.
- Includes safeguards for repository and ZIP processing.

## 💻 Run Locally

Clone the repository:

```bash
git clone https://github.com/ashishmuppalla14/CodeSentinel-AI.git
cd CodeSentinel-AI
```

Create a virtual environment:

```bash
python -m venv .venv
```

Activate it on Windows:

```powershell
.venv\Scripts\activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

Run the application:

```bash
streamlit run app.py
```

## 📊 Output Formats

- JSON
- Markdown
- SARIF 2.1.0

## 🎯 Objective

To provide developers with an accessible, privacy-conscious way to identify security risks, coding gaps and maintainability issues across different software repositories.

## ⚠️ Limitations

The tool uses static analysis and heuristic detection. Findings should be reviewed by developers and are not a substitute for comprehensive security audits or dependency vulnerability scanning.

## 👨‍💻 Developer

Ashish Muppalla

GitHub: https://github.com/ashishmuppalla14

---
CodeSentinel AI – Secure. Inspect. Improve.
