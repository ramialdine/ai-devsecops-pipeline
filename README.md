# ai-devsecops-pipeline

A GitHub Actions-powered DevSecOps pipeline that automatically runs a full AppSec scan suite on every push and pull request, then uses the Gemini API to triage findings and post an AI-generated summary as a PR comment.

## Quick Start (for first-time users)

1. Fork or copy this repository
2. In your repo, add `GEMINI_API_KEY`:
   - **Settings → Secrets and variables → Actions → New repository secret**
3. Push a branch and open a PR
4. Go to **Actions** and open the `Security Scan Pipeline` run
5. Review:
   - workflow logs/artifacts
   - PR security summary comment (on PR runs)

If you want to run everything manually, use:
- **Actions → Security Scan Pipeline → Run workflow → force_full_scan=true**

## Architecture

```
PR opened/updated
       │
       ▼
┌─────────────────────────────────────────────┐
│         GitHub Actions Workflow              │
│                                              │
│  ┌──────────┐ ┌───────────┐ ┌────────────┐  │
│  │ Semgrep  │ │TruffleHog │ │ pip-audit  │  │
│  │  (SAST)  │ │ (secrets) │ │   (SCA)    │  │
│  └────┬─────┘ └─────┬─────┘ └─────┬──────┘  │
│       │              │             │         │
│       │    ┌─────────┐             │         │
│       │    │   ZAP   │             │         │
│       │    │ (DAST)  │             │         │
│       │    └────┬────┘             │         │
│       │         │                  │         │
│       ▼         ▼                  ▼         │
│  ┌──────────────────────────────────────┐    │
│  │      JSON scan artifacts (merged)    │    │
│  └──────────────────┬───────────────────┘    │
│                     │                        │
│                     ▼                        │
│  ┌──────────────────────────────────────┐    │
│  │          triage.py (Gemini API)      │    │
│  │  - Parse scanner JSON               │    │
│  │  - Deduplicate cross-tool findings   │    │
│  │  - Classify severity                 │    │
│  │  - Generate remediation advice       │    │
│  └──────────────────┬───────────────────┘    │
│                     │                        │
│                     ▼                        │
│           PR Comment (Markdown table)        │
└─────────────────────────────────────────────┘
```

## How It Works

1. A push, pull request, or manual run triggers the `security-scan.yml` workflow
2. The workflow first classifies changed files and creates a scan plan:
   - **Docs/markdown-only changes** → run **TruffleHog (secrets)** only
   - **App/runtime changes** → run Semgrep, TruffleHog, pip-audit, and/or ZAP as relevant
   - **Workflow/triage changes** or manual **force full scan** → run all scanners
3. Enabled scanners run in parallel:
   - **Semgrep** (SAST) — scans source code for vulnerabilities using `p/python` and `p/owasp-top-ten` rulesets
   - **TruffleHog** (Secrets) — scans the filesystem for hardcoded secrets and API keys
   - **pip-audit** (SCA) — checks `requirements.txt` for dependencies with known CVEs
   - **ZAP** (DAST) — runs a baseline scan against the Dockerized app for runtime vulnerabilities
4. Each scanner outputs structured JSON artifacts
5. The **triage agent** (`triage/triage.py`) collects all artifacts, sends them to Gemini (`gemini-2.5-pro`), which deduplicates cross-tool findings, assigns severity, and writes plain-English remediation
6. On PR runs, triaged results are posted as a formatted Markdown table comment

### Manual Force Full Scan

You can always run a full scan from the Actions UI:

1. Go to **Actions** → **Security Scan Pipeline**
2. Click **Run workflow**
3. Set **force_full_scan = true**
4. Run

## Target Application

The `app/` directory contains an intentionally vulnerable Flask application with:
- SQL injection endpoint (`/search`)
- Reflected XSS endpoint (`/greet`)
- Hardcoded API keys and passwords in source
- Pinned dependencies with known CVEs

**This app exists solely as a scanner target. Do not deploy it.**

## Setup

### Prerequisites
- Python 3.11+
- Docker (for the DAST scan)

### Running Tests Locally

```bash
pip install pytest pytest-cov google-genai
python -m pytest tests/ -v --cov=triage --cov-report=term-missing
```

### GitHub Repository Setup

1. Push this repo to GitHub
2. Add repository secrets:
   - `GEMINI_API_KEY` — your Gemini API key
   - `GITHUB_TOKEN` is automatically provided by GitHub Actions
3. Open a pull request — the pipeline triggers automatically

### Public Repo Approval Behavior

- This workflow only runs PR scans for authors with GitHub association:
   - `OWNER`, `MEMBER`, or `COLLABORATOR`
- External contributors can still open PRs on a public repo, but scans are skipped until you add/approve them as collaborators.
- For stricter control, also enable:
   - **Settings → Actions → General → Fork pull request workflows from outside collaborators** (require approval)
   - **Branch protection** on `main` (require PR reviews and required checks)

### Use This Tool In Your Own Repo

If someone else wants to use this pipeline:

1. Fork or copy this repository
2. In their repo, add `GEMINI_API_KEY` at:
    - **Settings → Secrets and variables → Actions → New repository secret**
3. Push changes and open a PR
4. (Optional) Use **Actions → Security Scan Pipeline → Run workflow** with `force_full_scan=true` for a full manual run

## Example PR Comment Output

> ## Security Scan Results
>
> **4 findings:** CRITICAL 1 | HIGH 2 | MEDIUM 1
>
> | Severity | Finding | Scanner | File | Remediation |
> |----------|---------|---------|------|-------------|
> | CRITICAL | SQL Injection in search endpoint | semgrep | `app/app.py:42` | Use parameterized queries with `?` placeholders. |
> | HIGH | Hardcoded API key | trufflehog | `app/app.py:14` | Move secrets to environment variables or a vault. |
> | HIGH | requests==2.25.0 has known CVE | pip-audit | `requirements.txt` | Upgrade to requests>=2.31.0. |
> | MEDIUM | Reflected XSS via template injection | semgrep, zap | `app/app.py:52` | Use Jinja2 autoescaping or `escape()`. |

## Project Structure

```
ai-devsecops-pipeline/
├── .github/workflows/security-scan.yml  — CI/CD pipeline
├── app/
│   ├── app.py               — intentionally vulnerable Flask app
│   ├── requirements.txt      — includes pinned vulnerable deps
│   └── Dockerfile            — container for DAST scanning
├── triage/
│   ├── triage.py             — AI triage agent (Gemini API)
│   └── requirements.txt      — Gemini SDK dependency
├── tests/
│   └── test_triage.py        — 31 tests, 98% coverage
├── docs/
│   ├── runbook.md            — operational runbook
│   └── ai-tooling-notes.md   — AI output quality evaluation
└── README.md
```

## Tech Stack

- Python 3.11+
- GitHub Actions
- Gemini API (`google-genai` Python SDK)
- Semgrep, TruffleHog, pip-audit, ZAP
- pytest + pytest-cov
