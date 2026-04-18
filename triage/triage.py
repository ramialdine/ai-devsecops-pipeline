"""
AI-powered security finding triage agent.

Reads JSON output from multiple security scanners (semgrep, trufflehog,
pip-audit, ZAP), calls the Gemini API to classify and deduplicate findings,
and posts a structured PR comment via the GitHub API.
"""

import json
import os
import sys
from pathlib import Path

from google import genai


# ---------------------------------------------------------------------------
# Scanner output parsers
# ---------------------------------------------------------------------------

def parse_semgrep(raw: dict) -> list[dict]:
    """Parse Semgrep JSON output into normalized findings."""
    findings = []
    for result in raw.get("results", []):
        findings.append({
            "scanner": "semgrep",
            "rule_id": result.get("check_id", "unknown"),
            "message": result.get("extra", {}).get("message", ""),
            "file": result.get("path", ""),
            "line": result.get("start", {}).get("line", 0),
            "severity": result.get("extra", {}).get("severity", "WARNING").upper(),
            "snippet": result.get("extra", {}).get("lines", ""),
        })
    return findings


def parse_trufflehog(raw: list) -> list[dict]:
    """Parse TruffleHog JSON output (one object per line) into normalized findings."""
    findings = []
    for item in raw:
        source_meta = item.get("SourceMetadata", {}).get("Data", {})
        file_info = source_meta.get("Filesystem", {})
        findings.append({
            "scanner": "trufflehog",
            "rule_id": item.get("DetectorName", "unknown"),
            "message": f"Secret detected: {item.get('DetectorName', 'unknown')} (verified={item.get('Verified', False)})",
            "file": file_info.get("file", ""),
            "line": file_info.get("line", 0),
            "severity": "CRITICAL" if item.get("Verified", False) else "HIGH",
            "snippet": item.get("Raw", "")[:120],
        })
    return findings


def parse_pip_audit(raw) -> list[dict]:
    """Parse pip-audit JSON output into normalized findings."""
    # pip-audit may wrap results in {"dependencies": [...], "fixes": [...]}
    if isinstance(raw, dict):
        raw = raw.get("dependencies", [])
    findings = []
    for vuln_pkg in raw:
        pkg_name = vuln_pkg.get("name", "unknown")
        version = vuln_pkg.get("version", "?")
        for vuln in vuln_pkg.get("vulns", []):
            findings.append({
                "scanner": "pip-audit",
                "rule_id": vuln.get("id", "unknown"),
                "message": f"{pkg_name}=={version}: {vuln.get('description', vuln.get('id', ''))}",
                "file": "requirements.txt",
                "line": 0,
                "severity": _map_pip_audit_severity(vuln),
                "snippet": "",
            })
    return findings


def _map_pip_audit_severity(vuln: dict) -> str:
    """Map pip-audit fix availability to a severity hint."""
    fix = vuln.get("fix_versions", [])
    vuln_id = vuln.get("id", "")
    if "CRITICAL" in vuln_id.upper():
        return "CRITICAL"
    if fix:
        return "HIGH"
    return "MEDIUM"


def parse_zap(raw: dict) -> list[dict]:
    """Parse ZAP baseline scan JSON output into normalized findings."""
    findings = []
    for site in raw.get("site", []):
        for alert in site.get("alerts", []):
            risk = alert.get("riskdesc", "").split(" ")[0].upper()
            severity = {"HIGH": "HIGH", "MEDIUM": "MEDIUM", "LOW": "LOW", "INFORMATIONAL": "INFO"}.get(risk, "MEDIUM")
            for instance in alert.get("instances", [{}])[:3]:
                findings.append({
                    "scanner": "zap",
                    "rule_id": f"zap-{alert.get('pluginid', 'unknown')}",
                    "message": alert.get("name", ""),
                    "file": instance.get("uri", ""),
                    "line": 0,
                    "severity": severity,
                    "snippet": instance.get("evidence", ""),
                })
    return findings


PARSERS = {
    "semgrep": parse_semgrep,
    "trufflehog": parse_trufflehog,
    "pip-audit": parse_pip_audit,
    "zap": parse_zap,
}


def load_scanner_results(artifact_dir: str) -> list[dict]:
    """Load and parse all scanner JSON files from the artifact directory."""
    all_findings = []
    artifact_path = Path(artifact_dir)
    for json_file in sorted(artifact_path.glob("*.json")):
        scanner_name = json_file.stem.replace("_results", "").replace("-results", "")
        # Normalize scanner name variations
        for key in PARSERS:
            if key.replace("-", "") in scanner_name.replace("-", "").replace("_", ""):
                scanner_name = key
                break
        if scanner_name not in PARSERS:
            print(f"[triage] Skipping unknown scanner output: {json_file.name}", file=sys.stderr)
            continue
        with open(json_file) as f:
            raw = json.load(f)
        parsed = PARSERS[scanner_name](raw)
        all_findings.extend(parsed)
        print(f"[triage] Parsed {len(parsed)} findings from {json_file.name}", file=sys.stderr)
    return all_findings


# ---------------------------------------------------------------------------
# Gemini API triage
# ---------------------------------------------------------------------------

TRIAGE_PROMPT = """\
You are a senior application security engineer triaging findings from automated \
security scanners run against a pull request.

Below is a JSON array of raw findings from multiple scanners (semgrep, trufflehog, \
pip-audit, ZAP). Your job:

1. **Deduplicate** cross-tool findings that describe the same underlying issue.
2. **Assign severity**: CRITICAL / HIGH / MEDIUM / LOW / INFO.
3. **Write a one-sentence plain-English remediation** for each unique finding.
4. **Return valid JSON** — an array of objects with these keys:
   - `title`: short title for the finding
   - `severity`: one of CRITICAL, HIGH, MEDIUM, LOW, INFO
   - `scanner`: which scanner(s) flagged it (comma-separated if multiple)
   - `file`: file path (if applicable)
   - `line`: line number (if applicable, else 0)
   - `remediation`: one-sentence fix recommendation

Only return the JSON array, no markdown fencing, no commentary.

Raw findings:
{findings_json}
"""


def triage_findings(findings: list[dict]) -> list[dict]:
    """Send findings to Gemini for deduplication, classification, and remediation."""
    if not findings:
        return []

    client = genai.Client(api_key=os.environ.get("GEMINI_API_KEY"))
    prompt = TRIAGE_PROMPT.format(findings_json=json.dumps(findings, indent=2))

    response = client.models.generate_content(
        model="gemini-2.5-pro",
        contents=prompt,
    )

    response_text = (response.text or "").strip()
    # Strip markdown fencing if the model adds it despite instructions
    if response_text.startswith("```"):
        response_text = response_text.split("\n", 1)[1] if "\n" in response_text else ""
    if response_text.endswith("```"):
        response_text = response_text.rsplit("```", 1)[0]

    return json.loads(response_text)


# ---------------------------------------------------------------------------
# Markdown formatting
# ---------------------------------------------------------------------------

SEVERITY_EMOJI = {
    "CRITICAL": "\U0001f534",
    "HIGH": "\U0001f7e0",
    "MEDIUM": "\U0001f7e1",
    "LOW": "\U0001f535",
    "INFO": "\u26aa",
}

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


def format_pr_comment(triaged: list[dict]) -> str:
    """Format triaged findings into a markdown PR comment."""
    if not triaged:
        return (
            "## \u2705 Security Scan — No Findings\n\n"
            "All scanners completed with no actionable findings."
        )

    triaged_sorted = sorted(triaged, key=lambda f: SEVERITY_ORDER.get(f.get("severity", "INFO"), 5))

    counts = {}
    for f in triaged_sorted:
        sev = f.get("severity", "INFO")
        counts[sev] = counts.get(sev, 0) + 1

    summary_parts = []
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        if sev in counts:
            emoji = SEVERITY_EMOJI.get(sev, "")
            summary_parts.append(f"{emoji} {counts[sev]} {sev}")

    lines = [
        "## \U0001f6e1\ufe0f Security Scan Results\n",
        f"**{len(triaged_sorted)} findings:** {' | '.join(summary_parts)}\n",
        "| Severity | Finding | Scanner | File | Remediation |",
        "|----------|---------|---------|------|-------------|",
    ]

    for f in triaged_sorted:
        sev = f.get("severity", "INFO")
        emoji = SEVERITY_EMOJI.get(sev, "")
        title = f.get("title", "Untitled")
        scanner = f.get("scanner", "")
        file_ref = f.get("file", "")
        line = f.get("line", 0)
        if line and file_ref:
            file_ref = f"`{file_ref}:{line}`"
        elif file_ref:
            file_ref = f"`{file_ref}`"
        remediation = f.get("remediation", "")
        lines.append(f"| {emoji} **{sev}** | {title} | {scanner} | {file_ref} | {remediation} |")

    lines.append("")
    lines.append("---")
    lines.append("*Generated by [ai-devsecops-pipeline](https://github.com) — Gemini-powered triage*")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# GitHub PR comment
# ---------------------------------------------------------------------------

def post_pr_comment(comment_body: str, repo: str, pr_number: int) -> None:
    """Post a comment to a GitHub pull request."""
    import urllib.request

    github_token = os.environ.get("GITHUB_TOKEN")
    if not github_token:
        print("[triage] GITHUB_TOKEN not set — printing comment to stdout", file=sys.stderr)
        print(comment_body)
        return

    url = f"https://api.github.com/repos/{repo}/issues/{pr_number}/comments"
    data = json.dumps({"body": comment_body}).encode()
    req = urllib.request.Request(
        url,
        data=data,
        headers={
            "Authorization": f"Bearer {github_token}",
            "Accept": "application/vnd.github+json",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    with urllib.request.urlopen(req) as resp:
        print(f"[triage] Posted PR comment (status {resp.status})", file=sys.stderr)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    artifact_dir = os.environ.get("SCAN_ARTIFACTS", "artifacts")
    repo = os.environ.get("GITHUB_REPOSITORY", "")
    pr_number_str = (os.environ.get("PR_NUMBER") or "").strip()
    try:
        pr_number = int(pr_number_str) if pr_number_str else 0
    except ValueError:
        print(f"[triage] Invalid PR_NUMBER='{pr_number_str}' — defaulting to 0", file=sys.stderr)
        pr_number = 0

    print(f"[triage] Loading scanner results from {artifact_dir}", file=sys.stderr)
    findings = load_scanner_results(artifact_dir)
    print(f"[triage] Total raw findings: {len(findings)}", file=sys.stderr)

    if not findings:
        comment = format_pr_comment([])
    else:
        print("[triage] Sending findings to Gemini for triage...", file=sys.stderr)
        triaged = triage_findings(findings)
        print(f"[triage] Triaged to {len(triaged)} unique findings", file=sys.stderr)
        comment = format_pr_comment(triaged)

    if repo and pr_number:
        post_pr_comment(comment, repo, pr_number)
    else:
        print(comment)


if __name__ == "__main__":
    main()
