# Operational Runbook — ai-devsecops-pipeline

## How to Trigger a Scan

Open or update a pull request against the repository. The `security-scan.yml` workflow triggers automatically on `pull_request` events (opened, synchronize).

## How to Interpret Findings

The PR comment is a Markdown table sorted by severity:

| Severity | Meaning | Action Required |
|----------|---------|-----------------|
| CRITICAL | Exploitable vulnerability with high impact (e.g., SQLi, verified leaked secret) | Must fix before merge |
| HIGH | Significant vulnerability or unverified secret | Should fix before merge |
| MEDIUM | Moderate risk, may require context to assess | Review and fix if applicable |
| LOW | Minor issue, hardening recommendation | Fix at your discretion |
| INFO | Informational, no direct security impact | No action required |

Each row includes:
- **Finding** — short description of the issue
- **Scanner** — which tool(s) flagged it (cross-tool findings are deduplicated)
- **File** — source file and line number where applicable
- **Remediation** — one-sentence fix recommendation from Gemini

## Escalation Path

1. **Developer** reviews the PR comment and addresses CRITICAL/HIGH findings before requesting review
2. **Security champion / reviewer** validates fixes and assesses MEDIUM findings for context-specific risk
3. **Security team** is notified if CRITICAL findings are merged (configure branch protection rules to block merges with unresolved CRITICAL findings)

## False Positive Suppression

If a finding is a confirmed false positive:

1. **Semgrep**: Add a `# nosemgrep: <rule-id>` inline comment
2. **TruffleHog**: Add the pattern to a `.trufflehog-ignore` file
3. **pip-audit**: If the CVE doesn't apply to your usage, document in a `pip-audit-ignore.txt`
4. **ZAP**: Configure alert filters in the ZAP baseline config

After suppression, re-run the pipeline to confirm the finding no longer appears.

## Updating Scanner Rules

- **Semgrep rules**: Edit the `--config` flags in `security-scan.yml`. Available rulesets: https://semgrep.dev/explore
- **TruffleHog**: Updates automatically (uses latest detectors). Custom patterns can be added via `--rules` flag
- **pip-audit**: Pulls from the OSV and PyPI advisory databases automatically
- **ZAP**: Uses the default baseline ruleset. Custom scan policies can be configured via `-z` options

## Troubleshooting

| Problem | Likely Cause | Fix |
|---------|-------------|-----|
| Triage job fails with `GEMINI_API_KEY` error | Secret not configured | Add `GEMINI_API_KEY` to repo Settings > Secrets |
| ZAP scan produces empty results | App container didn't start in time | Check Docker build logs; increase health check timeout |
| Scanner job passes but no PR comment | `PR_NUMBER` env var not set correctly | Verify the workflow uses `github.event.pull_request.number` |
| Gemini returns malformed JSON | Unexpected model output | The triage agent strips markdown fencing; if still failing, check the prompt |
| Pipeline runs but misses known vulns | Scanner rules may not cover the pattern | Add targeted Semgrep rules or update dependency databases |
