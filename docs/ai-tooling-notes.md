# AI Tooling Evaluation — Gemini Triage Agent

Internal evaluation of the Gemini API integration used for security finding triage in this pipeline.

## What It Does Well

- **Cross-tool deduplication**: Gemini reliably identifies when multiple scanners flag the same underlying issue (e.g., Semgrep finds the XSS in source while ZAP finds it at runtime) and merges them into a single finding
- **Severity normalization**: Scanner-native severity labels are inconsistent (Semgrep uses ERROR/WARNING, ZAP uses High/Medium/Low, pip-audit has none). Gemini maps them to a consistent CRITICAL/HIGH/MEDIUM/LOW/INFO scale with reasonable accuracy
- **Remediation quality**: The one-sentence remediations are actionable and specific to the technology stack (e.g., "use parameterized queries with `?` placeholders" rather than generic "fix the SQL injection")
- **Structured output**: With explicit JSON schema instructions in the prompt, Gemini returns parseable JSON reliably (>95% of calls)

## Known Limitations

- **No code context**: The triage agent only sees scanner output, not the actual source code. This means Gemini cannot verify whether a finding is a true or false positive — it can only classify what the scanners report
- **Severity can be overfit to labels**: If a scanner labels something as HIGH, Gemini may defer to that label even when context suggests otherwise. The prompt instructs independent assessment, but the scanner's label acts as an anchor
- **Model variability**: Different runs on the same input may produce slightly different severity assignments or remediation wording. The pipeline does not pin a specific model snapshot
- **Cost**: Each triage call costs ~$0.01–0.05 depending on finding volume. At scale (hundreds of PRs/day), this adds up
- **Latency**: The Gemini API call adds a few seconds to the pipeline. Acceptable for CI, but noticeable

## Safe Usage Guidelines

1. **Gemini output is advisory, not authoritative.** It assists human review — it does not replace it. Security decisions (merge/block) must be made by a human reviewer
2. **Do not send sensitive source code to the API.** The current implementation only sends scanner output (file paths, line numbers, rule IDs, short snippets). Full source code is never included in the prompt
3. **Audit the prompt.** The triage prompt is in `triage/triage.py` (`TRIAGE_PROMPT`). Any changes to the prompt should be reviewed for:
   - Inadvertent data leakage (e.g., adding full file contents)
   - Prompt injection vectors (scanner output is user-controlled data embedded in the prompt)
4. **Monitor for prompt injection.** A malicious PR could craft code or filenames designed to manipulate the triage prompt. Current mitigation: the prompt clearly separates instructions from data, and findings are JSON-serialized. Future work: add input sanitization
5. **Rate limiting.** The pipeline makes one API call per PR. If the workflow is triggered excessively (e.g., force-push spam), costs and rate limits could become an issue. Consider adding concurrency controls to the workflow

## Output Quality Assessment

Based on testing against the intentionally vulnerable target app:

| Metric | Assessment |
|--------|-----------|
| True positive rate | High — correctly identifies all planted vulnerabilities |
| False positive handling | Moderate — cannot verify FPs without code context, but severity assignment helps prioritize |
| Deduplication accuracy | High — reliably merges cross-tool findings for the same issue |
| Remediation usefulness | High — actionable, specific to the stack, avoids generic advice |
| JSON parse success rate | >95% — markdown fencing fallback handles remaining cases |
| Consistency across runs | Moderate — severity and wording may vary slightly between runs |
