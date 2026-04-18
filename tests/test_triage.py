"""
Tests for the triage agent.

Covers JSON parsing for each scanner, severity mapping, markdown formatting,
and Gemini API call (mocked).
"""

import json
import os
import sys
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "triage"))

from triage import (
    format_pr_comment,
    load_scanner_results,
    main,
    parse_pip_audit,
    parse_semgrep,
    parse_trufflehog,
    parse_zap,
    post_pr_comment,
    triage_findings,
)


# ---------------------------------------------------------------------------
# Fixtures: sample scanner outputs
# ---------------------------------------------------------------------------

SAMPLE_SEMGREP = {
    "results": [
        {
            "check_id": "python.lang.security.audit.sqli.string-concat-query",
            "path": "app/app.py",
            "start": {"line": 42, "col": 4},
            "end": {"line": 42, "col": 80},
            "extra": {
                "message": "Detected string concatenation in SQL query",
                "severity": "ERROR",
                "lines": 'f"SELECT username, email FROM users WHERE username LIKE \'%{query}%\'"',
            },
        },
        {
            "check_id": "python.flask.security.xss.audit.template-unescaped",
            "path": "app/app.py",
            "start": {"line": 52, "col": 4},
            "end": {"line": 52, "col": 50},
            "extra": {
                "message": "User input rendered in template without escaping",
                "severity": "WARNING",
                "lines": 'template = f"<h1>Hello {name}!</h1>"',
            },
        },
    ]
}

SAMPLE_TRUFFLEHOG = [
    {
        "DetectorName": "Generic API Key",
        "Verified": False,
        "Raw": "sk-ant-api03-FAKE-KEY-FOR-TESTING-ONLY-do-not-use-xxxxxxxxxxxxxxxx",
        "SourceMetadata": {
            "Data": {
                "Filesystem": {
                    "file": "app/app.py",
                    "line": 14,
                }
            }
        },
    }
]

SAMPLE_PIP_AUDIT = [
    {
        "name": "requests",
        "version": "2.25.0",
        "vulns": [
            {
                "id": "PYSEC-2023-74",
                "description": "Unintended leak of Proxy-Authorization header",
                "fix_versions": ["2.31.0"],
            }
        ],
    },
    {
        "name": "urllib3",
        "version": "1.26.5",
        "vulns": [
            {
                "id": "PYSEC-2023-212",
                "description": "Cookie leak on redirect to different host",
                "fix_versions": ["1.26.18", "2.0.7"],
            }
        ],
    },
]

SAMPLE_ZAP = {
    "site": [
        {
            "@name": "http://localhost:5000",
            "alerts": [
                {
                    "pluginid": "10021",
                    "name": "X-Content-Type-Options Header Missing",
                    "riskdesc": "Low (Medium)",
                    "instances": [
                        {"uri": "http://localhost:5000/search", "evidence": ""},
                    ],
                },
                {
                    "pluginid": "40012",
                    "name": "Cross Site Scripting (Reflected)",
                    "riskdesc": "High (Medium)",
                    "instances": [
                        {
                            "uri": "http://localhost:5000/greet?name=<script>alert(1)</script>",
                            "evidence": "<script>alert(1)</script>",
                        },
                    ],
                },
            ],
        }
    ]
}


# ---------------------------------------------------------------------------
# Parser tests
# ---------------------------------------------------------------------------

class TestParseSemgrep:
    def test_parses_all_results(self):
        findings = parse_semgrep(SAMPLE_SEMGREP)
        assert len(findings) == 2

    def test_fields(self):
        findings = parse_semgrep(SAMPLE_SEMGREP)
        f = findings[0]
        assert f["scanner"] == "semgrep"
        assert "sqli" in f["rule_id"]
        assert f["file"] == "app/app.py"
        assert f["line"] == 42
        assert f["severity"] == "ERROR"
        assert "concatenation" in f["message"].lower()

    def test_empty_input(self):
        assert parse_semgrep({}) == []
        assert parse_semgrep({"results": []}) == []


class TestParseTrufflehog:
    def test_parses_secret(self):
        findings = parse_trufflehog(SAMPLE_TRUFFLEHOG)
        assert len(findings) == 1

    def test_unverified_is_high(self):
        findings = parse_trufflehog(SAMPLE_TRUFFLEHOG)
        assert findings[0]["severity"] == "HIGH"

    def test_verified_is_critical(self):
        verified = [{**SAMPLE_TRUFFLEHOG[0], "Verified": True}]
        findings = parse_trufflehog(verified)
        assert findings[0]["severity"] == "CRITICAL"

    def test_fields(self):
        findings = parse_trufflehog(SAMPLE_TRUFFLEHOG)
        f = findings[0]
        assert f["scanner"] == "trufflehog"
        assert f["file"] == "app/app.py"
        assert "Secret detected" in f["message"]

    def test_empty_input(self):
        assert parse_trufflehog([]) == []


class TestParsePipAudit:
    def test_parses_all_vulns(self):
        findings = parse_pip_audit(SAMPLE_PIP_AUDIT)
        assert len(findings) == 2

    def test_fields(self):
        findings = parse_pip_audit(SAMPLE_PIP_AUDIT)
        f = findings[0]
        assert f["scanner"] == "pip-audit"
        assert f["rule_id"] == "PYSEC-2023-74"
        assert f["file"] == "requirements.txt"
        assert "requests==2.25.0" in f["message"]

    def test_severity_with_fix(self):
        findings = parse_pip_audit(SAMPLE_PIP_AUDIT)
        # Both have fix versions, so both should be HIGH
        assert all(f["severity"] == "HIGH" for f in findings)

    def test_severity_without_fix(self):
        no_fix = [{"name": "foo", "version": "1.0", "vulns": [{"id": "CVE-X", "description": "bad"}]}]
        findings = parse_pip_audit(no_fix)
        assert findings[0]["severity"] == "MEDIUM"

    def test_dict_format_with_dependencies_key(self):
        wrapped = {"dependencies": SAMPLE_PIP_AUDIT, "fixes": []}
        findings = parse_pip_audit(wrapped)
        assert len(findings) == 2
        assert findings[0]["rule_id"] == "PYSEC-2023-74"

    def test_empty_input(self):
        assert parse_pip_audit([]) == []
        assert parse_pip_audit({"dependencies": []}) == []


class TestParseZap:
    def test_parses_alerts(self):
        findings = parse_zap(SAMPLE_ZAP)
        assert len(findings) == 2

    def test_severity_mapping(self):
        findings = parse_zap(SAMPLE_ZAP)
        severities = {f["rule_id"]: f["severity"] for f in findings}
        assert severities["zap-10021"] == "LOW"
        assert severities["zap-40012"] == "HIGH"

    def test_fields(self):
        findings = parse_zap(SAMPLE_ZAP)
        xss = [f for f in findings if "40012" in f["rule_id"]][0]
        assert xss["scanner"] == "zap"
        assert "Cross Site Scripting" in xss["message"]
        assert "<script>" in xss["snippet"]

    def test_empty_input(self):
        assert parse_zap({}) == []
        assert parse_zap({"site": []}) == []


# ---------------------------------------------------------------------------
# load_scanner_results integration test
# ---------------------------------------------------------------------------

class TestLoadScannerResults:
    def test_loads_multiple_scanners(self, tmp_path):
        (tmp_path / "semgrep_results.json").write_text(json.dumps(SAMPLE_SEMGREP))
        (tmp_path / "trufflehog_results.json").write_text(json.dumps(SAMPLE_TRUFFLEHOG))
        (tmp_path / "pip-audit_results.json").write_text(json.dumps(SAMPLE_PIP_AUDIT))
        (tmp_path / "zap_results.json").write_text(json.dumps(SAMPLE_ZAP))

        findings = load_scanner_results(str(tmp_path))
        # 2 semgrep + 1 trufflehog + 2 pip-audit + 2 zap = 7
        assert len(findings) == 7

    def test_skips_unknown_scanner(self, tmp_path):
        (tmp_path / "foobar_results.json").write_text(json.dumps({"data": []}))
        findings = load_scanner_results(str(tmp_path))
        assert len(findings) == 0

    def test_empty_directory(self, tmp_path):
        findings = load_scanner_results(str(tmp_path))
        assert findings == []


# ---------------------------------------------------------------------------
# Markdown formatting tests
# ---------------------------------------------------------------------------

class TestFormatPrComment:
    def test_no_findings(self):
        comment = format_pr_comment([])
        assert "No Findings" in comment
        assert "no actionable" in comment.lower()

    def test_table_structure(self):
        triaged = [
            {
                "title": "SQL Injection in search",
                "severity": "CRITICAL",
                "scanner": "semgrep",
                "file": "app/app.py",
                "line": 42,
                "remediation": "Use parameterized queries.",
            },
            {
                "title": "Missing header",
                "severity": "LOW",
                "scanner": "zap",
                "file": "http://localhost/search",
                "line": 0,
                "remediation": "Add X-Content-Type-Options header.",
            },
        ]
        comment = format_pr_comment(triaged)
        assert "Security Scan Results" in comment
        assert "| Severity |" in comment
        assert "SQL Injection" in comment
        assert "CRITICAL" in comment
        assert "`app/app.py:42`" in comment

    def test_severity_ordering(self):
        triaged = [
            {"title": "Low issue", "severity": "LOW", "scanner": "a", "file": "", "line": 0, "remediation": "x"},
            {"title": "Critical issue", "severity": "CRITICAL", "scanner": "b", "file": "", "line": 0, "remediation": "y"},
        ]
        comment = format_pr_comment(triaged)
        # CRITICAL should appear before LOW
        crit_pos = comment.index("CRITICAL")
        low_pos = comment.index("**LOW**")
        assert crit_pos < low_pos

    def test_finding_count(self):
        triaged = [
            {"title": f"Issue {i}", "severity": "MEDIUM", "scanner": "s", "file": "", "line": 0, "remediation": "r"}
            for i in range(5)
        ]
        comment = format_pr_comment(triaged)
        assert "5 findings" in comment


# ---------------------------------------------------------------------------
# Gemini API triage test (mocked)
# ---------------------------------------------------------------------------

class TestTriageFindings:
    def test_calls_gemini_api(self):
        mock_response = MagicMock()
        mock_response.text = json.dumps([
            {
                "title": "SQL Injection",
                "severity": "CRITICAL",
                "scanner": "semgrep",
                "file": "app/app.py",
                "line": 42,
                "remediation": "Use parameterized queries.",
            }
        ])

        with patch("triage.genai.Client") as mock_cls:
            mock_client = MagicMock()
            mock_cls.return_value = mock_client
            mock_client.models.generate_content.return_value = mock_response

            findings = [{"scanner": "semgrep", "rule_id": "test", "message": "test", "file": "x", "line": 1, "severity": "HIGH", "snippet": ""}]
            result = triage_findings(findings)

            mock_client.models.generate_content.assert_called_once()
            call_kwargs = mock_client.models.generate_content.call_args[1]
            assert call_kwargs["model"] == "gemini-2.5-pro"
            assert len(result) == 1
            assert result[0]["title"] == "SQL Injection"

    def test_empty_findings_returns_empty(self):
        result = triage_findings([])
        assert result == []

    def test_handles_markdown_fencing(self):
        mock_response = MagicMock()
        mock_response.text = '```json\n[{"title": "XSS", "severity": "HIGH", "scanner": "zap", "file": "", "line": 0, "remediation": "Escape output."}]\n```'

        with patch("triage.genai.Client") as mock_cls:
            mock_client = MagicMock()
            mock_cls.return_value = mock_client
            mock_client.models.generate_content.return_value = mock_response

            findings = [{"scanner": "zap", "rule_id": "t", "message": "t", "file": "x", "line": 1, "severity": "HIGH", "snippet": ""}]
            result = triage_findings(findings)
            assert result[0]["title"] == "XSS"


# ---------------------------------------------------------------------------
# post_pr_comment tests
# ---------------------------------------------------------------------------

class TestPostPrComment:
    def test_prints_to_stdout_without_token(self, capsys):
        post_pr_comment("test comment body", "owner/repo", 1)
        captured = capsys.readouterr()
        assert "test comment body" in captured.out

    def test_posts_to_github_with_token(self):
        mock_resp = MagicMock()
        mock_resp.status = 201
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)

        with patch.dict(os.environ, {"GITHUB_TOKEN": "ghp_fake123"}):
            with patch("urllib.request.urlopen", return_value=mock_resp) as mock_urlopen:
                post_pr_comment("body", "owner/repo", 42)
                mock_urlopen.assert_called_once()
                req = mock_urlopen.call_args[0][0]
                assert "owner/repo" in req.full_url
                assert req.get_header("Authorization") == "Bearer ghp_fake123"


# ---------------------------------------------------------------------------
# main() integration test (mocked)
# ---------------------------------------------------------------------------

class TestMain:
    def test_main_no_findings(self, tmp_path, capsys):
        env = {
            "SCAN_ARTIFACTS": str(tmp_path),
            "GITHUB_REPOSITORY": "",
            "PR_NUMBER": "0",
        }
        with patch.dict(os.environ, env):
            main()
        captured = capsys.readouterr()
        assert "No Findings" in captured.out

    def test_main_with_findings(self, tmp_path, capsys):
        (tmp_path / "semgrep_results.json").write_text(json.dumps(SAMPLE_SEMGREP))

        triaged_response = json.dumps([{
            "title": "SQL Injection",
            "severity": "CRITICAL",
            "scanner": "semgrep",
            "file": "app/app.py",
            "line": 42,
            "remediation": "Use parameterized queries.",
        }])
        mock_response = MagicMock()
        mock_response.text = triaged_response

        env = {
            "SCAN_ARTIFACTS": str(tmp_path),
            "GITHUB_REPOSITORY": "",
            "PR_NUMBER": "0",
        }
        with patch.dict(os.environ, env):
            with patch("triage.genai.Client") as mock_cls:
                mock_client = MagicMock()
                mock_cls.return_value = mock_client
                mock_client.models.generate_content.return_value = mock_response
                main()

        captured = capsys.readouterr()
        assert "SQL Injection" in captured.out
        assert "CRITICAL" in captured.out
