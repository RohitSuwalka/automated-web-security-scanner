import json
import ssl

import pytest

from app import (validate_url, scan_headers, scan_tls, scan_cors,
                 calculate_score, generate_json_report, generate_html_report,
                 _is_private_ip, _resolve_hostname, _assign_grade, CHECK_WEIGHTS)


class TestValidator:
    def test_valid_public_url_passes(self, mocker):
        mocker.patch("app._resolve_hostname", return_value=["93.184.216.34"])
        result = validate_url("https://example.com")
        assert result.startswith("https://example.com")

    def test_localhost_blocked(self):
        with pytest.raises(ValueError):
            validate_url("http://localhost/admin")

    def test_loopback_ip_blocked(self):
        with pytest.raises(ValueError):
            validate_url("http://127.0.0.1/")

    def test_rfc1918_ip_blocked(self):
        with pytest.raises(ValueError):
            validate_url("http://192.168.1.1/")

    def test_private_hostname_blocked(self, mocker):
        mocker.patch("app._resolve_hostname", return_value=["10.0.0.1"])
        with pytest.raises(ValueError):
            validate_url("http://internal.corp")

    def test_dot_local_blocked(self):
        with pytest.raises(ValueError):
            validate_url("http://printer.local/")

    def test_non_http_scheme_blocked(self):
        with pytest.raises(ValueError):
            validate_url("ftp://example.com")

    def test_allowlist_pass(self, mocker):
        mocker.patch("app._resolve_hostname", return_value=["93.184.216.34"])
        result = validate_url("https://example.com", allowlist=["example.com"])
        assert result.startswith("https://example.com")

    def test_allowlist_fail(self, mocker):
        mocker.patch("app._resolve_hostname", return_value=["93.184.216.34"])
        with pytest.raises(ValueError):
            validate_url("https://example.com", allowlist=["allowed.com"])

    def test_scheme_prepended_when_missing(self, mocker):
        mocker.patch("app._resolve_hostname", return_value=["93.184.216.34"])
        result = validate_url("example.com")
        assert result.startswith("https://")

    def test_file_scheme_blocked(self):
        with pytest.raises(ValueError, match="Only http/https"):
            validate_url("file:///etc/passwd")

    def test_dns_failure_raises_value_error(self, mocker):
        mocker.patch("app._resolve_hostname", side_effect=ValueError("DNS resolution failed"))
        with pytest.raises(ValueError, match="DNS"):
            validate_url("https://nonexistent.invalid.tld.xyz")


class TestHeaderScanner:
    def _make_mock_response(self, mocker, headers: dict, url: str = "https://example.com"):
        mock_resp = mocker.MagicMock()
        mock_resp.headers = headers  # pass a plain dict; requests uses CaseInsensitiveDict but dict works for our checks
        mock_resp.url = url
        mock_session = mocker.MagicMock()
        mock_session.get.return_value = mock_resp
        mocker.patch("app.requests.Session", return_value=mock_session)
        return mock_resp

    def test_all_headers_present_and_strong(self, mocker):
        headers = {
            "Content-Security-Policy": "default-src 'self'",
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Permissions-Policy": "geolocation=()",
        }
        self._make_mock_response(mocker, headers)
        findings = scan_headers("https://example.com")
        statuses = {f["check_id"]: f["status"] for f in findings}
        assert statuses["csp"] == "pass"
        assert statuses["hsts"] == "pass"
        assert statuses["xfo"] == "pass"
        assert statuses["xcto"] == "pass"
        assert statuses["rp"] == "pass"
        assert statuses["pp"] == "pass"

    def test_all_headers_missing(self, mocker):
        self._make_mock_response(mocker, {})
        findings = scan_headers("https://example.com")
        fail_count = sum(1 for f in findings if f["status"] == "fail")
        warn_count = sum(1 for f in findings if f["status"] == "warn")
        # CSP, HSTS, XFO, XCTO, Referrer-Policy → fail; PP → warn
        assert fail_count >= 5
        assert warn_count >= 1

    def test_csp_with_unsafe_inline_warns(self, mocker):
        headers = {"Content-Security-Policy": "default-src 'self'; script-src 'unsafe-inline'"}
        self._make_mock_response(mocker, headers)
        findings = scan_headers("https://example.com")
        csp = next(f for f in findings if f["check_id"] == "csp")
        assert csp["status"] == "warn"

    def test_hsts_low_max_age_warns(self, mocker):
        headers = {
            "Content-Security-Policy": "default-src 'self'",
            "Strict-Transport-Security": "max-age=3600",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "no-referrer",
            "Permissions-Policy": "geolocation=()",
        }
        self._make_mock_response(mocker, headers)
        findings = scan_headers("https://example.com")
        hsts = next(f for f in findings if f["check_id"] == "hsts")
        assert hsts["status"] == "warn"

    def test_xcto_wrong_value_fails(self, mocker):
        headers = {"X-Content-Type-Options": "something-else"}
        self._make_mock_response(mocker, headers)
        findings = scan_headers("https://example.com")
        xcto = next(f for f in findings if f["check_id"] == "xcto")
        assert xcto["status"] == "fail"

    def test_http_site_hsts_not_applicable(self, mocker):
        headers = {}
        mock_resp = mocker.MagicMock()
        mock_resp.headers = headers
        mock_resp.url = "http://example.com"
        mock_session = mocker.MagicMock()
        mock_session.get.return_value = mock_resp
        mocker.patch("app.requests.Session", return_value=mock_session)
        findings = scan_headers("http://example.com")
        hsts = next(f for f in findings if f["check_id"] == "hsts")
        # HSTS should be warn (not applicable over HTTP), not fail
        assert hsts["status"] == "warn"

    def test_connection_error_raises_runtime_error(self, mocker):
        import requests as req
        mock_session = mocker.MagicMock()
        mock_session.get.side_effect = req.RequestException("Connection refused")
        mocker.patch("app.requests.Session", return_value=mock_session)
        with pytest.raises(RuntimeError, match="Failed to connect"):
            scan_headers("https://example.com")


class TestTLSScanner:
    def test_http_url_returns_no_https_warning(self):
        findings = scan_tls("http://example.com")
        assert len(findings) == 1
        assert findings[0]["status"] == "warn"
        assert findings[0]["check_id"] == "tls"

    def test_ssl_error_returns_fail(self, mocker):
        mocker.patch("app.socket.create_connection", side_effect=ssl.SSLError("cert verify failed"))
        findings = scan_tls("https://example.com")
        assert any(f["status"] == "fail" and f["check_id"] == "tls" for f in findings)

    def test_connection_refused_returns_fail(self, mocker):
        mocker.patch("app.socket.create_connection", side_effect=ConnectionRefusedError())
        findings = scan_tls("https://example.com")
        assert any(f["status"] == "fail" for f in findings)


class TestCORSScanner:
    def _mock_session(self, mocker, options_headers=None, get_headers=None):
        options_headers = options_headers or {}
        get_headers = get_headers or {}
        mock_options_resp = mocker.MagicMock()
        mock_options_resp.headers = options_headers
        mock_get_resp = mocker.MagicMock()
        mock_get_resp.headers = get_headers
        mock_session = mocker.MagicMock()
        mock_session.options.return_value = mock_options_resp
        mock_session.get.return_value = mock_get_resp
        mocker.patch("app.requests.Session", return_value=mock_session)

    def test_wildcard_cors_warns(self, mocker):
        self._mock_session(mocker, get_headers={"Access-Control-Allow-Origin": "*"})
        findings = scan_cors("https://example.com")
        assert len(findings) == 1
        assert findings[0]["status"] == "warn"
        assert findings[0]["severity"] == "medium"

    def test_wildcard_with_credentials_fails(self, mocker):
        self._mock_session(mocker,
            options_headers={"Access-Control-Allow-Origin": "*", "Access-Control-Allow-Credentials": "true"},
            get_headers={"Access-Control-Allow-Origin": "*", "Access-Control-Allow-Credentials": "true"})
        findings = scan_cors("https://example.com")
        assert findings[0]["status"] == "fail"
        assert findings[0]["severity"] == "critical"

    def test_restrictive_cors_passes(self, mocker):
        self._mock_session(mocker,
            options_headers={"Access-Control-Allow-Origin": "https://example.com"},
            get_headers={"Access-Control-Allow-Origin": "https://example.com"})
        findings = scan_cors("https://example.com")
        assert findings[0]["status"] == "pass"

    def test_reflected_origin_warns(self, mocker):
        probe = "https://attacker-probe.example.com"
        mock_options_resp = mocker.MagicMock()
        mock_options_resp.headers = {}
        mock_get_resp = mocker.MagicMock()
        mock_get_resp.headers = {"Access-Control-Allow-Origin": probe}
        mock_session = mocker.MagicMock()
        mock_session.options.return_value = mock_options_resp
        mock_session.get.return_value = mock_get_resp
        mocker.patch("app.requests.Session", return_value=mock_session)
        findings = scan_cors("https://example.com")
        assert findings[0]["status"] == "warn"
        assert findings[0]["severity"] == "high"


class TestScoring:
    def _make_finding(self, check_id, status, severity="info", title="Test"):
        return {
            "check_id": check_id, "header": "X-Test", "status": status,
            "severity": severity, "title": title,
            "description": "desc", "recommendation": "rec", "evidence": "ev"
        }

    def test_all_pass_score_is_100(self):
        findings = [
            self._make_finding("csp", "pass"),
            self._make_finding("hsts", "pass"),
            self._make_finding("xfo", "pass"),
            self._make_finding("xcto", "pass"),
            self._make_finding("rp", "pass"),
            self._make_finding("pp", "pass"),
            self._make_finding("tls", "pass"),
            self._make_finding("cors", "pass"),
        ]
        result = calculate_score(findings)
        assert result["score"] == 100
        assert result["grade"] == "A+"

    def test_all_fail_score_is_0(self):
        findings = [
            self._make_finding("csp", "fail"),
            self._make_finding("hsts", "fail"),
            self._make_finding("xfo", "fail"),
            self._make_finding("xcto", "fail"),
            self._make_finding("rp", "fail"),
            self._make_finding("pp", "fail"),
            self._make_finding("tls", "fail"),
            self._make_finding("cors", "fail"),
        ]
        result = calculate_score(findings)
        assert result["score"] == 0
        assert result["grade"] == "F"

    def test_all_warn_score_is_50(self):
        findings = [
            self._make_finding("csp", "warn"),
            self._make_finding("hsts", "warn"),
            self._make_finding("xfo", "warn"),
            self._make_finding("xcto", "warn"),
            self._make_finding("rp", "warn"),
            self._make_finding("pp", "warn"),
            self._make_finding("tls", "warn"),
            self._make_finding("cors", "warn"),
        ]
        result = calculate_score(findings)
        # warn = half points → score should be ~50
        assert 45 <= result["score"] <= 55

    def test_mixed_findings(self):
        findings = [
            self._make_finding("csp", "pass"),   # 20 pts
            self._make_finding("hsts", "fail"),  # 0 pts
            self._make_finding("xfo", "pass"),   # 10 pts
            self._make_finding("xcto", "pass"),  # 10 pts
            self._make_finding("rp", "warn"),    # 5 pts
            self._make_finding("pp", "pass"),    # 5 pts
            self._make_finding("tls", "pass"),   # 15 pts
            self._make_finding("cors", "warn"),  # 7 pts
        ]
        result = calculate_score(findings)
        # earned: 20+0+10+10+5+5+15+7 = 72
        assert result["score"] == 72

    def test_severity_counts(self):
        findings = [
            self._make_finding("csp", "fail", "critical"),
            self._make_finding("hsts", "fail", "high"),
            self._make_finding("xfo", "warn", "medium"),
            self._make_finding("xcto", "pass", "info"),
            self._make_finding("rp", "pass", "info"),
            self._make_finding("pp", "warn", "low"),
            self._make_finding("tls", "pass", "info"),
            self._make_finding("cors", "pass", "info"),
        ]
        result = calculate_score(findings)
        assert result["severity_counts"]["critical"] == 1
        assert result["severity_counts"]["high"] == 1
        assert result["severity_counts"]["medium"] == 1
        assert result["severity_counts"]["low"] == 1

    def test_grade_thresholds(self):
        assert _assign_grade(95) == "A+"
        assert _assign_grade(85) == "A"
        assert _assign_grade(75) == "B"
        assert _assign_grade(65) == "C"
        assert _assign_grade(55) == "D"
        assert _assign_grade(40) == "F"

    def test_no_findings_gives_50_score(self):
        # empty findings → all checks inconclusive → all warn → ~50
        result = calculate_score([])
        assert 45 <= result["score"] <= 55

    def test_score_breakdown_has_all_checks(self):
        findings = [self._make_finding(cid, "pass") for cid in CHECK_WEIGHTS]
        result = calculate_score(findings)
        breakdown_ids = {item["check_id"] for item in result["score_breakdown"]}
        assert breakdown_ids == set(CHECK_WEIGHTS.keys())

    def test_unknown_check_id_ignored_in_score(self):
        # Findings with unknown check_id should not affect the score
        findings = [
            self._make_finding("csp", "pass"),
            self._make_finding("hsts", "pass"),
            self._make_finding("xfo", "pass"),
            self._make_finding("xcto", "pass"),
            self._make_finding("rp", "pass"),
            self._make_finding("pp", "pass"),
            self._make_finding("tls", "pass"),
            self._make_finding("cors", "pass"),
            self._make_finding("tls_version", "warn"),  # not in CHECK_WEIGHTS
        ]
        result = calculate_score(findings)
        assert result["score"] == 100  # tls_version doesn't reduce score


class TestReports:
    def _sample_findings(self):
        return [
            {"check_id": "csp", "header": "Content-Security-Policy",
             "status": "fail", "severity": "high",
             "title": "CSP Missing", "description": "desc",
             "recommendation": "rec", "evidence": "Header not present"},
            {"check_id": "hsts", "header": "Strict-Transport-Security",
             "status": "pass", "severity": "info",
             "title": "HSTS Present", "description": "desc",
             "recommendation": "rec", "evidence": "max-age=31536000"},
        ]

    def _sample_score(self):
        return {
            "score": 75,
            "grade": "B",
            "severity_counts": {"critical": 0, "high": 1, "medium": 0, "low": 0, "info": 1},
            "score_breakdown": [
                {"check_id": "csp", "max_points": 20, "earned_points": 0, "status": "fail", "title": "CSP Missing"},
                {"check_id": "hsts", "max_points": 15, "earned_points": 15, "status": "pass", "title": "HSTS Present"},
            ],
        }

    def test_json_report_is_valid_json(self):
        data = generate_json_report("https://example.com", self._sample_findings(), self._sample_score())
        assert isinstance(data, bytes)
        parsed = json.loads(data.decode("utf-8"))
        assert parsed["scan_target"] == "https://example.com"
        assert parsed["score"] == 75
        assert parsed["grade"] == "B"
        assert len(parsed["findings"]) == 2

    def test_json_report_has_disclaimer(self):
        data = generate_json_report("https://example.com", self._sample_findings(), self._sample_score())
        parsed = json.loads(data.decode("utf-8"))
        assert "disclaimer" in parsed
        assert len(parsed["disclaimer"]) > 20

    def test_html_report_is_bytes(self):
        data = generate_html_report("https://example.com", self._sample_findings(), self._sample_score())
        assert isinstance(data, bytes)
        html = data.decode("utf-8")
        assert "<!DOCTYPE html>" in html

    def test_html_report_contains_score(self):
        data = generate_html_report("https://example.com", self._sample_findings(), self._sample_score())
        html = data.decode("utf-8")
        assert "75" in html
        assert "example.com" in html

    def test_html_report_contains_findings(self):
        data = generate_html_report("https://example.com", self._sample_findings(), self._sample_score())
        html = data.decode("utf-8")
        assert "CSP Missing" in html
        assert "HSTS Present" in html

    def test_json_report_timestamp_format(self):
        data = generate_json_report("https://example.com", self._sample_findings(), self._sample_score())
        parsed = json.loads(data.decode("utf-8"))
        ts = parsed["scan_timestamp"]
        assert ts.endswith("Z")
        assert "T" in ts  # ISO-8601 format

    def test_html_report_has_no_external_resources(self):
        data = generate_html_report("https://example.com", self._sample_findings(), self._sample_score())
        html = data.decode("utf-8")
        # Must not reference external CDN URLs
        assert "cdn.jsdelivr" not in html
        assert "googleapis.com" not in html
        assert "unpkg.com" not in html
