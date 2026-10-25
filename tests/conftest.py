import pytest
import json


@pytest.fixture
def sample_findings():
    """A representative set of findings covering all CHECK_WEIGHTS check_ids."""
    return [
        {"check_id": "csp",  "header": "Content-Security-Policy",      "status": "fail", "severity": "high",   "title": "CSP Missing",      "description": "d", "recommendation": "r", "evidence": "Header not present"},
        {"check_id": "hsts", "header": "Strict-Transport-Security",     "status": "pass", "severity": "info",   "title": "HSTS Present",     "description": "d", "recommendation": "r", "evidence": "max-age=31536000"},
        {"check_id": "xfo",  "header": "X-Frame-Options",               "status": "pass", "severity": "info",   "title": "XFO Set",          "description": "d", "recommendation": "r", "evidence": "DENY"},
        {"check_id": "xcto", "header": "X-Content-Type-Options",        "status": "warn", "severity": "medium", "title": "XCTO Weak",        "description": "d", "recommendation": "r", "evidence": "Header not present"},
        {"check_id": "rp",   "header": "Referrer-Policy",               "status": "pass", "severity": "info",   "title": "Referrer OK",      "description": "d", "recommendation": "r", "evidence": "no-referrer"},
        {"check_id": "pp",   "header": "Permissions-Policy",            "status": "warn", "severity": "low",    "title": "PP Missing",       "description": "d", "recommendation": "r", "evidence": "Header not present"},
        {"check_id": "tls",  "header": "TLS/HTTPS",                     "status": "pass", "severity": "info",   "title": "TLS Valid",        "description": "d", "recommendation": "r", "evidence": "TLSv1.3"},
        {"check_id": "cors", "header": "Access-Control-Allow-Origin",   "status": "pass", "severity": "info",   "title": "CORS Restrictive", "description": "d", "recommendation": "r", "evidence": "Not present"},
    ]


@pytest.fixture
def sample_score_result():
    """A representative ScoreResult for report generator tests."""
    return {
        "score": 78,
        "grade": "B",
        "severity_counts": {"critical": 0, "high": 1, "medium": 1, "low": 1, "info": 5},
        "score_breakdown": [
            {"check_id": "csp",  "max_points": 20, "earned_points": 0,  "status": "fail", "title": "CSP Missing"},
            {"check_id": "hsts", "max_points": 15, "earned_points": 15, "status": "pass", "title": "HSTS Present"},
            {"check_id": "xfo",  "max_points": 10, "earned_points": 10, "status": "pass", "title": "XFO Set"},
            {"check_id": "xcto", "max_points": 10, "earned_points": 0,  "status": "warn", "title": "XCTO Weak"},
            {"check_id": "rp",   "max_points": 10, "earned_points": 10, "status": "pass", "title": "Referrer OK"},
            {"check_id": "pp",   "max_points": 5,  "earned_points": 2,  "status": "warn", "title": "PP Missing"},
            {"check_id": "tls",  "max_points": 15, "earned_points": 15, "status": "pass", "title": "TLS Valid"},
            {"check_id": "cors", "max_points": 15, "earned_points": 15, "status": "pass", "title": "CORS Restrictive"},
        ],
    }
