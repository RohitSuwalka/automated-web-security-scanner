# ── SECTION 1: Imports & Constants ──────────────────────────────────────────

import ipaddress
import json
import socket
import ssl
import urllib.parse
from datetime import datetime, timezone
from typing import Literal

import requests
import streamlit as st
from cryptography import x509
from jinja2 import BaseLoader, Environment
from typing_extensions import TypedDict


class Finding(TypedDict):
    check_id: str
    header: str
    status: Literal["pass", "warn", "fail"]
    severity: Literal["info", "low", "medium", "high", "critical"]
    title: str
    description: str
    recommendation: str
    evidence: str


class ScoreResult(TypedDict):
    score: int
    grade: str
    severity_counts: dict
    score_breakdown: list


CHECK_WEIGHTS: dict[str, int] = {
    "csp": 20,
    "hsts": 15,
    "xfo": 10,
    "xcto": 10,
    "rp": 10,
    "pp": 5,
    "tls": 15,
    "cors": 15,
}

# ── SECTION 2: SSRF Guard & URL Validator ────────────────────────────────────


def _is_private_ip(ip_str: str) -> bool:
    """Return True if the IP is private, loopback, link-local, or reserved."""
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    return addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved


def _resolve_hostname(hostname: str) -> list:
    """Resolve *hostname* to a deduplicated list of IP address strings.

    Raises ValueError on DNS failure.
    """
    try:
        results = socket.getaddrinfo(hostname, None)
    except socket.gaierror as e:
        raise ValueError(f"DNS resolution failed for {hostname}: {e}") from e
    return list(dict.fromkeys(result[4][0] for result in results))


def validate_url(url: str, allowlist: list | None = None) -> str:
    """Validate *url* against SSRF-guard rules and return a normalised URL.

    Raises ValueError describing the specific rejection reason.
    """
    # 1. Strip whitespace
    url = url.strip()

    # 2. Prepend https:// if no scheme present
    if "://" not in url:
        url = "https://" + url

    # 3. Parse
    parsed = urllib.parse.urlparse(url)

    # 4. Scheme check
    if parsed.scheme not in {"http", "https"}:
        raise ValueError("Only http/https URLs are supported.")

    # 5. Hostname check
    hostname = parsed.hostname or ""
    if not hostname:
        raise ValueError("Invalid URL: no hostname.")

    # 6. Block private/local hostname patterns
    if (
        hostname == "localhost"
        or hostname.endswith(".local")
        or hostname.endswith(".internal")
    ):
        raise ValueError(
            f"Scanning '{hostname}' is not permitted (private/local destination)."
        )

    # 7. Resolve hostname (propagates ValueError on DNS failure)
    resolved_ips = _resolve_hostname(hostname)

    # 8. Block private IPs
    for ip in resolved_ips:
        if _is_private_ip(ip):
            raise ValueError(
                f"Scanning '{hostname}' is not permitted: resolves to private IP {ip}."
            )

    # 9. Allowlist check
    if allowlist:
        lower_allowlist = [h.lower() for h in allowlist]
        if hostname not in lower_allowlist:
            raise ValueError(f"'{hostname}' is not in the configured allowlist.")

    # 10. Return normalised URL
    normalised = urllib.parse.urlunparse(
        (parsed.scheme.lower(), parsed.netloc.lower(), parsed.path,
         parsed.params, parsed.query, parsed.fragment)
    )
    return normalised


# ── SECTION 3: HTTP Security Header Scanner ──────────────────────────────────


def _check_csp(headers: dict) -> Finding:
    """Check Content-Security-Policy header."""
    value = headers.get("Content-Security-Policy")
    if value is None:
        return Finding(
            check_id="csp",
            header="Content-Security-Policy",
            status="fail",
            severity="high",
            title="Content-Security-Policy Header Missing",
            description=(
                "The Content-Security-Policy (CSP) header is not set. Without CSP, the browser "
                "has no restrictions on what resources can be loaded, increasing the risk of "
                "cross-site scripting (XSS) and data injection attacks."
            ),
            recommendation=(
                "Add a Content-Security-Policy header with a restrictive policy such as "
                "'default-src \\'self\\'' and explicitly allowlist only necessary sources."
            ),
            evidence="Header not present",
        )
    value_lower = value.lower()
    if "'unsafe-inline'" in value_lower or "'unsafe-eval'" in value_lower:
        return Finding(
            check_id="csp",
            header="Content-Security-Policy",
            status="warn",
            severity="medium",
            title="Content-Security-Policy Contains Unsafe Directives",
            description=(
                "The Content-Security-Policy header is present but contains 'unsafe-inline' "
                "or 'unsafe-eval', which significantly weakens the protection against XSS attacks "
                "by allowing inline scripts or dynamic code evaluation."
            ),
            recommendation=(
                "Remove 'unsafe-inline' and 'unsafe-eval' from your CSP. Use nonces or hashes "
                "for inline scripts instead, and avoid eval() in your JavaScript code."
            ),
            evidence=value,
        )
    return Finding(
        check_id="csp",
        header="Content-Security-Policy",
        status="pass",
        severity="info",
        title="Content-Security-Policy Header Present",
        description="A Content-Security-Policy header is configured without unsafe directives.",
        recommendation="Regularly review and tighten your CSP as your application evolves.",
        evidence=value,
    )


def _check_hsts(headers: dict, is_https: bool = True) -> Finding:
    """Check Strict-Transport-Security header."""
    if not is_https:
        return Finding(
            check_id="hsts",
            header="Strict-Transport-Security",
            status="warn",
            severity="medium",
            title="HSTS Not Applicable Over HTTP",
            description=(
                "HTTP Strict Transport Security (HSTS) is not applicable because the target "
                "URL uses plain HTTP. HSTS instructs browsers to always use HTTPS for future "
                "connections, but only takes effect when delivered over HTTPS."
            ),
            recommendation=(
                "Ensure your site is accessible over HTTPS and configure HSTS on the HTTPS "
                "endpoint with a max-age of at least 31536000 seconds (one year)."
            ),
            evidence="HSTS not applicable over HTTP",
        )
    value = headers.get("Strict-Transport-Security")
    if value is None:
        return Finding(
            check_id="hsts",
            header="Strict-Transport-Security",
            status="fail",
            severity="high",
            title="Strict-Transport-Security Header Missing",
            description=(
                "The Strict-Transport-Security (HSTS) header is not set. Without HSTS, browsers "
                "may connect over plain HTTP, making users vulnerable to protocol downgrade attacks "
                "and man-in-the-middle attacks."
            ),
            recommendation=(
                "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' to all "
                "HTTPS responses. Consider adding the 'preload' directive and submitting to the "
                "HSTS preload list."
            ),
            evidence="Header not present",
        )
    # Parse max-age
    max_age = None
    for part in value.lower().split(";"):
        part = part.strip()
        if part.startswith("max-age="):
            try:
                max_age = int(part.split("=", 1)[1].strip())
            except ValueError:
                pass
            break
    if max_age is None or max_age < 31536000:
        return Finding(
            check_id="hsts",
            header="Strict-Transport-Security",
            status="warn",
            severity="medium",
            title="Strict-Transport-Security max-age Too Short",
            description=(
                f"The HSTS header is present but the max-age value "
                f"({max_age if max_age is not None else 'unreadable'}) is less than one year "
                f"(31536000 seconds). A short max-age limits HSTS protection."
            ),
            recommendation=(
                "Set max-age to at least 31536000 (one year). Example: "
                "'Strict-Transport-Security: max-age=31536000; includeSubDomains'."
            ),
            evidence=value,
        )
    return Finding(
        check_id="hsts",
        header="Strict-Transport-Security",
        status="pass",
        severity="info",
        title="Strict-Transport-Security Header Present and Strong",
        description="HSTS is configured with a max-age of at least one year.",
        recommendation=(
            "Consider adding 'includeSubDomains' and 'preload' directives if not already present."
        ),
        evidence=value,
    )


def _check_xfo(headers: dict) -> Finding:
    """Check X-Frame-Options header."""
    value = headers.get("X-Frame-Options")
    if value is None:
        return Finding(
            check_id="xfo",
            header="X-Frame-Options",
            status="fail",
            severity="medium",
            title="X-Frame-Options Header Missing",
            description=(
                "The X-Frame-Options header is not set. Without this header, the page can be "
                "embedded in a frame or iframe on any origin, enabling clickjacking attacks."
            ),
            recommendation=(
                "Add 'X-Frame-Options: DENY' to prevent all framing, or 'SAMEORIGIN' to allow "
                "framing only from the same origin. Alternatively, use the CSP 'frame-ancestors' "
                "directive for finer control."
            ),
            evidence="Header not present",
        )
    if value.strip().upper() == "ALLOWALL":
        return Finding(
            check_id="xfo",
            header="X-Frame-Options",
            status="warn",
            severity="low",
            title="X-Frame-Options Set to ALLOWALL",
            description=(
                "X-Frame-Options is set to ALLOWALL, which permits the page to be framed by any "
                "origin. This value is non-standard and provides no clickjacking protection."
            ),
            recommendation=(
                "Change X-Frame-Options to 'DENY' or 'SAMEORIGIN' to prevent unauthorized "
                "framing of your content."
            ),
            evidence=value,
        )
    return Finding(
        check_id="xfo",
        header="X-Frame-Options",
        status="pass",
        severity="info",
        title="X-Frame-Options Header Configured",
        description="X-Frame-Options is set to a protective value (DENY or SAMEORIGIN).",
        recommendation="Consider migrating to the CSP 'frame-ancestors' directive for greater control.",
        evidence=value,
    )


def _check_xcto(headers: dict) -> Finding:
    """Check X-Content-Type-Options header."""
    value = headers.get("X-Content-Type-Options")
    if value is None:
        return Finding(
            check_id="xcto",
            header="X-Content-Type-Options",
            status="fail",
            severity="medium",
            title="X-Content-Type-Options Header Missing",
            description=(
                "The X-Content-Type-Options header is not set. Without this header, browsers may "
                "MIME-sniff the content type, potentially executing non-script content as scripts "
                "and enabling MIME-confusion attacks."
            ),
            recommendation=(
                "Add 'X-Content-Type-Options: nosniff' to all HTTP responses to prevent MIME-type "
                "sniffing."
            ),
            evidence="Header not present",
        )
    if value.strip().lower() != "nosniff":
        return Finding(
            check_id="xcto",
            header="X-Content-Type-Options",
            status="fail",
            severity="medium",
            title="X-Content-Type-Options Not Set to nosniff",
            description=(
                f"The X-Content-Type-Options header is present but set to '{value}' instead of "
                "the required 'nosniff' value. Only 'nosniff' is a valid directive for this header."
            ),
            recommendation=(
                "Set X-Content-Type-Options to exactly 'nosniff': "
                "'X-Content-Type-Options: nosniff'."
            ),
            evidence=value,
        )
    return Finding(
        check_id="xcto",
        header="X-Content-Type-Options",
        status="pass",
        severity="info",
        title="X-Content-Type-Options Set to nosniff",
        description="MIME-type sniffing is disabled, protecting against MIME-confusion attacks.",
        recommendation="No action required. Keep this header on all responses.",
        evidence=value,
    )


def _check_rp(headers: dict) -> Finding:
    """Check Referrer-Policy header."""
    value = headers.get("Referrer-Policy")
    if value is None:
        return Finding(
            check_id="rp",
            header="Referrer-Policy",
            status="fail",
            severity="low",
            title="Referrer-Policy Header Missing",
            description=(
                "The Referrer-Policy header is not set. Without it, browsers default to sending "
                "full referrer URLs to third-party sites, potentially leaking sensitive URL "
                "parameters and user paths."
            ),
            recommendation=(
                "Add a Referrer-Policy header. Recommended values include 'no-referrer', "
                "'strict-origin', or 'strict-origin-when-cross-origin'."
            ),
            evidence="Header not present",
        )
    value_lower = value.strip().lower()
    if value_lower in ("unsafe-url", "no-referrer-when-downgrade"):
        return Finding(
            check_id="rp",
            header="Referrer-Policy",
            status="warn",
            severity="low",
            title="Referrer-Policy Uses Unsafe Value",
            description=(
                f"Referrer-Policy is set to '{value}', which may send full URLs (including query "
                "strings) to third-party sites. This can expose sensitive data embedded in URLs."
            ),
            recommendation=(
                "Replace with a stricter policy such as 'strict-origin-when-cross-origin', "
                "'strict-origin', or 'no-referrer'."
            ),
            evidence=value,
        )
    return Finding(
        check_id="rp",
        header="Referrer-Policy",
        status="pass",
        severity="info",
        title="Referrer-Policy Header Configured",
        description="A Referrer-Policy header is present with an acceptable value.",
        recommendation="Verify the policy aligns with your application's cross-origin referral needs.",
        evidence=value,
    )


def _check_pp(headers: dict) -> Finding:
    """Check Permissions-Policy header."""
    value = headers.get("Permissions-Policy")
    if value is None:
        return Finding(
            check_id="pp",
            header="Permissions-Policy",
            status="warn",
            severity="low",
            title="Permissions-Policy Header Missing",
            description=(
                "The Permissions-Policy header (formerly Feature-Policy) is not set. Without it, "
                "the browser applies default permissions for powerful features such as camera, "
                "microphone, and geolocation, which may be broader than needed."
            ),
            recommendation=(
                "Add a Permissions-Policy header to explicitly disable or restrict browser "
                "features your site does not use. Example: "
                "'Permissions-Policy: geolocation=(), microphone=(), camera=()'."
            ),
            evidence="Header not present",
        )
    return Finding(
        check_id="pp",
        header="Permissions-Policy",
        status="pass",
        severity="info",
        title="Permissions-Policy Header Present",
        description="A Permissions-Policy header is configured, controlling browser feature access.",
        recommendation=(
            "Review the policy to ensure all unnecessary browser features are explicitly disabled."
        ),
        evidence=value,
    )


def scan_headers(url: str, timeout: int = 10) -> list:
    """Fetch *url* and evaluate the six required HTTP security headers.

    Returns a list of Finding dicts — one per header plus an optional
    redirect-downgrade finding.

    Raises RuntimeError on network failure.
    """
    try:
        session = requests.Session()
        session.max_redirects = 5
        session.headers.update({"User-Agent": "WebSecurityScanner/1.0 (Security Audit Tool)"})
        response = session.get(url, timeout=timeout, verify=True, allow_redirects=True)
    except requests.RequestException as e:
        raise RuntimeError(f"Failed to connect to {url}: {e}") from e

    headers = response.headers
    is_https = url.lower().startswith("https://")

    findings: list = [
        _check_csp(headers),
        _check_hsts(headers, is_https=is_https),
        _check_xfo(headers),
        _check_xcto(headers),
        _check_rp(headers),
        _check_pp(headers),
    ]

    # Redirect downgrade: HTTPS → HTTP
    if is_https and response.url.lower().startswith("http://"):
        findings.append(
            Finding(
                check_id="hsts",
                header="Strict-Transport-Security",
                status="fail",
                severity="high",
                title="HTTPS to HTTP Redirect Detected",
                description=(
                    "The server redirected an HTTPS request to a plain HTTP URL. This exposes "
                    "all subsequent traffic to interception and man-in-the-middle attacks."
                ),
                recommendation=(
                    "Ensure all redirects keep the HTTPS scheme. Configure your web server to "
                    "serve all content over HTTPS and enable HSTS to prevent downgrade attacks."
                ),
                evidence=f"Redirected to: {response.url}",
            )
        )

    return findings


# ── SECTION 4: TLS / HTTPS Certificate Scanner ───────────────────────────────


def scan_tls(url: str, timeout: int = 10) -> list:
    """Check TLS certificate validity and TLS version for *url*.

    Returns a list of Finding dicts.
    """
    parsed = urllib.parse.urlparse(url)

    # 1. HTTP-only: skip TLS checks, return a single warn finding
    if parsed.scheme.lower() == "http":
        return [
            Finding(
                check_id="tls",
                header="TLS/HTTPS",
                status="warn",
                severity="medium",
                title="HTTPS Not Used",
                description=(
                    "The target URL uses HTTP, not HTTPS. TLS certificate checks were skipped."
                ),
                recommendation="Migrate to HTTPS and configure a valid TLS certificate.",
                evidence=url,
            )
        ]

    # 2. Extract hostname and port
    hostname = parsed.hostname or ""
    port = parsed.port or 443

    findings: list = []

    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                raw_cert = ssock.getpeercert(binary_form=True)
                tls_version = ssock.version()

        # 3. Parse certificate with cryptography
        cert = x509.load_der_x509_certificate(raw_cert)

        # 4. Check expiry — handle cryptography >= 42 vs older
        try:
            not_after = cert.not_valid_after_utc  # timezone-aware (cryptography >= 42)
        except AttributeError:
            # Older cryptography: not_valid_after is a naive datetime (UTC)
            naive = cert.not_valid_after
            not_after = naive.replace(tzinfo=timezone.utc)

        now = datetime.now(timezone.utc)
        days_remaining = (not_after - now).days

        if days_remaining < 0:
            findings.append(
                Finding(
                    check_id="tls",
                    header="TLS/HTTPS",
                    status="fail",
                    severity="critical",
                    title="TLS Certificate Expired",
                    description=(
                        f"The TLS certificate expired on {not_after.date().isoformat()}. "
                        "Browsers will reject this certificate, preventing users from accessing "
                        "the site securely."
                    ),
                    recommendation=(
                        "Renew the TLS certificate immediately. Consider using an automated "
                        "certificate manager (e.g. Let's Encrypt with certbot) to avoid future "
                        "expiry."
                    ),
                    evidence=f"Expired: {not_after.isoformat()}",
                )
            )
        elif days_remaining <= 30:
            findings.append(
                Finding(
                    check_id="tls",
                    header="TLS/HTTPS",
                    status="warn",
                    severity="high",
                    title="TLS Certificate Expiring Soon",
                    description=(
                        f"The TLS certificate will expire in {days_remaining} day(s) "
                        f"(on {not_after.date().isoformat()}). Allow time for renewal before "
                        "it lapses."
                    ),
                    recommendation=(
                        "Renew the TLS certificate now. Automate renewal with a tool such as "
                        "certbot to avoid unexpected expiry."
                    ),
                    evidence=f"Expires: {not_after.isoformat()} ({days_remaining} days remaining)",
                )
            )
        else:
            findings.append(
                Finding(
                    check_id="tls",
                    header="TLS/HTTPS",
                    status="pass",
                    severity="info",
                    title="TLS Certificate Valid",
                    description=(
                        f"The TLS certificate is valid and does not expire for "
                        f"{days_remaining} day(s) ({not_after.date().isoformat()})."
                    ),
                    recommendation=(
                        "Continue to monitor certificate expiry. Consider automating renewal."
                    ),
                    evidence=f"Expires: {not_after.isoformat()} ({days_remaining} days remaining)",
                )
            )

        # 5. Check TLS version
        if tls_version in ("TLSv1", "TLSv1.1"):
            findings.append(
                Finding(
                    check_id="tls_version",
                    header="TLS/HTTPS",
                    status="warn",
                    severity="high",
                    title=f"Deprecated TLS Version in Use: {tls_version}",
                    description=(
                        f"The server negotiated {tls_version}, which is deprecated and known "
                        "to have critical weaknesses (BEAST, POODLE). Modern browsers no longer "
                        "support these versions."
                    ),
                    recommendation=(
                        "Disable TLS 1.0 and 1.1 on the server. Configure TLS 1.2 as the minimum "
                        "supported version and prefer TLS 1.3."
                    ),
                    evidence=f"TLS version: {tls_version}",
                )
            )
        elif tls_version == "TLSv1.2":
            findings.append(
                Finding(
                    check_id="tls_version",
                    header="TLS/HTTPS",
                    status="warn",
                    severity="low",
                    title="TLS 1.2 in Use (TLS 1.3 Preferred)",
                    description=(
                        "The server negotiated TLS 1.2, which is still considered acceptable but "
                        "is not the latest version. TLS 1.3 offers improved performance and security."
                    ),
                    recommendation=(
                        "Enable TLS 1.3 support on the server while keeping TLS 1.2 as a fallback "
                        "for older clients."
                    ),
                    evidence=f"TLS version: {tls_version}",
                )
            )
        else:
            # TLSv1.3 or None (unknown — treat as pass)
            findings.append(
                Finding(
                    check_id="tls_version",
                    header="TLS/HTTPS",
                    status="pass",
                    severity="info",
                    title=f"TLS Version Acceptable: {tls_version}",
                    description=(
                        f"The server negotiated {tls_version}, which is the recommended "
                        "version."
                    ),
                    recommendation="No action required. Keep TLS 1.3 enabled.",
                    evidence=f"TLS version: {tls_version}",
                )
            )

    except ssl.SSLError as e:
        return [
            Finding(
                check_id="tls",
                header="TLS/HTTPS",
                status="fail",
                severity="critical",
                title="TLS Certificate Validation Failed",
                description=(
                    "The TLS certificate could not be validated. This may indicate a self-signed "
                    "certificate, an expired certificate, or a hostname mismatch."
                ),
                recommendation=(
                    "Obtain a valid certificate from a trusted Certificate Authority (CA) and "
                    "ensure the certificate's Common Name / SAN matches the hostname."
                ),
                evidence=str(e),
            )
        ]
    except (ConnectionRefusedError, socket.timeout, OSError) as e:
        return [
            Finding(
                check_id="tls",
                header="TLS/HTTPS",
                status="fail",
                severity="high",
                title="TLS Connection Failed",
                description=(
                    "Could not establish a TLS connection to the host. The server may be "
                    "unreachable, the port may be closed, or the connection timed out."
                ),
                recommendation=(
                    "Verify that the server is running and reachable on port 443 (or the "
                    "configured port) and that no firewall is blocking the connection."
                ),
                evidence=str(e),
            )
        ]

    return findings


# ── SECTION 5: CORS Scanner ──────────────────────────────────────────────────


def scan_cors(url: str, timeout: int = 10) -> list:
    """Check the CORS configuration of *url* for common misconfigurations.

    Returns a list with a single Finding summarising the CORS posture.
    """
    probe = "https://attacker-probe.example.com"

    try:
        session = requests.Session()
        session.headers.update({"User-Agent": "WebSecurityScanner/1.0 (Security Audit Tool)"})

        # OPTIONS preflight
        options_resp = session.options(
            url,
            headers={
                "Origin": "https://evil.example.com",
                "Access-Control-Request-Method": "GET",
            },
            timeout=timeout,
            verify=True,
        )

        # GET with reflected-origin probe
        get_resp = session.get(
            url,
            headers={"Origin": probe},
            timeout=timeout,
            verify=True,
        )

    except requests.RequestException as e:
        return [
            Finding(
                check_id="cors",
                header="Access-Control-Allow-Origin",
                status="warn",
                severity="medium",
                title="CORS Check Failed",
                description=str(e),
                recommendation=(
                    "Ensure the target is reachable and review any network or TLS issues "
                    "before interpreting CORS posture."
                ),
                evidence=str(e),
            )
        ]

    acao_options = options_resp.headers.get("Access-Control-Allow-Origin", "")
    acac_options = options_resp.headers.get("Access-Control-Allow-Credentials", "").strip().lower()

    acao_get = get_resp.headers.get("Access-Control-Allow-Origin", "")
    acac_get = get_resp.headers.get("Access-Control-Allow-Credentials", "").strip().lower()

    # Use the most permissive of the two responses for acao/acac
    acao = acao_options if acao_options else acao_get
    acac = acac_options if acac_options == "true" else acac_get

    # Decision logic — most severe condition wins
    if acao == "*" and acac == "true":
        return [
            Finding(
                check_id="cors",
                header="Access-Control-Allow-Origin",
                status="fail",
                severity="critical",
                title="CORS Wildcard with Credentials Enabled",
                description=(
                    "The server returns 'Access-Control-Allow-Origin: *' alongside "
                    "'Access-Control-Allow-Credentials: true'. While browsers block this "
                    "combination per the spec, the configuration signals a critically "
                    "misconfigured CORS policy that should be remediated immediately."
                ),
                recommendation=(
                    "Never combine a wildcard ACAO with credentials. Specify the exact "
                    "trusted origin and set 'Access-Control-Allow-Credentials: true' only "
                    "for that origin."
                ),
                evidence=f"ACAO: {acao}, ACAC: {acac}",
            )
        ]

    if probe in acao_get and acac_get == "true":
        return [
            Finding(
                check_id="cors",
                header="Access-Control-Allow-Origin",
                status="fail",
                severity="critical",
                title="CORS Origin Reflection with Credentials",
                description=(
                    "The server reflects the attacker-supplied Origin header back in "
                    "'Access-Control-Allow-Origin' and also sets "
                    "'Access-Control-Allow-Credentials: true'. This allows any origin to "
                    "make credentialed cross-origin requests, potentially exposing session "
                    "data to malicious sites."
                ),
                recommendation=(
                    "Maintain an explicit allowlist of trusted origins. Never reflect the "
                    "incoming Origin header directly. Pair 'Access-Control-Allow-Credentials: true' "
                    "only with explicitly trusted origins."
                ),
                evidence=f"ACAO: {acao_get}, ACAC: {acac_get}",
            )
        ]

    if probe in acao_get:
        return [
            Finding(
                check_id="cors",
                header="Access-Control-Allow-Origin",
                status="warn",
                severity="high",
                title="CORS Origin Reflection Detected",
                description=(
                    "The server reflects the attacker-supplied Origin header verbatim in "
                    "'Access-Control-Allow-Origin'. While credentials are not currently "
                    "enabled, this configuration can allow unintended cross-origin reads."
                ),
                recommendation=(
                    "Maintain an explicit allowlist of trusted origins instead of reflecting "
                    "the incoming Origin header."
                ),
                evidence=f"ACAO: {acao_get}",
            )
        ]

    if acao == "*":
        return [
            Finding(
                check_id="cors",
                header="Access-Control-Allow-Origin",
                status="warn",
                severity="medium",
                title="CORS Wildcard Origin Allowed",
                description=(
                    "The server returns 'Access-Control-Allow-Origin: *', permitting any origin "
                    "to read the response. This is acceptable for fully public APIs but may be "
                    "overly permissive for endpoints that return user-specific data."
                ),
                recommendation=(
                    "Restrict ACAO to specific trusted origins unless the resource is intentionally "
                    "public. Never use '*' for endpoints accessed with credentials."
                ),
                evidence=f"ACAO: {acao}",
            )
        ]

    return [
        Finding(
            check_id="cors",
            header="Access-Control-Allow-Origin",
            status="pass",
            severity="info",
            title="CORS Configuration Appears Restrictive",
            description=(
                "The server did not reflect arbitrary origins or return a wildcard "
                "'Access-Control-Allow-Origin'. CORS appears to be configured restrictively."
            ),
            recommendation=(
                "Periodically review your CORS policy to ensure only intended origins are "
                "granted cross-origin access."
            ),
            evidence=f"ACAO: {acao_get or '(not present)'}",
        )
    ]


# ── SECTION 6: Scoring Engine ────────────────────────────────────────────────


def _assign_grade(score: int) -> str:
    if score >= 90:
        return "A+"
    if score >= 80:
        return "A"
    if score >= 70:
        return "B"
    if score >= 60:
        return "C"
    if score >= 50:
        return "D"
    return "F"


def calculate_score(findings: list) -> ScoreResult:
    # Step 1: Group findings by check_id; determine worst status per group.
    STATUS_RANK = {"fail": 2, "warn": 1, "pass": 0}
    groups: dict[str, dict] = {}  # check_id -> {"status": worst, "title": first title}
    for f in findings:
        cid = f["check_id"]
        if cid not in groups:
            groups[cid] = {"status": f["status"], "title": f.get("title", "No data")}
        else:
            if STATUS_RANK[f["status"]] > STATUS_RANK[groups[cid]["status"]]:
                groups[cid]["status"] = f["status"]

    # Step 2-3: Compute earned vs possible points using CHECK_WEIGHTS.
    earned = 0
    possible = sum(CHECK_WEIGHTS.values())  # always 100
    score_breakdown = []
    for check_id, max_points in CHECK_WEIGHTS.items():
        if check_id in groups:
            status = groups[check_id]["status"]
            title = groups[check_id]["title"]
        else:
            status = "warn"  # inconclusive
            title = "No data"

        if status == "pass":
            earned_points = max_points
        elif status == "warn":
            earned_points = max_points // 2
        else:  # fail
            earned_points = 0

        earned += earned_points
        score_breakdown.append({
            "check_id": check_id,
            "max_points": max_points,
            "earned_points": earned_points,
            "status": status,
            "title": title,
        })

    # Step 4: Compute final score.
    score = round((earned / possible) * 100)
    score = max(0, min(100, score))

    # Step 5: Count severities across ALL findings.
    severity_counts: dict[str, int] = {
        "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0
    }
    for f in findings:
        sev = f.get("severity", "info")
        if sev in severity_counts:
            severity_counts[sev] += 1

    return ScoreResult(
        score=score,
        grade=_assign_grade(score),
        severity_counts=severity_counts,
        score_breakdown=score_breakdown,
    )


# ── SECTION 7: Report Generators ─────────────────────────────────────────────

HTML_REPORT_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Security Scan Report — {{ scan_target }}</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: -apple-system, 'Segoe UI', system-ui, sans-serif; background: #0d1117; color: #e6edf3; font-size: 14px; line-height: 1.6; padding: 2rem; }
  .container { max-width: 960px; margin: 0 auto; }
  h1 { font-size: 1.8rem; color: #58a6ff; margin-bottom: 0.25rem; }
  h2 { font-size: 1.2rem; color: #8b949e; border-bottom: 1px solid #30363d; padding-bottom: 0.5rem; margin: 1.5rem 0 1rem; }
  .meta { color: #8b949e; font-size: 0.9rem; margin-bottom: 1.5rem; }
  .score-badge { display: inline-block; font-size: 3rem; font-weight: 900; padding: 0.75rem 1.5rem; border-radius: 12px; margin-bottom: 1.5rem; }
  .grade-Aplus { color: #3fb950; background: rgba(63,185,80,0.1); border: 2px solid #3fb950; }
  .grade-A { color: #58a6ff; background: rgba(88,166,255,0.1); border: 2px solid #58a6ff; }
  .grade-B { color: #d29922; background: rgba(210,153,34,0.1); border: 2px solid #d29922; }
  .grade-C { color: #f0883e; background: rgba(240,136,62,0.1); border: 2px solid #f0883e; }
  .grade-D { color: #f85149; background: rgba(248,81,73,0.1); border: 2px solid #f85149; }
  .grade-F { color: #ff4444; background: rgba(255,68,68,0.15); border: 2px solid #ff4444; }
  table { width: 100%; border-collapse: collapse; margin-bottom: 1rem; }
  th { background: #161b22; color: #8b949e; text-align: left; padding: 0.6rem 0.8rem; font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.05em; border-bottom: 2px solid #30363d; }
  td { padding: 0.6rem 0.8rem; border-bottom: 1px solid #21262d; vertical-align: top; }
  tr:hover td { background: #161b22; }
  .status-pass { color: #3fb950; font-weight: 600; }
  .status-warn { color: #d29922; font-weight: 600; }
  .status-fail { color: #f85149; font-weight: 600; }
  .sev-critical { color: #ff4444; font-weight: 700; }
  .sev-high { color: #f85149; font-weight: 700; }
  .sev-medium { color: #f0883e; font-weight: 600; }
  .sev-low { color: #d29922; font-weight: 600; }
  .sev-info { color: #8b949e; }
  .severity-cards { display: flex; gap: 1rem; margin-bottom: 1.5rem; flex-wrap: wrap; }
  .sev-card { flex: 1; min-width: 120px; background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 1rem; text-align: center; }
  .sev-card .count { font-size: 2rem; font-weight: 800; }
  .sev-card .label { font-size: 0.8rem; color: #8b949e; text-transform: uppercase; }
  .small-text { font-size: 0.8rem; color: #8b949e; }
  .disclaimer { background: #161b22; border-left: 3px solid #d29922; padding: 0.75rem 1rem; border-radius: 4px; font-size: 0.85rem; color: #8b949e; margin-top: 2rem; }
  .footer { text-align: center; color: #484f58; font-size: 0.75rem; margin-top: 2rem; padding-top: 1rem; border-top: 1px solid #21262d; }
</style>
</head>
<body>
<div class="container">
  <h1>🔒 Security Scan Report</h1>
  <div class="meta">
    <strong>Target:</strong> {{ scan_target }}<br>
    <strong>Scanned:</strong> {{ scan_timestamp }}<br>
    <strong>Scanner:</strong> WebSecurityScanner v1.0.0
  </div>

  <div class="score-badge grade-{{ grade_class }}">{{ score }}/100 &nbsp; {{ grade }}</div>

  <h2>Severity Summary</h2>
  <div class="severity-cards">
    <div class="sev-card"><div class="count sev-critical">{{ severity_counts.critical }}</div><div class="label">Critical</div></div>
    <div class="sev-card"><div class="count sev-high">{{ severity_counts.high }}</div><div class="label">High</div></div>
    <div class="sev-card"><div class="count sev-medium">{{ severity_counts.medium }}</div><div class="label">Medium</div></div>
    <div class="sev-card"><div class="count sev-low">{{ severity_counts.low }}</div><div class="label">Low</div></div>
  </div>

  <h2>Score Breakdown</h2>
  <table>
    <thead><tr><th>Check</th><th>Status</th><th>Earned</th><th>Max</th></tr></thead>
    <tbody>
    {% for item in score_breakdown %}
    <tr>
      <td>{{ item.title }}</td>
      <td class="status-{{ item.status }}">{{ item.status | upper }}</td>
      <td>{{ item.earned_points }}</td>
      <td>{{ item.max_points }}</td>
    </tr>
    {% endfor %}
    </tbody>
  </table>

  <h2>Findings ({{ findings | length }})</h2>
  <table>
    <thead><tr><th>Severity</th><th>Status</th><th>Header / Check</th><th>Title</th><th>Evidence</th></tr></thead>
    <tbody>
    {% for f in findings %}
    <tr>
      <td class="sev-{{ f.severity }}">{{ f.severity | upper }}</td>
      <td class="status-{{ f.status }}">{{ f.status | upper }}</td>
      <td class="small-text">{{ f.header }}</td>
      <td>{{ f.title }}</td>
      <td class="small-text">{{ f.evidence }}</td>
    </tr>
    {% endfor %}
    </tbody>
  </table>

  <h2>Detailed Findings</h2>
  {% for f in findings %}
  <div style="background:#161b22;border:1px solid #30363d;border-radius:8px;padding:1rem;margin:0.75rem 0;">
    <div style="margin-bottom:0.5rem;">
      <span class="sev-{{ f.severity }}" style="font-size:1.1rem;">{{ f.title }}</span>
      <span class="small-text" style="margin-left:1rem;">{{ f.header }} · <span class="status-{{ f.status }}">{{ f.status | upper }}</span></span>
    </div>
    <div style="margin-bottom:0.4rem;"><strong style="color:#8b949e;">Evidence:</strong> <code style="background:#0d1117;padding:0.1rem 0.4rem;border-radius:4px;font-size:0.85rem;">{{ f.evidence }}</code></div>
    <div style="margin-bottom:0.4rem;color:#c9d1d9;">{{ f.description }}</div>
    <div style="color:#58a6ff;font-size:0.9rem;">💡 {{ f.recommendation }}</div>
  </div>
  {% endfor %}

  <div class="disclaimer">
    ⚠️ <strong>Disclaimer:</strong> This Security Configuration Score reflects the presence and basic configuration of HTTP security headers, TLS certificate validity, and CORS settings at the time of the scan. It does not guarantee that the target is fully secure or free from vulnerabilities. Always consult a qualified security professional for comprehensive assessments.
  </div>

  <div class="footer">Generated by WebSecurityScanner v1.0.0 · For educational and authorised use only</div>
</div>
</body>
</html>"""


def generate_json_report(url: str, findings: list, score_result: ScoreResult) -> bytes:
    report = {
        "scan_target": url,
        "scan_timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "scanner_version": "1.0.0",
        "score": score_result["score"],
        "grade": score_result["grade"],
        "severity_counts": score_result["severity_counts"],
        "score_breakdown": score_result["score_breakdown"],
        "findings": findings,
        "disclaimer": (
            "This Security Configuration Score reflects the presence and basic configuration of "
            "HTTP security headers, TLS certificate validity, and CORS settings at the time of the "
            "scan. It does not guarantee that the target is fully secure or free from vulnerabilities."
        ),
    }
    return json.dumps(report, indent=2, default=str).encode("utf-8")


def generate_html_report(url: str, findings: list, score_result: ScoreResult) -> bytes:
    grade = score_result["grade"]
    grade_class = grade.replace("+", "plus")  # "A+" → "Aplus"
    env = Environment(loader=BaseLoader(), autoescape=True)
    template = env.from_string(HTML_REPORT_TEMPLATE)
    html = template.render(
        scan_target=url,
        scan_timestamp=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        score=score_result["score"],
        grade=grade,
        grade_class=grade_class,
        severity_counts=score_result["severity_counts"],
        score_breakdown=score_result["score_breakdown"],
        findings=findings,
    )
    return html.encode("utf-8")


# ── SECTION 8: Streamlit Dashboard ───────────────────────────────────────────

_CSS = """
<style>
/* Dark cybersecurity theme */
.stApp { background-color: #0d1117; color: #e6edf3; }
.main-header { color: #58a6ff; font-size: 2rem; font-weight: 700; margin-bottom: 0.25rem; }
.sub-header { color: #8b949e; font-size: 1rem; margin-bottom: 1.5rem; }
.score-badge { font-size: 3.5rem; font-weight: 900; text-align: center; padding: 1rem; border-radius: 12px; }
.score-a-plus { color: #3fb950; background: rgba(63,185,80,0.1); border: 2px solid #3fb950; }
.score-a { color: #58a6ff; background: rgba(88,166,255,0.1); border: 2px solid #58a6ff; }
.score-b { color: #d29922; background: rgba(210,153,34,0.1); border: 2px solid #d29922; }
.score-c { color: #f0883e; background: rgba(240,136,62,0.1); border: 2px solid #f0883e; }
.score-d { color: #f85149; background: rgba(248,81,73,0.1); border: 2px solid #f85149; }
.score-f { color: #ff4444; background: rgba(255,68,68,0.15); border: 2px solid #ff4444; }
.severity-critical { color: #ff4444; font-weight: 700; }
.severity-high { color: #f85149; font-weight: 700; }
.severity-medium { color: #f0883e; font-weight: 600; }
.severity-low { color: #d29922; font-weight: 600; }
.severity-info { color: #8b949e; }
.status-pass { color: #3fb950; }
.status-warn { color: #d29922; }
.status-fail { color: #f85149; }
.finding-card { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 1rem; margin: 0.5rem 0; }
.disclaimer { background: #161b22; border-left: 3px solid #d29922; padding: 0.75rem 1rem; border-radius: 4px; font-size: 0.85rem; color: #8b949e; }
</style>
"""


def run_scan(url: str, allowlist: list | None = None) -> dict:
    """Orchestrate the full scan pipeline and return a results dict."""
    validated_url = validate_url(url, allowlist)  # may raise ValueError
    headers_findings = scan_headers(validated_url)
    tls_findings = scan_tls(validated_url)
    cors_findings = scan_cors(validated_url)
    all_findings = headers_findings + tls_findings + cors_findings
    score_result = calculate_score(all_findings)
    return {
        "url": validated_url,
        "findings": all_findings,
        "score_result": score_result,
    }


def _grade_css_class(grade: str) -> str:
    """Map a grade string to a CSS class name for the score badge."""
    return {
        "A+": "score-a-plus",
        "A": "score-a",
        "B": "score-b",
        "C": "score-c",
        "D": "score-d",
        "F": "score-f",
    }.get(grade, "score-f")


def render_score_section(score_result: ScoreResult) -> None:
    """Render the score badge, severity cards, and score breakdown expander."""
    score = score_result["score"]
    grade = score_result["grade"]
    severity_counts = score_result["severity_counts"]
    score_breakdown = score_result["score_breakdown"]

    css_class = _grade_css_class(grade)

    col_badge, col_metrics = st.columns([1, 2])

    with col_badge:
        st.markdown(
            f'<div class="score-badge {css_class}">{score}/100<br/><span style="font-size:1.5rem;">{grade}</span></div>',
            unsafe_allow_html=True,
        )

    with col_metrics:
        m1, m2, m3, m4 = st.columns(4)
        m1.metric("🔴 Critical", severity_counts.get("critical", 0))
        m2.metric("🟠 High", severity_counts.get("high", 0))
        m3.metric("🟡 Medium", severity_counts.get("medium", 0))
        m4.metric("🟢 Low", severity_counts.get("low", 0))

    with st.expander("📊 Score Breakdown"):
        breakdown_rows = []
        for item in score_breakdown:
            breakdown_rows.append({
                "Check": item["check_id"].upper(),
                "Max Points": item["max_points"],
                "Earned": item["earned_points"],
                "Status": item["status"].upper(),
            })
        st.table(breakdown_rows)


def render_findings_section(findings: list) -> None:
    """Render all findings sorted by severity/status inside expanders."""
    st.subheader("🔍 Findings")

    STATUS_ORDER = {"fail": 0, "warn": 1, "pass": 2}
    sorted_findings = sorted(findings, key=lambda f: STATUS_ORDER.get(f["status"], 3))

    STATUS_ICON = {"pass": "✅", "warn": "⚠️", "fail": "❌"}
    SEVERITY_LABEL = {
        "critical": "🔴 CRITICAL",
        "high": "🟠 HIGH",
        "medium": "🟡 MEDIUM",
        "low": "🟢 LOW",
        "info": "⚪ INFO",
    }

    for finding in sorted_findings:
        status = finding["status"]
        severity = finding["severity"]
        icon = STATUS_ICON.get(status, "❓")
        sev_label = SEVERITY_LABEL.get(severity, severity.upper())
        title = finding["title"]

        label = f"{sev_label}  {icon} {title}"
        with st.expander(label):
            st.markdown(
                f'<div class="finding-card">'
                f'<p><strong>Header:</strong> {finding.get("header", "N/A")}</p>'
                f'<p><strong>Evidence:</strong> <code>{finding.get("evidence", "N/A")}</code></p>'
                f'<p><strong>Description:</strong> {finding.get("description", "")}</p>'
                f'<p><strong>Recommendation:</strong> {finding.get("recommendation", "")}</p>'
                f'</div>',
                unsafe_allow_html=True,
            )


def main() -> None:
    """Streamlit dashboard entry point — executed on every rerun."""
    st.set_page_config(
        page_title="Web Security Scanner",
        page_icon="🔒",
        layout="wide",
        initial_sidebar_state="expanded",
    )

    st.markdown(_CSS, unsafe_allow_html=True)

    # ── Sidebar ──────────────────────────────────────────────────────────────
    with st.sidebar:
        st.title("🔒 Web Security Scanner")
        st.markdown(
            "Analyse HTTP security headers, TLS certificates, and CORS configuration "
            "of any publicly reachable website."
        )

        st.markdown("---")
        st.markdown("**─── Allowlist Mode ───**")
        use_allowlist = st.checkbox("Enable allowlist mode")
        allowlist: list | None = None
        if use_allowlist:
            raw = st.text_area(
                "Allowed hostnames (one per line)",
                placeholder="example.com\napi.example.com",
            )
            if raw.strip():
                allowlist = [h.strip() for h in raw.splitlines() if h.strip()]

        st.markdown("---")
        st.markdown("**─── Disclaimer ───**")
        st.markdown(
            '<div class="disclaimer">'
            "This tool is intended for security professionals with explicit authorisation "
            "to test the target. Unauthorised scanning may be illegal. The authors accept "
            "no liability for misuse."
            "</div>",
            unsafe_allow_html=True,
        )

    # ── Main area header ─────────────────────────────────────────────────────
    st.markdown('<p class="main-header">🔒 Web Security Scanner</p>', unsafe_allow_html=True)
    st.markdown(
        '<p class="sub-header">Analyze HTTP security headers, TLS certificates, and CORS configuration</p>',
        unsafe_allow_html=True,
    )

    # ── Input form ───────────────────────────────────────────────────────────
    url_input = st.text_input(
        "Enter website URL",
        placeholder="https://example.com",
        label_visibility="collapsed",
    )
    authorized = st.checkbox("✅ I confirm I have authorization to scan this target")
    scan_clicked = st.button("🔍 Scan Website", disabled=not authorized)

    # ── Scan logic ───────────────────────────────────────────────────────────
    if scan_clicked and url_input:
        try:
            with st.status("Scanning…", expanded=True) as status_box:
                st.write("✅ Validating URL…")
                validated = validate_url(url_input, allowlist)

                st.write("✅ Scanning HTTP security headers…")
                headers_findings = scan_headers(validated)

                st.write("✅ Checking TLS certificate…")
                tls_findings = scan_tls(validated)

                st.write("✅ Analyzing CORS configuration…")
                cors_findings = scan_cors(validated)

                st.write("✅ Calculating security score…")
                all_findings = headers_findings + tls_findings + cors_findings
                score_result = calculate_score(all_findings)
                status_box.update(label="Scan complete ✅", state="complete", expanded=False)

            st.session_state["scan_results"] = {
                "url": validated,
                "findings": all_findings,
                "score_result": score_result,
            }
        except ValueError as e:
            st.error(str(e))
        except RuntimeError as e:
            st.error(str(e))
        except Exception as e:
            st.error(f"Unexpected error: {e}")

    # ── Results rendering ────────────────────────────────────────────────────
    if "scan_results" in st.session_state:
        results = st.session_state["scan_results"]
        scanned_url = results["url"]
        findings = results["findings"]
        score_result = results["score_result"]

        st.markdown("---")
        st.markdown(f"**Scanned:** `{scanned_url}`")

        render_score_section(score_result)
        render_findings_section(findings)

        st.markdown("---")
        st.markdown("**📥 Download Reports**")
        dl_col1, dl_col2 = st.columns(2)
        with dl_col1:
            st.download_button(
                label="📥 Download JSON Report",
                data=generate_json_report(scanned_url, findings, score_result),
                file_name="security_report.json",
                mime="application/json",
            )
        with dl_col2:
            st.download_button(
                label="📄 Download HTML Report",
                data=generate_html_report(scanned_url, findings, score_result),
                file_name="security_report.html",
                mime="text/html",
            )


# ── Streamlit entry point ─────────────────────────────────────────────────────
# Guard: only call main() when Streamlit is actually running the script.
# When imported by pytest, __name__ == "app" and streamlit has no active server,
# so we skip the call. When run via `streamlit run app.py`, __name__ == "__main__"
# OR Streamlit re-executes the module in its own thread where we detect the
# runtime by attempting a lightweight check.
if __name__ != "__main__":
    # Imported as a module (e.g. by pytest) — do not call main()
    pass
else:
    main()
