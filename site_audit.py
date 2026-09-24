#!/usr/bin/env python3
"""Bounded, passive security audit for one explicitly supplied homepage."""

from __future__ import annotations

import argparse
import datetime as dt
import http.client
import ipaddress
import json
import re
import socket
import ssl
import sys
from dataclasses import dataclass
from html.parser import HTMLParser
from typing import Callable
from urllib.parse import urljoin, urlsplit

MAX_REDIRECTS = 3
MAX_RESPONSE_BYTES = 1_000_000
DEFAULT_TIMEOUT = 5.0
ALLOWED_PORTS = {"http": {80}, "https": {443}}
USER_AGENT = "PassiveWebsiteAuditor/1.0"


class AuditError(Exception):
    """A safe, reportable audit failure."""


@dataclass(frozen=True)
class ValidatedTarget:
    url: str
    scheme: str
    hostname: str
    port: int
    path: str
    ip: str


class _HTMLHints(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.password_form = False
        self.mixed_content: list[str] = []
        self._form_depth = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = {key.lower(): value for key, value in attrs if value is not None}
        if tag.lower() == "form":
            self._form_depth += 1
        elif tag.lower() == "input" and self._form_depth and values.get("type", "").lower() == "password":
            self.password_form = True
        normalized_tag = tag.lower()
        active_resource_attributes = {
            "script": "src",
            "iframe": "src",
            "embed": "src",
            "object": "data",
        }
        attribute = active_resource_attributes.get(normalized_tag)
        if normalized_tag == "link" and "stylesheet" in values.get("rel", "").lower().split():
            attribute = "href"
        value = values.get(attribute, "") if attribute else ""
        if value.lower().startswith("http://"):
            self.mixed_content.append(value[:200])

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "form" and self._form_depth:
            self._form_depth -= 1


def _is_public_ip(address: str) -> bool:
    ip = ipaddress.ip_address(address)
    return ip.is_global and not any(
        (ip.is_private, ip.is_loopback, ip.is_link_local, ip.is_multicast,
         ip.is_reserved, ip.is_unspecified)
    )


def validate_target(
    url: str,
    resolver: Callable[..., list[tuple]] = socket.getaddrinfo,
) -> ValidatedTarget:
    try:
        parsed = urlsplit(url)
        hostname = parsed.hostname
        username = parsed.username
        password = parsed.password
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
    except ValueError as exc:
        raise AuditError("Invalid URL") from exc
    if parsed.scheme not in ALLOWED_PORTS:
        raise AuditError("Only http and https URLs are allowed")
    if not hostname or username or password:
        raise AuditError("URL must contain a hostname and no credentials")
    if port not in ALLOWED_PORTS[parsed.scheme]:
        raise AuditError(f"Port {port} is not allowed for {parsed.scheme}")
    try:
        records = resolver(hostname, port, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise AuditError(f"DNS resolution failed: {exc}") from exc
    addresses = sorted({record[4][0] for record in records})
    if not addresses:
        raise AuditError("DNS resolution returned no addresses")
    invalid = [address for address in addresses if not _is_public_ip(address)]
    if invalid:
        raise AuditError("Target resolves to a local, private, or reserved address")
    # Pin one already validated address. The transport never resolves the hostname again.
    ip = addresses[0]
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    try:
        normalized = parsed._replace(fragment="").geturl()
    except ValueError as exc:
        raise AuditError("Invalid URL") from exc
    return ValidatedTarget(normalized, parsed.scheme, hostname, port, path, ip)


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, target: ValidatedTarget, timeout: float) -> None:
        super().__init__(target.hostname, target.port, timeout=timeout,
                         context=ssl.create_default_context())
        self._validated_ip = target.ip

    def connect(self) -> None:
        sock = socket.create_connection((self._validated_ip, self.port), self.timeout)
        self.sock = self._context.wrap_socket(sock, server_hostname=self.host)


def _host_header(target: ValidatedTarget) -> str:
    default = (target.scheme == "https" and target.port == 443) or (
        target.scheme == "http" and target.port == 80)
    host = f"[{target.hostname}]" if ":" in target.hostname else target.hostname
    return host if default else f"{host}:{target.port}"


def fetch_once(target: ValidatedTarget, timeout: float, max_bytes: int) -> tuple[int, dict[str, str], bytes]:
    if target.scheme == "https":
        connection: http.client.HTTPConnection = _PinnedHTTPSConnection(target, timeout)
    else:
        connection = http.client.HTTPConnection(target.ip, target.port, timeout=timeout)
    try:
        connection.request("GET", target.path, headers={
            "Host": _host_header(target), "User-Agent": USER_AGENT,
            "Accept": "text/html,application/xhtml+xml",
        })
        response = connection.getresponse()
        body = response.read(max_bytes + 1)
        if len(body) > max_bytes:
            raise AuditError(f"Response exceeds {max_bytes} byte limit")
        headers = {name.lower(): value for name, value in response.getheaders()}
        return response.status, headers, body
    except (OSError, ssl.SSLError, http.client.HTTPException) as exc:
        raise AuditError(f"HTTP request failed: {exc}") from exc
    finally:
        connection.close()


def fetch_homepage(
    url: str,
    timeout: float = DEFAULT_TIMEOUT,
    max_bytes: int = MAX_RESPONSE_BYTES,
    max_redirects: int = MAX_REDIRECTS,
    resolver: Callable[..., list[tuple]] = socket.getaddrinfo,
    transport: Callable[[ValidatedTarget, float, int], tuple[int, dict[str, str], bytes]] = fetch_once,
) -> tuple[str, int, dict[str, str], bytes, list[str]]:
    current = url
    redirects: list[str] = []
    original_target: ValidatedTarget | None = None
    for attempt in range(max_redirects + 1):
        target = validate_target(current, resolver)
        if original_target is None:
            original_target = target
        status, headers, body = transport(target, timeout, max_bytes)
        if status not in {301, 302, 303, 307, 308}:
            return target.url, status, headers, body, redirects
        location = headers.get("location")
        if not location:
            raise AuditError("Redirect response has no Location header")
        if attempt == max_redirects:
            raise AuditError(f"Redirect limit of {max_redirects} exceeded")
        try:
            next_url = urljoin(target.url, location)
            next_parsed = urlsplit(next_url)
            next_hostname = next_parsed.hostname
        except ValueError as exc:
            raise AuditError("Invalid redirect URL") from exc
        if (next_parsed.scheme != original_target.scheme or
                next_hostname != original_target.hostname):
            raise AuditError("Redirect must keep the original scheme and hostname")
        validate_target(next_url, resolver)  # Reject unsafe redirects before the next request.
        redirects.append(next_url)
        current = next_url
    raise AuditError("Redirect processing failed")


def _finding(identifier: str, severity: str, title: str, evidence: str, remediation: str) -> dict[str, str]:
    return {"id": identifier, "severity": severity, "title": title,
            "evidence": evidence, "remediation": remediation}


def inspect_headers(headers: dict[str, str], scheme: str) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    checks = [
        ("content-security-policy", "missing-content-security-policy", "Content Security Policy is missing",
         "Define a restrictive Content-Security-Policy appropriate for the application."),
        ("x-content-type-options", "missing-nosniff", "X-Content-Type-Options is missing",
         "Set X-Content-Type-Options: nosniff."),
        ("referrer-policy", "missing-referrer-policy", "Referrer-Policy is missing",
         "Set a restrictive Referrer-Policy such as strict-origin-when-cross-origin."),
        ("permissions-policy", "missing-permissions-policy", "Permissions-Policy is missing",
         "Set Permissions-Policy to disable browser capabilities the site does not use."),
    ]
    for header, identifier, title, remediation in checks:
        if header not in headers:
            findings.append(_finding(identifier, "medium" if header == "content-security-policy" else "low",
                                     title, f"Response did not include {header}", remediation))
    if scheme == "https" and "strict-transport-security" not in headers:
        findings.append(_finding("missing-hsts", "medium", "HSTS is missing",
                                 "HTTPS response did not include strict-transport-security",
                                 "Set Strict-Transport-Security after confirming all subdomains support HTTPS."))
    if "server" in headers:
        findings.append(_finding("server-header-disclosure", "info", "Server header is exposed",
                                 headers["server"][:200], "Remove unnecessary product and version details."))
    return findings


def inspect_html(body: bytes, headers: dict[str, str], scheme: str) -> tuple[list[dict[str, str]], list[str]]:
    content_type = headers.get("content-type", "")
    if "html" not in content_type.lower():
        return [], ["HTML hints skipped because the response Content-Type was not HTML."]
    text = body.decode("utf-8", errors="replace")
    parser = _HTMLHints()
    parser.feed(text)
    findings: list[dict[str, str]] = []
    if scheme == "http" and parser.password_form:
        findings.append(_finding("password-form-over-http", "high", "Password field served over HTTP",
                                 "HTML contains a password input on an unencrypted page",
                                 "Serve authentication pages exclusively over HTTPS."))
    if scheme == "https" and parser.mixed_content:
        findings.append(_finding("active-mixed-content", "medium", "HTTP resources referenced from HTTPS",
                                 ", ".join(parser.mixed_content[:3]),
                                 "Load page resources over HTTPS or use same-origin relative URLs."))
    return findings, []


def inspect_tls(target: ValidatedTarget, timeout: float = DEFAULT_TIMEOUT) -> tuple[dict, list[dict[str, str]]]:
    if target.scheme != "https":
        return {"checked": False, "reason": "Target uses HTTP"}, []
    connection = _PinnedHTTPSConnection(target, timeout)
    try:
        connection.connect()
        certificate = connection.sock.getpeercert() if connection.sock else {}
        expires_text = certificate.get("notAfter")
        expires = ssl.cert_time_to_seconds(expires_text) if expires_text else None
        days = int((expires - dt.datetime.now(dt.timezone.utc).timestamp()) / 86400) if expires else None
        result = {"checked": True, "expires_at": expires_text, "days_remaining": days}
        findings = []
        if days is not None and days < 30:
            severity = "high" if days < 0 else "medium"
            findings.append(_finding("tls-certificate-expiry", severity, "TLS certificate expires soon",
                                     f"Certificate has {days} days remaining",
                                     "Renew and deploy the certificate before expiration."))
        return result, findings
    except (OSError, ssl.SSLError, ValueError) as exc:
        raise AuditError(f"TLS certificate check failed: {exc}") from exc
    finally:
        connection.close()


def audit(url: str, resolver: Callable[..., list[tuple]] = socket.getaddrinfo,
          transport: Callable = fetch_once, tls_inspector: Callable = inspect_tls) -> dict:
    report = {
        "target": url, "final_url": None, "status_code": None, "redirects": [],
        "findings": [], "tls": {"checked": False}, "errors": [],
        "limits": {
            "homepage_only": True, "max_redirects": MAX_REDIRECTS,
            "max_response_bytes": MAX_RESPONSE_BYTES, "timeout_seconds": DEFAULT_TIMEOUT,
            "allowed_ports": {"http": [80], "https": [443]},
            "notice": "No findings does not prove the site is secure.",
        },
    }
    try:
        final_url, status, headers, body, redirects = fetch_homepage(
            url, resolver=resolver, transport=transport)
        report.update(final_url=final_url, status_code=status, redirects=redirects)
        target = validate_target(final_url, resolver)
        report["findings"].extend(inspect_headers(headers, target.scheme))
        html_findings, notes = inspect_html(body, headers, target.scheme)
        report["findings"].extend(html_findings)
        report["limits"]["notes"] = notes
        try:
            report["tls"], tls_findings = tls_inspector(target)
            report["findings"].extend(tls_findings)
        except AuditError as exc:
            report["errors"].append(str(exc))
    except AuditError as exc:
        report["errors"].append(str(exc))
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("url", help="Explicitly authorized HTTP(S) homepage URL")
    args = parser.parse_args(argv)
    report = audit(args.url)
    json.dump(report, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")
    return 1 if report["errors"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
