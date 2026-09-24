import json
import socket
import unittest
from unittest import mock

import site_audit


def resolver_for(*addresses):
    def resolve(host, port, type=socket.SOCK_STREAM):
        return [(socket.AF_INET6 if ":" in address else socket.AF_INET,
                 type, 6 if ":" in address else 0, "", (address, port))
                for address in addresses]
    return resolve


PUBLIC = resolver_for("93.184.216.34")


class TargetValidationTests(unittest.TestCase):
    def test_accepts_public_https_and_pins_resolved_ip(self):
        target = site_audit.validate_target("https://example.com/path?q=1#fragment", PUBLIC)
        self.assertEqual("93.184.216.34", target.ip)
        self.assertEqual("/path?q=1", target.path)
        self.assertNotIn("fragment", target.url)

    def test_rejects_unsupported_protocol_credentials_and_ports(self):
        cases = ["ftp://example.com", "https://user:pass@example.com", "https://example.com:8443"]
        for url in cases:
            with self.subTest(url=url), self.assertRaises(site_audit.AuditError):
                site_audit.validate_target(url, PUBLIC)

    def test_rejects_private_loopback_link_local_and_reserved_resolution(self):
        addresses = ["127.0.0.1", "10.0.0.1", "169.254.1.1", "::1", "192.0.2.1"]
        for address in addresses:
            with self.subTest(address=address), self.assertRaises(site_audit.AuditError):
                site_audit.validate_target("https://example.com", resolver_for(address))

    def test_rejects_hostname_with_any_private_dns_answer(self):
        resolver = resolver_for("93.184.216.34", "127.0.0.1")
        with self.assertRaisesRegex(site_audit.AuditError, "local, private, or reserved"):
            site_audit.validate_target("https://example.com", resolver)

    def test_dns_failure_is_reportable(self):
        def failing_resolver(*args, **kwargs):
            raise socket.gaierror("not found")
        with self.assertRaisesRegex(site_audit.AuditError, "DNS resolution failed"):
            site_audit.validate_target("https://example.com", failing_resolver)

    def test_malformed_bracketed_ipv6_is_reportable(self):
        malformed_urls = ["https://[::1", "https://[invalid]/", "https://example.com:invalid"]
        for url in malformed_urls:
            with self.subTest(url=url), self.assertRaises(site_audit.AuditError):
                site_audit.validate_target(url, PUBLIC)

    def test_audit_converts_malformed_url_to_json_error(self):
        report = site_audit.audit("https://[::1", resolver=PUBLIC)
        self.assertTrue(report["errors"])
        json.dumps(report)


class FetchTests(unittest.TestCase):
    def test_same_origin_relative_redirect_is_revalidated_and_followed(self):
        requests = []
        def transport(target, timeout, max_bytes):
            requests.append((target.hostname, target.path, target.ip))
            if target.path == "/":
                return 302, {"location": "/home"}, b""
            return 200, {"content-type": "text/html"}, b"ok"

        result = site_audit.fetch_homepage("https://example.com", resolver=PUBLIC, transport=transport)
        self.assertEqual("https://example.com/home", result[0])
        self.assertEqual([("example.com", "/", "93.184.216.34"),
                          ("example.com", "/home", "93.184.216.34")], requests)

    def test_public_external_host_redirect_is_rejected_before_resolution_or_request(self):
        requested = []
        resolved = []
        def resolver(host, port, type=socket.SOCK_STREAM):
            resolved.append(host)
            return PUBLIC(host, port, type)
        def transport(target, timeout, max_bytes):
            requested.append(target.hostname)
            return 302, {"location": "https://www.example.com/"}, b""

        with self.assertRaisesRegex(site_audit.AuditError, "original scheme and hostname"):
            site_audit.fetch_homepage("https://example.com", resolver=resolver, transport=transport)
        self.assertEqual(["example.com"], requested)
        self.assertEqual(["example.com"], resolved)

    def test_https_to_http_redirect_is_rejected_before_next_request(self):
        requested = []
        def transport(target, timeout, max_bytes):
            requested.append(target.url)
            return 302, {"location": "http://example.com/"}, b""

        with self.assertRaisesRegex(site_audit.AuditError, "original scheme and hostname"):
            site_audit.fetch_homepage("https://example.com", resolver=PUBLIC, transport=transport)
        self.assertEqual(["https://example.com"], requested)

    def test_private_redirect_is_rejected_before_request(self):
        requested = []
        def resolver(host, port, type=socket.SOCK_STREAM):
            address = "127.0.0.1" if host == "localhost" else "93.184.216.34"
            return resolver_for(address)(host, port, type)
        def transport(target, timeout, max_bytes):
            requested.append(target.hostname)
            return 302, {"location": "http://localhost/secret"}, b""

        with self.assertRaises(site_audit.AuditError):
            site_audit.fetch_homepage("https://example.com", resolver=resolver, transport=transport)
        self.assertEqual(["example.com"], requested)

    def test_redirect_limit_is_bounded(self):
        def transport(target, timeout, max_bytes):
            return 302, {"location": "/again"}, b""
        with self.assertRaisesRegex(site_audit.AuditError, "Redirect limit"):
            site_audit.fetch_homepage("https://example.com", max_redirects=1,
                                      resolver=PUBLIC, transport=transport)

    @mock.patch("site_audit.http.client.HTTPConnection")
    def test_http_transport_connects_to_pinned_ip_and_bounds_read(self, connection_class):
        response = connection_class.return_value.getresponse.return_value
        response.status = 200
        response.getheaders.return_value = [("Content-Type", "text/html")]
        response.read.return_value = b"ok"
        target = site_audit.validate_target("http://example.com", PUBLIC)

        status, headers, body = site_audit.fetch_once(target, 2, 10)

        connection_class.assert_called_once_with("93.184.216.34", 80, timeout=2)
        connection_class.return_value.request.assert_called_once()
        self.assertEqual(200, status)
        self.assertEqual(b"ok", body)
        response.read.assert_called_once_with(11)

    @mock.patch("site_audit.http.client.HTTPConnection")
    def test_oversized_response_fails_closed(self, connection_class):
        response = connection_class.return_value.getresponse.return_value
        response.status = 200
        response.getheaders.return_value = []
        response.read.return_value = b"123456"
        target = site_audit.validate_target("http://example.com", PUBLIC)
        with self.assertRaisesRegex(site_audit.AuditError, "byte limit"):
            site_audit.fetch_once(target, 2, 5)


class InspectionTests(unittest.TestCase):
    def test_reports_actionable_header_html_and_tls_findings(self):
        def transport(target, timeout, max_bytes):
            return 200, {"content-type": "text/html", "server": "Example/1.0"}, (
                b'<html><script src="http://cdn.example/a.js"></script></html>')
        def tls(target):
            return {"checked": True, "days_remaining": 10}, [
                site_audit._finding("tls-certificate-expiry", "medium", "TLS certificate expires soon",
                                    "10 days", "Renew certificate.")]

        report = site_audit.audit("https://example.com", resolver=PUBLIC,
                                  transport=transport, tls_inspector=tls)
        identifiers = {finding["id"] for finding in report["findings"]}
        self.assertTrue({"missing-content-security-policy", "missing-hsts",
                         "active-mixed-content", "server-header-disclosure",
                         "tls-certificate-expiry"}.issubset(identifiers))
        self.assertEqual([], report["errors"])

    def test_reports_password_form_on_http(self):
        findings, notes = site_audit.inspect_html(
            b'<form><input type="password"></form>', {"content-type": "text/html"}, "http")
        self.assertEqual("password-form-over-http", findings[0]["id"])
        self.assertEqual([], notes)

    def test_http_anchor_is_not_active_mixed_content(self):
        findings, notes = site_audit.inspect_html(
            b'<a href="http://example.net/page">Read more</a>',
            {"content-type": "text/html"}, "https")
        self.assertEqual([], findings)
        self.assertEqual([], notes)

    def test_http_canonical_is_ignored_but_stylesheet_is_active_mixed_content(self):
        findings, _ = site_audit.inspect_html(
            (b'<link rel="canonical" href="http://example.com/page">'
             b'<link rel="stylesheet" href="http://cdn.example/site.css">'),
            {"content-type": "text/html"}, "https")
        self.assertEqual(1, len(findings))
        self.assertEqual("active-mixed-content", findings[0]["id"])
        self.assertEqual("http://cdn.example/site.css", findings[0]["evidence"])

    def test_http_script_is_active_mixed_content(self):
        findings, _ = site_audit.inspect_html(
            b'<script src="http://cdn.example/app.js"></script>',
            {"content-type": "text/html"}, "https")
        self.assertEqual(["active-mixed-content"], [finding["id"] for finding in findings])

    def test_non_html_response_records_skipped_limit(self):
        findings, notes = site_audit.inspect_html(b"data", {"content-type": "image/png"}, "https")
        self.assertEqual([], findings)
        self.assertIn("not HTML", notes[0])

    def test_audit_reports_network_failure_as_json_compatible_error(self):
        def transport(*args):
            raise site_audit.AuditError("HTTP request failed: timeout")
        report = site_audit.audit("https://example.com", resolver=PUBLIC, transport=transport)
        self.assertEqual(["HTTP request failed: timeout"], report["errors"])
        self.assertIsNone(report["status_code"])
        json.dumps(report)

    def test_main_emits_json_and_nonzero_for_invalid_target(self):
        with mock.patch("site_audit.audit", return_value={"errors": ["unsafe"]}), \
             mock.patch("sys.stdout") as stdout:
            self.assertEqual(1, site_audit.main(["http://localhost"]))
            self.assertTrue(stdout.write.called)


if __name__ == "__main__":
    unittest.main()
