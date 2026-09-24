# Passive Website Auditor

A small Python standard-library CLI that passively inspects one explicitly supplied HTTP(S) homepage. It reports selected response-header, HTML, and TLS certificate signals as JSON without submitting forms or attempting exploitation.

## Usage

Only audit systems you own or are explicitly authorized to assess.

```bash
python site_audit.py https://www.example.com/
```

Exit status is `0` when the bounded audit completes and `1` when a target, network, HTTP, or TLS error is reported. Errors are included in the JSON output rather than emitted as tracebacks.

Run deterministic tests (they use fake or mocked networking and make no live requests):

```bash
PYTHONDONTWRITEBYTECODE=1 python -m unittest discover -s tests -v
```

## Safety boundaries

- Makes a bounded `GET` request to the supplied homepage and follows at most three same-origin redirects.
- Rejects redirects to a different hostname or scheme before resolving or requesting them, including public external hosts and HTTPS-to-HTTP downgrades. Same-origin relative redirects remain supported.
- Does not crawl links, submit forms, send payloads, fuzz, authenticate, scan ports, or deliberately navigate to third-party resources found in HTML.
- Accepts only HTTP on port 80 and HTTPS on port 443.
- Rejects destinations when any DNS result is local, private, link-local, reserved, multicast, or otherwise non-global.
- Revalidates every redirect and connects to a previously validated IP address, while preserving the hostname for HTTP `Host` and TLS SNI/certificate verification. This prevents a second DNS lookup from silently changing the destination.
- Uses a five-second socket timeout, a 1,000,000-byte response limit, and a three-redirect limit.

## Report and limitations

The report includes the final URL, status, redirect chain, actionable findings with evidence and remediation, TLS certificate expiry health, errors, and enforced limits. Header checks cover CSP, HSTS, `X-Content-Type-Options`, `Referrer-Policy`, and `Permissions-Policy`; HTML checks are limited to obvious password-over-HTTP and mixed-content hints.

This is a narrow snapshot, not a vulnerability scanner. It does not execute JavaScript, inspect linked pages or resources, validate application behavior, analyze complete CSP quality, or prove the absence of vulnerabilities. DNS and network policy can also block otherwise legitimate destinations. A clean report is not proof that a site is secure.

## Built with Gentle-AI

<a href="https://github.com/Gentleman-Programming/gentle-ai">
  <img width="220" src="https://raw.githubusercontent.com/Gentleman-Programming/gentle-ai/main/docs/assets/brand/built-with-gentle-ai.png" alt="Built with Gentle-AI" />
</a>
