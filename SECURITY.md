# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.x     | :white_check_mark: |

## Reporting a Vulnerability

If you discover a security vulnerability in T3MP3ST, please report it responsibly:

1. **Do NOT** open a public GitHub issue for security vulnerabilities.
2. **Primary channel — GitHub private security advisory.** Open the repository's
   **Security** tab and click **"Report a vulnerability"**, or go directly to
   [`/security/advisories/new`](../../security/advisories/new). This creates a
   private advisory visible only to you and the maintainers — no email inbox is
   required, and it works from day one on a public repo.
3. **Fallback channel.** If the Security tab is unavailable to you, open a public
   issue that contains **only** the sentence "Requesting a private security
   contact" (no vulnerability details) and a maintainer will open a private
   advisory to continue the conversation.
4. Include detailed steps to reproduce the vulnerability in the private advisory.
5. Allow reasonable time for the issue to be addressed before public disclosure.

## Security Considerations

### Authorized Use Only

T3MP3ST is a security testing framework designed for **authorized penetration testing and red team operations only**. Before using this tool:

- Obtain explicit written authorization from the system owner
- Define clear scope and rules of engagement
- Ensure compliance with applicable laws and regulations
- Document all testing activities

See [docs/SCOPE_AND_AUTHORIZATION.md](docs/SCOPE_AND_AUTHORIZATION.md) for the working model used by the API and UI: human intent, scope receipts, tool gates, evidence, findings, retests, and accepted memory.

### API Key Security

- Never commit API keys to version control
- Use environment variables for all sensitive credentials
- Rotate API keys regularly
- Use separate keys for development and production

### Payload Database

The framework includes comprehensive payload databases for educational and testing purposes:

- SQL injection payloads
- XSS payloads
- SSTI payloads
- Command injection payloads
- XXE payloads

These payloads are intended for:
- Authorized security testing
- Security research
- Educational purposes
- CTF competitions

### Data Handling

When using T3MP3ST:

- Do not exfiltrate real sensitive data
- Use test/dummy data for demonstrations
- Properly dispose of any captured credentials after testing
- Follow data protection regulations (GDPR, CCPA, etc.)

### Network Security

- Test only against authorized targets
- Use isolated networks when possible
- Be aware of potential lateral impact
- Monitor for unintended effects

## Known Limitations

### Development Dependencies

`npm audit` currently reports **0 vulnerabilities** (verified 2026-07-02). Development
dependencies (build/test tooling such as the bundler) are not part of the production
runtime regardless. Maintainers should re-run `npm audit` before each release tag.

### Real Functionality

All core arsenal tools perform **real operations** (not simulations):

| Tool | Implementation |
|------|----------------|
| Port scanning | Real TCP connect scans via Node.js `net` module |
| DNS lookup | Real DNS resolution via Node.js `dns` module |
| Subdomain enumeration | Real DNS lookups for each subdomain candidate |
| Directory bruteforce | Real HTTP requests to discover paths |
| Technology detection | Real HTTP fingerprinting of headers/content |
| XSS scanning | Real payload injection with reflection detection |
| SQL injection scanning | Real error-based and boolean-based detection |
| SSL/TLS scanning | Real TLS connections via Node.js `tls` module |
| WHOIS lookup | Real WHOIS queries via TCP port 43 |
| Password spraying | Real HTTP POST requests to login endpoints |
| Hash cracking | Real dictionary attacks using `crypto` module |

**Note:** Only use these tools against systems you have explicit authorization to test.

## Security Best Practices

1. **Run in isolated environments** - Use VMs or containers
2. **Network segmentation** - Test networks should be isolated
3. **Logging** - Maintain detailed logs of all testing activities
4. **Authorization documentation** - Keep copies of all authorizations
5. **Scope adherence** - Never exceed authorized scope

## Compliance

T3MP3ST usage should comply with:

- Computer Fraud and Abuse Act (CFAA)
- General Data Protection Regulation (GDPR)
- PCI DSS (for payment card environments)
- HIPAA (for healthcare environments)
- Local and international cybersecurity laws

## Contact

Report vulnerabilities **privately** via the repository's **GitHub Security Advisories**
("Report a vulnerability" under the **Security** tab) — this keeps the report confidential
until a fix ships. Please do **not** open a public issue for a security problem.

Target response: acknowledgement within **3 business days**, and a remediation plan within
**30 days** of a confirmed report.
