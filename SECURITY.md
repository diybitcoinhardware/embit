# Security Policy

## Supported Versions

Security fixes are provided for the latest PyPI release line.

| Version | Supported |
| --- | --- |
| 0.8.x | yes |
| < 0.8.0 | no |

## Reporting a Vulnerability

Please report vulnerabilities using GitHub private vulnerability reporting:

- <https://github.com/diybitcoinhardware/embit/security/advisories/new>

Do not open public issues for security-sensitive reports.

Include:

- affected version(s)
- impact and attack prerequisites
- clear reproduction steps or proof of concept
- any proposed mitigation

## Response Expectations

- Initial acknowledgement target: within 3 business days
- Triage target (severity and scope): within 7 business days
- Ongoing updates: at least weekly until resolution

## Disclosure Expectations

- Keep details private until maintainers publish a fix or mitigation.
- Coordinate public disclosure timing with maintainers.
- For supply-chain incidents, assume CI and maintainer credentials may be impacted until proven otherwise.

## Release Integrity Notes

- Releases are expected to be built in GitHub Actions and published via PyPI Trusted Publisher.
- Maintainers verify artifact hashes, attestations, and PyPI metadata after publish (see `RELEASING.md`).
