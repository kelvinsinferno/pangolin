# Security Policy

Pangolin is in PoC stage. Do not use with real credentials.

## Reporting vulnerabilities

For PoC-stage security issues, open a GitHub issue with the
security label. For vulnerabilities discovered after MVP-3
(when external audit is mandatory per master plan §9.1), follow
the responsible-disclosure process documented at that point.

## Scope

This repository covers the Rust core + CLI + RevisionLogV0
contract. Future SDKs, hardware integrations, and mobile shells
will land in their own repositories or directories.

## Known limitations

See THREAT_MODEL.md (28 enumerated rows) and POC_README.md's
"PoC limitations" section. The PoC ships with documented gaps
that MVP-1+ closes.

## License

AGPL-3.0-or-later for the core. See LICENSE and
LICENSE-RATIONALE.md.
