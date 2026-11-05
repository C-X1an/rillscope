# Security policy

RillScope is experimental. It is not an audited database, hostile-code sandbox or production authorization service. Read THREAT_MODEL.md and LIMITATIONS.md before use. The supported boundary is untrusted restricted query syntax under trusted local host configuration and immutable catalog data.

Do not expose the CLI's catalog/context paths directly to an untrusted agent. Do not use real confidential datasets for the public demo. Do not treat logical work/memory budgets as OS-level containment. No guarantee of timing secrecy, statistical inference resistance or multi-user process isolation is made.

Report suspected vulnerabilities privately through GitHub private vulnerability reporting when enabled on the repository. Until that is enabled, do not post sensitive details in public issues; use a maintainer-designated private contact configured at release. No personal email address is embedded from the resume. Public bug reports may contain synthetic semantic failures without secrets.

Supported versions: unreleased development only until a tested release exists. Security fixes will identify affected versions, test evidence and residual risks; no response-time SLA is promised.

For contributors: never add credentials, employer data, unsafe first-party Rust, untrusted PR secrets, arbitrary query filesystem/network features, or tests that silently skip a failing security criterion. Follow CONTRIBUTING.md and the locked acceptance contract.
