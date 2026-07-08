# Security Policy

## Supported versions

`seehandshake` follows Semantic Versioning. Security fixes are backported to
the most recent minor release. Older releases receive fixes on a best-effort
basis.

| Version | Supported |
| ------- | --------- |
| 0.1.x   | Yes       |

## Reporting a vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Report vulnerabilities privately by emailing the maintainers at:

    security@seehandshake.invalid

*(Replace with a real contact address before publishing.)*

Please include:

- A description of the vulnerability and its impact.
- Steps to reproduce, or a proof-of-concept.
- Affected version(s).
- Any suggested mitigation, if you have one.

You will receive an acknowledgement within 72 hours. We will keep you informed
of progress toward a fix and coordinate a disclosure timeline with you.

## Scope

`seehandshake` is a passive observer. It does not initiate TLS connections,
does not decrypt traffic, and does not modify packets. Nonetheless, it parses
untrusted input from the network. The parser and reassembly layers are
therefore the primary security surface, and are the focus of any hardening
work.

## Known limitations

- Live capture requires elevated privileges (`CAP_NET_RAW` on Linux, root on
  macOS, Administrator on Windows). Running any privileged binary is a risk
  the operator must weigh. Prefer capabilities over full root where possible.
- The tool has not been audited. Do not rely on it as a security-critical
  monitoring system.

## Disclosure

Once a fix is available, we will publish a security advisory on GitHub and a
release announcement. Credit will be given to the reporter unless anonymity
is requested.
