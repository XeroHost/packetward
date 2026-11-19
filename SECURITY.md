# Security policy

## Supported versions
PacketWard is pre-1.0. Security fixes go to the latest release (stable channel) and to `main`.

## Reporting a vulnerability
Please **do not open a public issue** for security problems.

Use GitHub's private vulnerability reporting: open the repository's **Security** tab →
**Report a vulnerability** (<https://github.com/XeroHost/packetward/security/advisories/new>).
Include the PacketWard version, Windows version, what you did, what you expected and what happened. If the issue
involves a crafted IPC message, packet capture or blocklist file, attach it (it stays private).

A dedicated security email address will be published here once it exists (placeholder: `security@REPLACE-ME`).

## What to expect
- Acknowledgement within a few days; a fix or a mitigation plan for confirmed issues, coordinated with you before
  any public disclosure.
- Credit in the release notes if you want it.

## Scope notes
- The agent runs as `LocalSystem`; the pipe ACL (SYSTEM, Administrators and the `PacketWard Operators` group) is a
  security boundary. Bypasses of that ACL, of the Guardian's protected set, of the signature check on blocklists or
  of the updater signature are in scope and high severity.
- PacketWard cannot stop a volumetric DDoS that saturates the uplink; that is a documented limitation, not a bug.
