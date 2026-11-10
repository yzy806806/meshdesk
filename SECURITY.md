# Security Policy

## Supported versions

Only the latest release receives security fixes. MeshDesk is pre-1.0 in terms of
API stability promises; there are no long-term-support branches.

| Version | Supported |
|---------|-----------|
| latest release (v2.x) | ✅ |
| anything older | ❌ |

## Reporting a vulnerability

Please **do not open a public issue** for security problems.

Use GitHub's private reporting channel:
<https://github.com/yzy806806/meshdesk/security/advisories/new>

Include, where you can:

- affected version and component (Reality handshake, PunchDataplane, TUN
  forwarder, Web UI, WebSSH, join/onboarding, file transfer, …);
- the impact you believe it has, and who can trigger it (a mesh peer, an
  arbitrary network host, a Web UI user);
- a minimal reproduction — a packet capture, a config, or a test that fails.

You will get an acknowledgement, and a fix or an explanation of why the
behaviour is intended, in the advisory thread. Credit is given unless you ask
otherwise.

## Threat model

What MeshDesk does and does not defend against is documented in
[THREAT_MODEL.md](THREAT_MODEL.md) — read it before reporting, since several
"missing" protections there are deliberate (for example: the mesh trusts peers
that hold a valid key, and the TUN device is not a sandbox boundary).

## Scope notes

- **In scope**: memory-safety-adjacent panics reachable over the wire, auth
  bypass in the Web UI / WebSSH / join flows, capability-scope escapes (a peer
  reading or writing beyond its granted capability), remote DoS in the
  handshake or data plane.
- **Out of scope**: findings that require local root, findings that require
  already holding a valid mesh key *and* exceeding documented capability
  grants (that is a peer-misbehaviour report, still welcome but not a CVE),
  and dependency advisories with no reachable call path (state the call path
  in the report if you believe there is one).

## Dependencies

Dependency advisories are tracked via Dependabot and audited for
**reachability** before they are treated as incidents: a flagged module whose
vulnerable packages are not linked into the binary is reported as tech debt,
not as an exploitable issue. See `.github/dependabot.yml`.
