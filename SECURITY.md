# Security Policy

Security model and vulnerability reporting for FastFetch WebUI v1.0.0.

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.0.x   | yes       |

## Reporting a Vulnerability

Report security issues privately via GitHub security advisories for this
repository. Do not open public issues for suspected vulnerabilities.

Include in your report:

- Affected version
- Steps to reproduce or proof of concept
- Assessed impact

You receive a response within 7 days. Confirmed vulnerabilities are patched
in the next patch release and credited in the changelog if desired.

## Scope and Intended Use

This tool is designed for single-user, local use on a trusted machine:

- The server binds exclusively to loopback addresses (127.0.0.1, ::1)
- The security model assumes the local user is trustworthy
- The security model does not cover multi-user machines or network exposure

Exposing the server to a network is explicitly unsupported. The token
authentication protects against browser-launched attacks (DNS rebinding,
cross-site requests from malicious websites), not against hostile local
users with the same privileges.

## Threat Model

### Attack surface

1. Local HTTP server on the loopback interface
2. Bearer token authentication
3. File operations in ~/.config/fastfetch/
4. Subprocess execution of the fastfetch binary
5. User-supplied input: config content, uploads, drag-and-drop operations

### Mitigations

**Authentication**

- Bearer token, compared constant-time via secrets.compare_digest
- Minimum token length 16 characters
- Token lifetime capped at 24 hours
- Token exists only in process memory; never logged, never written to disk,
  never embedded in generated HTML
- Fail-closed acquisition: env var or TTY prompt, otherwise refusal to start

**Network**

- Loopback-only binding; no listen on external interfaces
- Host header allow-list prevents DNS rebinding, including IPv6 bracket forms
- Rejected requests close the connection (no keep-alive desync)
- Per-IP sliding-window rate limiting: 100 requests per 60 seconds, mutex-protected

**Input validation**

- Filename sanitization: no traversal sequences, strict character whitelist,
  hidden files rejected
- Upload whitelist: extension check plus MIME sniffing (python-magic, optional)
- Size caps: 2 MB images, 50 KB ASCII art, 10 MB request bodies, 100 KB config
- Server-chosen random filenames for uploaded logos

**File operations**

- Atomic writes via temp file, chmod 600, rename
- Directories created with owner-only permissions
- All config mutations serialized under a threading lock

**Subprocess execution**

- fastfetch executed without a shell, argv list only
- Minimal environment: PATH and TERM only
- 5-second timeout
- Output decoded with error replacement to prevent decode crashes

**Browser-facing defenses**

- Content-Security-Policy restricting resource loading
- X-Frame-Options: DENY, X-Content-Type-Options: nosniff
- Referrer-Policy: no-referrer, Cache-Control: no-store
- All user-controlled strings escaped in HTML and attribute contexts

### Residual risks

- The CSP allows inline scripts (required by the single-file, no-dependency
  design). Escaping discipline mitigates injection into generated markup.
- python-magic and cryptography are optional third-party dependencies. If
  unavailable, MIME validation degrades to extension checks and HTTPS is
  disabled.
- A compromised loopback process could interact with the server. This falls
  outside the stated threat model.

## Version History

- 1.0.0: Initial public release. Security model as documented above.
