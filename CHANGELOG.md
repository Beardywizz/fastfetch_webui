All notable changes to FastFetch WebUI will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-10-05

Initial public release. Scratch-style block builder edition.

### Added

- Self-contained single-file Python web UI for fastfetch configuration
- Scratch-style block builder interface with drag-and-drop module ordering
- Active/Parked module stacks (activation/deactivation via toggle switches)
- Full module object preservation (key/keyColor/format survive all operations)
- Timestamped automatic backups before every save/restore/change (FIFO, max 50)
- Collision-proof backup naming for simultaneous saves within the same second
- ASCII art upload with configurable default logo
- Image logo upload (PNG, JPG, GIF, WebP) with MIME validation
- Live preview of fastfetch output in browser
- Backup management panel (restore/delete all)
- Raw config editor with JSONC support
- Gruvbox Dark theme for the web interface
- Bearer token authentication (constant-time comparison, 24-hour expiry)
- Rate limiting per IP (sliding window, 100 requests per minute)
- DNS rebinding protection (loopback-only host validation)
- Atomic file operations (text and binary, chmod 600)
- Security headers (X-Frame-Options, X-Content-Type-Options, Referrer-Policy, CSP)
- Optional self-signed TLS/HTTPS support
- Graceful shutdown handling (SIGINT/SIGTERM, temp file cleanup on exit)
- Optional python-magic integration for MIME type validation

### Changed

- Module list now uses visual block builder instead of simple toggle buttons
- Full config output (including logo) shown in live preview
- Color scheme migrated to Gruvbox Dark palette
- Logo reference corrected from invalid 'file-source' to valid 'file' type
- MIME detection normalizes variants (image/x-png -> image/png, etc.)
- Fastfetch subprocess runs without text=True to prevent UTF-8 decode errors
- Build endpoint sends module permutation instead of metadata (preserves all props)

### Fixed

- Critical runtime crash: stat.S_IW_USR typo fixed to 0o600
- Token validation TypeError on non-ASCII characters (now encodes to UTF-8 bytes)
- Config corruption: placeholder changed from '#' to '//' for JSONC validity
- Race conditions: raw save/restore now wrapped in config_lock
- Rate limit storm: removed enable-all/disable-all endpoints (block builder handles activation)
- Preview edit bug: removed feature that rolled back to stale snapshot
- CORS/CSRF: no longer needed for loopback-only binding
- Host header validation includes IPv6 bracket form
- Cleanup of orphan temp files if frontend creation fails midway

### Security

- Fail-closed token acquisition (env var, TTY prompt, or refusal to start)
- Token stored only in memory (never logged, never embedded in HTML)
- Session token in sessionStorage (cleared when tab closes)
- Content-Security-Policy restricts resource loading
- Path traversal prevention with strict filename validation
- All config mutations protected by mutex
- Upload validation: extension whitelist, MIME sniffing, size limits
- Connection closed on rejected requests (prevents keep-alive desync)

### Documentation

- Comprehensive README with architecture overview and usage examples
- Detailed USAGE guide for all features and workflows
- SECURITY.md covering threat model and mitigation strategies
- CONTRIBUTING.md for issue reporting and development guidelines
- GitHub issue templates (bug report, feature request, config)
- CI workflow for syntax checks and security scanning

### Deprecated

- Old module toggle endpoints (/api/toggle-module, /api/toggle-all)
- /api/modules endpoint (replaced by /api/module-blocks)
- Preview editing feature (removed, does not work semantically)

## [0.x.x] - Historical versions (pre-public-release)

See git history for development versions v2.3.3 through v2.4.0. Internal iterations
during development; not published for external use.

[1.0.0]: https://github.com/beardywizz/fastfetch_webui/releases/tag/v1.0.0
EOF
