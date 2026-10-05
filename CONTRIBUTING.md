# Contributing Guidelines

Thank you for your interest in contributing to FastFetch WebUI.

## Ground Rules

- Stay constructive and on topic. Personal attacks and trolling are not tolerated.
- Search existing issues before opening a new one.
- Do not post tokens, passwords, or personal data in issues or code samples.

## Reporting Bugs

Open an issue using the Bug Report template and include:

- FastFetch WebUI version
- OS, Python version, fastfetch version
- Exact steps to reproduce
- Expected and actual behavior, with full error messages (terminal and
  browser console, F12)
- A sanitized config snippet if relevant

## Requesting Features

Open an issue using the Feature Request template. Explain the problem the
feature solves, not only the solution. Proposals must align with the project
constraints:

- Single-file design: all program code remains in fastfetch_webui.py
- Local use only: no network exposure features
- Security first: no weakening of the documented threat model

## Pull Requests

1. Fork the repository and create a feature branch from main
2. Make your changes
3. Verify before submitting:

```bash
python3 -m py_compile fastfetch_webui.py
python3 fastfetch_webui.py
