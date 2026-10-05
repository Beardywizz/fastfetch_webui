<img width="640" height="406" alt="webui" src="https://github.com/user-attachments/assets/09ac6a57-f2cf-4940-a727-74f124e5bb10" />

# FastFetch WebUI

A self-contained local web UI for configuring [fastfetch](https://github.com/fastfetch-cli/fastfetch), featuring a Scratch-style block builder for arranging system information modules.

**Version 1.0.0 - Initial Public Release**

## Overview

FastFetch WebUI lets you configure your fastfetch setup through a browser instead of hand-editing `config.jsonc`. Modules are represented as draggable blocks: pull them from a category palette into your active stack, reorder them by dragging, and deactivate them by parking them in a separate stack. All properties (keys, colors, formats) are preserved through every operation. A live preview shows the exact fastfetch output after each change.

This tool is aimed at users who are learning to customize their Linux or macOS system and want a safe, visual way to work with config files: every change is backed up automatically, and watching the Raw Config Editor while toggling blocks shows exactly what each block means in JSONC.

## Features

- Block builder interface inspired by Scratch: palette, active stack, parked stack
- Drag-and-drop module ordering and activation
- Full preservation of module properties (key, keyColor, format)
- ASCII art and image logo uploads (PNG, JPG, GIF, WebP)
- Automatic timestamped backups before every change (max 50, FIFO)
- Live preview of the full fastfetch output
- Raw JSONC editor for direct config access
- Gruvbox Dark theme

## Security Highlights

- Loopback-only binding (127.0.0.1 / ::1), DNS rebinding protection
- Bearer token authentication (constant-time comparison, 24-hour expiry, fail-closed acquisition)
- Per-IP rate limiting (100 requests per minute)
- Atomic file operations with restrictive permissions (mode 600)
- Path traversal prevention and upload validation

This tool is designed exclusively for local use. Never expose the server to a network.

## Requirements

- Linux or macOS with Python 3.10 or newer
- fastfetch installed and accessible in PATH

Installation commands:

- Debian/Ubuntu: `sudo apt install fastfetch`
- Fedora: `sudo dnf install fastfetch`
- Arch: `sudo pacman -S fastfetch`
- macOS (Homebrew): `brew install fastfetch`

Optional (graceful degradation if missing):

- python-magic - MIME type validation for uploads (otherwise extension check only)
- cryptography - HTTPS support (otherwise plain HTTP)

## Quick Start

```bash
python3 fastfetch_webui.py
