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
```

That is the entire installation - the program is a single file with no dependencies to install.

On first start you are asked for an access token: type your own (minimum 16 characters, input hidden) or press ENTER to have a secure random token generated and displayed exactly once. Paste it into the browser prompt. The browser opens automatically at http://127.0.0.1:8080.

## Usage
Adding modules
Drag a chip from the Palette into the Active Modules stack, or click it to append.

Activating and deactivating modules
Click the toggle switch on a block. Off moves the block to the Parked Blocks stack and removes it from the config; all properties survive and the block can be reactivated at any time.

Reordering
Drag blocks vertically within a stack. Changes are published automatically after a short delay.

Changing the logo
ASCII art: paste it into the ASCII Editor and click Upload ASCII. Images: drag and drop or select a file (PNG, JPG, GIF, WebP, max 2 MB).

Note: image logos render in the preview as blank space, because browsers cannot display terminal image protocols (Kitty, Sixel, iTerm2). Use a terminal with image protocol support (Kitty, WezTerm, foot, Ghostty, recent Konsole) to see image logos. ASCII logos always display correctly.

## Backups
Every save, restore, and structural change creates a timestamped backup in ~/.config/fastfetch/backups/. Restore or delete backups via the Backups panel.

## File Locations
~/.config/fastfetch/
├── config.jsonc          # main config - the file fastfetch reads
├── ascii/custom_ascii.txt  # uploaded ASCII art
├── logos/                # uploaded images (random names)
├── backups/             # automatic backups (max 50)
└── webui_state.json     # parked modules (sidecar)

Deleting this program never harms your configuration: the config file remains, and fastfetch continues to work without the web UI.

## Troubleshooting
Token not accepted: Clear the stored session token via the browser console (sessionStorage.removeItem('ff_token')), then reload the page. If the server runs longer than 24 hours, restart it: the token expired.

Preview shows an error: Verify that fastfetch is installed and reachable (which fastfetch && fastfetch --version).

Image uploads rejected: Uninstall python-magic; the program falls back to extension-only validation.

## Documentation
[USAGE.md](https://github.com/Beardywizz/fastfetch_webui/blob/main/USAGE.md)- complete user guide

[SECURITY.md](https://github.com/Beardywizz/fastfetch_webui/blob/main/SECURITY.md) - threat model and mitigations

[CONTRIBUTING.md](https://github.com/Beardywizz/fastfetch_webui/blob/main/CONTRIBUTING.md) - how to contribute

[CHANGELOG.md](https://github.com/Beardywizz/fastfetch_webui/blob/main/CHANGELOG.md) - version history

[License](https://github.com/Beardywizz/fastfetch_webui/blob/main/LICENSE) MIT License. See LICENSE.


Built with Lumo AI (Proton).

FastFetch WebUI (Deutsche Kurzanleitung)
FastFetch WebUI ist eine lokale Web-Oberfläche für fastfetch - das Programm, das die Systeminfo-Karte im Terminal zeichnet. Sie richtet sich an alle, die gerade lernen, ihr Linux- oder macOS-System zu personalisieren: Statt die Konfigurationsdatei config.jsonc von Hand zu bearbeiten, baust du deine Anzeige aus Blöcken zusammen, siehst jede Änderung sofort in der Vorschau, und vor jedem Schritt wird automatisch ein Backup angelegt.

## Schnellstart
```bash
python3 fastfetch_webui.py
```

Beim Start wird ein Zugangs-Token abgefragt: eigenes Token eintippen (mindestens 16 Zeichen) oder ENTER für ein einmalig angezeigtes Zufalls-Token. Der Browser öffnet sich automatisch unter http://127.0.0.1:8080.

Grundidee in drei Sätzen
Baukasten: Module sind farbige Blöcke, die du per Drag-and-drop aus der Palette in deinen aktiven Stapel ziehst, umsortierst und per Schalter an- und abschaltest.
Live-Vorschau: Nach jeder Änderung wird die echte fastfetch-Ausgabe neu gerendert - was du siehst, kommt später so ins Terminal.
Sicherheitsnetz: Jede Änderung erzeugt vorher ein Backup; per Klick stellst du jeden früheren Zustand wieder her.
Die ausführliche Anleitung mit Schritt-für-Schritt-Einführung findest du im englischen Abschnitt oben.

Hinweis zur Sprache
Diese Seite ist die einzige zweisprachige Dokumentation des Projekts. Alle weiteren Dokumente liegen ausschließlich auf Englisch - das ist Absicht: Die Arbeit mit Linux, Config-Dateien und der zugehörigen Community findet auf Englisch statt. Die deutsche Kurzfassung hilft beim ersten Einstieg; die Details schlägst du in der Sprache nach, in der du langfristig arbeitest.
