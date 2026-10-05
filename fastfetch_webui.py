#!/usr/bin/env python3
"""
FastFetch WebUI v2.4.1 Public v1.0 - Scratch-style Block Builder Edition
==========================================================
Self-contained local web UI for fastfetch configuration.

Security model:
- Loopback-only binding, host-header allow-list (DNS rebinding, incl. IPv6)
- Bearer token auth (constant-time compare, 24h expiry, never logged/embedded)
  Token acquisition (in priority order):
    1. WEBAUTH_TOKEN env variable (validated: stripped, >= 16 chars)
    2. Interactive CLI prompt (hidden input via getpass, or random
       one-time-displayed token)
    3. Refuses to start (fail-closed) if neither TTY nor env token
- Per-IP rate limiting (thread-safe sliding window, counted once per request)
- Path traversal prevention (strict validation + containment re-check)
- Atomic file operations (text + binary); ALL config writes under mutex
  (structural mutations, raw saves and restores alike)
- Upload validation: extension whitelist, MIME sniffing, size caps,
  server-chosen random filenames, file+config written in one locked cycle
- Timestamped backup before EVERY save, restore and structural change
  (collision-proof: suffixed when multiple saves fall into the same second)
- ASCII logos are referenced via the valid fastfetch LogoType 'file'
  (NOT 'file-source' / 'ascii' - both produced JsonConfig enum errors)
- Security headers incl. restrictive CSP; all rendered names escaped
  (HTML and attribute contexts); event delegation instead of inline JS
- Rejected requests close the connection (no keep-alive desync)
- Frontend generated fresh per run (random temp filename, mode 600),
  deleted on exit (normal shutdown, Ctrl+C, SIGTERM); orphan temp files
  are cleaned up if creation fails midway
- v2.4.1 Public v1.0: Scratch-style block builder - modules are draggable blocks that
  can be activated/deactivated by moving between "Active" and "Parked" stacks;
  full module objects preserved (key/keyColor/format survive all operations)

Author: Beardywizz
AI Assistant: Lumo AI (Proton)
License: MIT
Version: 2.4.1 Public v1.0
"""

import os
import re
import sys
import json
import shutil
import signal
import atexit
import secrets
import stat
import ssl
import time
import base64
import getpass
import tempfile
import threading
import subprocess
import webbrowser
from datetime import datetime, timedelta
from pathlib import Path
from collections import defaultdict
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler

# ---- Optional dependencies (graceful degradation if missing) -----------------
try:
    import magic
    MAGIC_AVAILABLE = True
except ImportError:
    MAGIC_AVAILABLE = False

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    CRYPTOGRAPHY_AVAILABLE = True
except ImportError:
    CRYPTOGRAPHY_AVAILABLE = False

#===============================================================================
# CONFIGURATION
#===============================================================================

HOST = '127.0.0.1'
PORT = 8080
SSL_ENABLED = False

# Hostnames accepted in the Host header (DNS rebinding protection)
ALLOWED_HOSTS = {'127.0.0.1', 'localhost', '[::1]', '::1'}

# Authentication (token never written to disk, logs or HTML by this program)
MIN_TOKEN_LENGTH = 16         # enforced for env and manually entered tokens
TOKEN_MAX_AGE = 86400         # 24 hours
AUTH_TOKEN = None             # resolved by setup_auth() at startup
TOKEN_CREATED = None          # set when the token is assigned, not at import

# Resource limits
MAX_UPLOAD_SIZE = 2 * 1024 * 1024     # images: 2MB
MAX_BODY_SIZE = 10 * 1024 * 1024     # any request body
MAX_CONFIG_SIZE = 100 * 1024        # config file
MAX_ASCII_SIZE = 50 * 1024          # ASCII art
MAX_BACKUPS = 50
MAX_MODULES = 500                    # sanity cap for reorder payloads
RATE_LIMIT = 100
RATE_WINDOW = 60

ALLOWED_IMAGE_EXTS = ['.png', '.jpg', '.jpeg', '.gif', '.webp']
ALLOWED_IMAGE_MIMES = ['image/png', 'image/jpeg', 'image/gif', 'image/webp']

# Paths - fastfetch-compatible structure
HOME = Path.home()
CONFIG_DIR = HOME / '.config' / 'fastfetch'
CONFIG_FILE = CONFIG_DIR / 'config.jsonc'
BACKUP_DIR = CONFIG_DIR / 'backups'
ASCII_DIR = CONFIG_DIR / 'ascii'    # uploaded ASCII art (.txt)
LOGO_DIR = CONFIG_DIR / 'logos'     # uploaded images (.png, etc.)
STATE_FILE = CONFIG_DIR / 'webui_state.json'  # v2.4.1 Public v1.0: parked modules sidecar

# Runtime-managed frontend file (created in main(), removed on exit)
INDEX_FILE = None

STANDARD_MODULES = [
    {'type': 'os', 'key': 'OS', 'keyColor': 'yellow'},
    {'type': 'kernel', 'key': 'Kernel', 'keyColor': 'yellow'},
    {'type': 'shell', 'key': 'Shell', 'keyColor': 'yellow'},
    {'type': 'de', 'key': 'DE', 'keyColor': 'blue'},
    {'type': 'wm', 'key': 'WM', 'keyColor': 'blue'},
    {'type': 'terminal', 'key': 'Terminal', 'keyColor': 'blue'},
    {'type': 'cpu', 'key': 'CPU', 'keyColor': 'green'},
    {'type': 'gpu', 'key': 'GPU', 'keyColor': 'green'},
    {'type': 'memory', 'key': 'Memory', 'keyColor': 'green'},
    {'type': 'disk', 'key': 'Disk', 'keyColor': 'green'},
    {'type': 'uptime', 'key': 'Uptime', 'keyColor': 'magenta'},
    {'type': 'packages', 'key': 'Packages', 'keyColor': 'yellow'},
]

# Thread-safety primitives
config_lock = threading.Lock()
_rate_counts = defaultdict(list)
_rate_lock = threading.Lock()

#===============================================================================
# SECURITY UTILITIES
#===============================================================================

def sanitize_path(filepath):
    """Strict filename validation; blocks traversal and unsafe characters."""
    if not isinstance(filepath, str) or not filepath:
        raise ValueError("Invalid filename")
    if '..' in filepath or '/' in filepath or '\\' in filepath:
        raise ValueError("Directory traversal detected")
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._ -]*', filepath):
        raise ValueError("Invalid characters in filename")
    if filepath.startswith('.') and 'backup' not in filepath.lower():
        raise ValueError("Hidden files not allowed")
    return filepath

def atomic_write_text(content, filepath):
    """Atomic text write: temp file in same dir, chmod 600, rename."""
    filepath = Path(filepath)
    filepath.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=filepath.parent,
                               prefix='.' + filepath.stem + '_', suffix='.tmp')
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            f.write(content)
        os.chmod(tmp, 0o600)
        os.rename(tmp, filepath)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise

def atomic_write_bytes(data, filepath):
    """Atomic binary write (image uploads)."""
    filepath = Path(filepath)
    filepath.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=filepath.parent,
                               prefix='.' + filepath.stem + '_', suffix='.tmp')
    try:
        with os.fdopen(fd, 'wb') as f:
            f.write(data)
        os.chmod(tmp, 0o600)
        os.rename(tmp, filepath)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise

def check_rate_limit(ip):
    """Thread-safe sliding-window rate limiter (counted once per request)."""
    now = time.time()
    with _rate_lock:
        _rate_counts[ip] = [t for t in _rate_counts[ip] if now - t < RATE_WINDOW]
        if len(_rate_counts[ip]) >= RATE_LIMIT:
            return False
        _rate_counts[ip].append(now)
        return True

# MIME sniffer singleton
_magic_obj = None

def sniff_mime(data, allowed):
    """
    True if detected MIME type is whitelisted.
    Graceful degradation: on detection failure, allow the file (don't block).
    Normalizes common MIME variants (x-png → png, etc.).
    """
    global _magic_obj
    if not MAGIC_AVAILABLE:
        return True  # No libmagic → trust the extension
    try:
        if _magic_obj is None:
            _magic_obj = magic.Magic(mime=True)
        detected = _magic_obj.from_buffer(data[:2048])
        if not detected:
            return True  # Can't detect → allow (graceful degradation)
        # Normalize: some libmagic versions return x-png, x-jpeg, etc.
        detected = detected.lower()
        mime_map = {
            'image/x-png': 'image/png',
            'image/x-jpg': 'image/jpeg',
            'image/x-jpeg': 'image/jpeg',
            'image/x-webp': 'image/webp',
            'image/svg+xml': 'image/svg+xml',
            'application/octet-stream': '',  # unknown → rely on extension
        }
        normalized = mime_map.get(detected, detected)
        # Allow the file if it matches OR if detection was ambiguous
        return normalized in allowed or normalized == '' or any(
            allowed_type.split('/')[-1] in detected for allowed_type in allowed
        )
    except Exception:
        return True  # Detection failed → don't block (graceful degradation)

def parse_int_header(value, default=0):
    """Safely parse integer headers; malformed input never raises."""
    try:
        return int(value)
    except (TypeError, ValueError):
        return default

def validate_config_size(text):
    if len(text.encode('utf-8')) > MAX_CONFIG_SIZE:
        raise ValueError("Config exceeds size limit")

def token_is_valid(provided):
    """
    Constant-time token check plus lifetime check.
    v2.4.1 Public v1.0: compares UTF-8 BYTES - compare_digest raises TypeError on
    non-ASCII strings, which previously crashed the connection handler.
    """
    if not AUTH_TOKEN or not TOKEN_CREATED or not isinstance(provided, str):
        return False
    if time.time() - TOKEN_CREATED > TOKEN_MAX_AGE:
        return False
    try:
        return secrets.compare_digest(provided.encode('utf-8'),
                                      AUTH_TOKEN.encode('utf-8'))
    except Exception:
        return False

#===============================================================================
# AUTHENTICATION SETUP
#===============================================================================

def _read_token_interactive():
    """
    Interactive token acquisition:
    - hidden input via getpass (nothing appears in scrollback)
    - empty input -> random token, displayed exactly once
    - min length enforced (brute-force resistance)
    Returns the token string, or exits cleanly on Ctrl+D / Ctrl+C.
    """
    print()
    print("  Token setup")
    print("  -----------")
    print("  1) Type your own token (min. {} chars, input hidden)".format(MIN_TOKEN_LENGTH))
    print("  2) Just press ENTER for a secure random token")
    while True:
        try:
            entered = getpass.getpass('  TOKEN > ').strip()
        except (EOFError, KeyboardInterrupt):
            print("\n[INFO] Aborted by user.")
            raise SystemExit(0)
        if not entered:
            token = secrets.token_urlsafe(32)
            print("  Random token generated. Displayed ONCE - copy it now:")
            print()
            print("      " + token)
            print()
            print("  Note: this line remains in your terminal scrollback.")
            print("        For unattended/persistent runs use WEBAUTH_TOKEN.")
            return token
        if len(entered) < MIN_TOKEN_LENGTH:
            print("  [!] Too short (min. {} chars). Try again.".format(MIN_TOKEN_LENGTH))
            continue
        print("  [OK] Token accepted (length: {} chars, hidden - not echoed).".format(len(entered)))
        return entered

def setup_auth():
    """
    Resolve the auth token. Priority:
    1. WEBAUTH_TOKEN env var (stripped, length >= MIN_TOKEN_LENGTH)
    2. Interactive prompt (TTY required)
    3. FAIL CLOSED otherwise: refusing to print a secret to potentially
       redirected output.
    Returns True on success.
    """
    global AUTH_TOKEN, TOKEN_CREATED

    env_token = os.environ.get('WEBAUTH_TOKEN')
    if env_token is not None:
        env_token = env_token.strip()
        if len(env_token) >= MIN_TOKEN_LENGTH:
            AUTH_TOKEN = env_token
            TOKEN_CREATED = time.time()
            print("[OK] Auth token taken from WEBAUTH_TOKEN (not displayed).")
            return True
        print("[ERROR] WEBAUTH_TOKEN is set but shorter than {} characters.".format(MIN_TOKEN_LENGTH))
        print("        Refusing to start with a weak token. Abort.")
        return False

    if sys.stdin.isatty() and sys.stdout.isatty():
        AUTH_TOKEN = _read_token_interactive()
        TOKEN_CREATED = time.time()
        return True

    print("[ERROR] No terminal available and no WEBAUTH_TOKEN set.")
    print("        This program refuses to print a secret to (possibly")
    print("        redirected) output. Set WEBAUTH_TOKEN, e.g.:")
    print("        export WEBAUTH_TOKEN=$(python3 -c "
          "'import secrets; print(secrets.token_urlsafe(32))')")
    return False

#===============================================================================
# CORE CONFIG FUNCTIONS
#===============================================================================

def setup_directories():
    """Create working directories with owner-only permissions."""
    for d in [CONFIG_DIR, BACKUP_DIR, ASCII_DIR, LOGO_DIR]:
        try:
            made_now = not d.exists()
            d.mkdir(parents=True, exist_ok=True)
            if made_now and hasattr(os, 'chmod'):
                os.chmod(d, stat.S_IRWXU)
        except OSError as e:
            print(f"[ERROR] Directory setup failed for {d}: {e}")

def find_fastfetch():
    """Locate the fastfetch binary."""
    for exe in ('fastfetch', 'fastfetch.exe'):
        path = shutil.which(exe)
        if path:
            return path
    for path in ('/usr/bin/fastfetch', '/usr/local/bin/fastfetch',
                 '/opt/homebrew/bin/fastfetch',           # macOS (Apple Silicon)
                 str(HOME / '.local' / 'bin' / 'fastfetch')):
        if Path(path).exists():
            return path
    return None

def get_backups():
    """Backups sorted newest-first, capped at MAX_BACKUPS."""
    if not BACKUP_DIR.exists():
        return []
    return sorted(BACKUP_DIR.glob('*.backup'), reverse=True)[:MAX_BACKUPS]

def load_disabled_modules():
    """v2.4.1 Public v1.0: Read parked modules from sidecar. Never throws."""
    try:
        if not STATE_FILE.exists() or STATE_FILE.stat().st_size > MAX_CONFIG_SIZE:
            return []
        data = json.loads(STATE_FILE.read_text(encoding='utf-8'))
        out = data.get('disabled', [])
        return out if isinstance(out, list) else []
    except Exception:
        return []

def save_disabled_modules(disabled):
    """v2.4.1 Public v1.0: Atomically persist sidecar (mode 600)."""
    try:
        atomic_write_text(json.dumps({'disabled': disabled}, indent=2,
                                     ensure_ascii=False), STATE_FILE)
        return True
    except Exception as e:
        print(f"[ERROR] Could not save WebUI state: {e}")
        return False

def create_backup():
    """Snapshot the current config before any mutation (FIFO pruning)."""
    if not CONFIG_FILE.exists():
        return None
    try:
        existing = get_backups()
        if len(existing) >= MAX_BACKUPS:
            existing[-1].unlink()
        stamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        backup_path = BACKUP_DIR / f'config_{stamp}.backup'
        # v2.4.1 Public v1.0: multiple saves within one second must not overwrite
        n = 1
        while backup_path.exists():
            backup_path = BACKUP_DIR / f'config_{stamp}_{n}.backup'
            n += 1
        shutil.copy2(CONFIG_FILE, backup_path)
        return backup_path
    except Exception as e:
        print(f"[ERROR] Backup failed: {e}")
        return None

def load_config():
    """Read config with size validation. None on any failure."""
    if not CONFIG_FILE.exists():
        return None
    try:
        if CONFIG_FILE.stat().st_size > MAX_CONFIG_SIZE:
            return None
        with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
            return f.read()
    except Exception:
        return None

def save_config(content):
    """Size-checked atomic save."""
    try:
        validate_config_size(content)
        atomic_write_text(content, CONFIG_FILE)
        return True
    except Exception as e:
        print(f"[ERROR] Save failed: {e}")
        return False

def parse_config(text):
    """JSONC -> dict. Strips block and line comments (string-aware)."""
    if not text:
        return {'modules': []}
    try:
        cleaned = re.sub(r'/\*.*?\*/', '', text, flags=re.DOTALL)
        out_lines = []
        in_string = False
        for line in cleaned.split('\n'):
            kept = []
            i = 0
            while i < len(line):
                c = line[i]
                if c == '\\' and i + 1 < len(line):
                    kept.append(c + line[i + 1])
                    i += 2
                    continue
                if c == '"':
                    in_string = not in_string
                elif not in_string and line[i:i + 2] == '//':
                    break
                kept.append(c)
                i += 1
            out_lines.append(''.join(kept))
        return json.loads('\n'.join(out_lines))
    except Exception:
        return {'modules': []}

def mutate_config(mutator):
    """
    Guarded read-modify-write cycle for ALL structural config changes:
    - serialized by config_lock (no lost updates across threads)
    - preserves the user's leading comment block (before first '{')
    - backs up the current state before writing
    """
    with config_lock:
        original = load_config() or ''
        cfg = parse_config(original)
        mutator(cfg)
        brace = original.find('{')
        header = original[:brace] if brace > 0 else ''
        if not header.strip():
            header = '// fastfetch config (managed by FastFetch WebUI)\n'
        create_backup()
        return save_config(header + json.dumps(cfg, indent=2, ensure_ascii=False))

def run_fastfetch():
    """Run fastfetch sandboxed (timeout, minimal env, no shell).
    v2.4.1 Public v1.0: full output incl. logo - the preview mirrors the terminal.
    (Browser can't render image protocols; ASCII logos show fine.)"""
    exe = find_fastfetch()
    if not exe:
        return "Error: fastfetch not found"
    if not CONFIG_FILE.exists():
        return "Error: config file not found"
    env = {'PATH': '/usr/bin:/bin', 'TERM': os.environ.get('TERM', '')}
    try:
        result = subprocess.run(
            [exe, '-c', str(CONFIG_FILE)],
            capture_output=True, text=False, timeout=5, env=env,
            cwd='/tmp')
        if result.returncode == 0:
            output = result.stdout.decode('utf-8', errors='replace')
        else:
            output = result.stderr.decode('utf-8', errors='replace')
        return output[:50000] if len(output) <= 50000 else output[:50000] + '\n...'
    except subprocess.TimeoutExpired:
        return "Error: fastfetch timed out"
    except Exception as e:
        return f"Error: {str(e)[:200]}"

def generate_ssl_context():
    """Optional self-signed TLS for HTTPS mode."""
    if not SSL_ENABLED or not CRYPTOGRAPHY_AVAILABLE:
        return None
    try:
        cert_dir = CONFIG_DIR / 'ssl'
        cert_dir.mkdir(parents=True, exist_ok=True)
        cert_file = cert_dir / 'localhost.crt'
        key_file = cert_dir / 'localhost.key'
        if not (cert_file.exists() and key_file.exists()):
            key = rsa.generate_private_key(65537, 2048, default_backend())
            name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'localhost')])
            cert = (x509.CertificateBuilder()
                    .subject_name(name).issuer_name(name)
                    .public_key(key.public_key())
                    .serial_number(x509.random_serial_number())
                    .not_valid_before(datetime.now())
                    .not_valid_after(datetime.now() + timedelta(days=365))
                    .add_extension(x509.SubjectAlternativeName([x509.DNSName('localhost')]),
                                   critical=True)
                    .sign(key, hashes.SHA256(), default_backend()))
            with open(key_file, 'wb') as f:
                f.write(key.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.TraditionalOpenSSL,
                    serialization.NoEncryption()))
            with open(cert_file, 'wb') as f:
                f.write(cert.public_bytes(serialization.Encoding.PEM))
        ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        ctx.load_cert_chain(str(cert_file), str(key_file))
        return ctx
    except Exception as e:
        print(f"[ERROR] SSL setup failed: {e}")
        return None

#===============================================================================
# FRONTEND LIFECYCLE
#===============================================================================

def create_index_file():
    """Write embedded HTML to a randomly named temp file (mode 600)."""
    global INDEX_FILE
    fd, path = tempfile.mkstemp(prefix='ffwebui_', suffix='.html')
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            f.write(INDEX_HTML)
        os.chmod(path, 0o600)   # v2.4.1 Public v1.0 fix: was stat.S_IW_USR (AttributeError)
        INDEX_FILE = Path(path)
        print(f"[INFO] Frontend: {INDEX_FILE} (temporary, deleted on exit)")
    except Exception as e:
        # v2.4.1 Public v1.0: close the fd and remove the orphan file before giving up
        try:
            os.close(fd)
        except OSError:
            pass
        try:
            os.unlink(path)
        except OSError:
            pass
        INDEX_FILE = None
        print(f"[ERROR] Could not create frontend file: {e}")

def cleanup_index_file():
    """Remove the temporary frontend file."""
    global INDEX_FILE
    if INDEX_FILE and INDEX_FILE.exists():
        try:
            INDEX_FILE.unlink()
            print(f"[INFO] Frontend file removed: {INDEX_FILE}")
        except OSError:
            pass
    INDEX_FILE = None

atexit.register(cleanup_index_file)

def terminate_handler(signum, frame):
    """Convert SIGTERM/SIGINT into clean exit so atexit cleanup runs."""
    raise SystemExit(0)

#===============================================================================
# HTTP HANDLER
#===============================================================================

class Handler(BaseHTTPRequestHandler):
    """Request handler: host validation, rate limiting, token auth."""

    protocol_version = 'HTTP/1.1'

    def log_message(self, fmt, *args):
        print(f"[WEB] {self.address_string()} - {fmt % args}")

    # ---- response helpers -----------------------------------------------------

    def _security_headers(self):
        self.send_header('X-Frame-Options', 'DENY')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Referrer-Policy', 'no-referrer')
        self.send_header('Cache-Control', 'no-store')
        self.send_header('Content-Security-Policy',
                         "default-src 'none'; script-src 'unsafe-inline'; "
                         "style-src 'unsafe-inline'; connect-src 'self'; "
                         "img-src 'self' data:")

    def send_json(self, data, status=200):
        body = json.dumps(data).encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', len(body))
        self._security_headers()
        self.end_headers()
        self.wfile.write(body)

    # ---- request gates (each check runs exactly ONCE per request) -------------

    def check_host(self):
        """DNS rebinding protection; Host must be a loopback name."""
        raw = self.headers.get('Host', '')
        if raw.startswith('[') and ']' in raw:
            host = raw[:raw.index(']') + 1].lower()   # IPv6 bracket form
        else:
            host = raw.split(':')[0].lower()
        if host not in ALLOWED_HOSTS:
            print(f"[SECURITY] Blocked request with Host: {raw!r}")
            return False
        return True

    def check_auth(self):
        auth = self.headers.get('Authorization', '')
        if not auth.startswith('Bearer '):
            return False
        return token_is_valid(auth[7:])

    def gate_common(self):
        """Host + rate + body-size. Sends error response and returns False on fail."""
        if not self.check_host():
            self.close_connection = True
            self.send_json({'error': 'Forbidden'}, 403)
            return False
        if not check_rate_limit(self.client_address[0]):
            self.close_connection = True
            self.send_json({'error': 'Rate limit exceeded'}, 429)
            return False
        if self.command == 'POST':
            length = parse_int_header(self.headers.get('Content-Length'), -1)
            if length < 0:
                # Body stays unread: close to avoid keep-alive desync
                self.close_connection = True
                self.send_json({'error': 'Invalid Content-Length'}, 400)
                return False
            if length > MAX_BODY_SIZE:
                self.close_connection = True
                self.send_json({'error': 'Request too large'}, 413)
                return False
        return True

    # ---- GET -------------------------------------------------------------------

    def do_GET(self):
        if not self.gate_common():
            return
        path = self.path.split('?')[0]

        # Public endpoints
        if path in ('/', '/index.html'):
            self._serve_index()
        elif path == '/api/health':
            self.send_json({'ok': True,
                            'config_exists': CONFIG_FILE.exists(),
                            'auth_required': True})
        elif path == '/api/default-ascii':
            body = DEFAULT_ASCII.encode('utf-8')
            self.send_response(200)
            self.send_header('Content-Type', 'text/plain; charset=utf-8')
            self.send_header('Content-Length', len(body))
            self._security_headers()
            self.end_headers()
            self.wfile.write(body)
        else:
            # Protected endpoints: host/rate already checked above -> auth ONLY
            if not self.check_auth():
                self.send_json({'error': 'Authentication required'}, 401)
                return
            if path == '/api/config':
                # v2.4.1 Public v1.0: '//' comment, NOT '#' (would corrupt the config on save)
                self.send_json({'content': load_config() or '// No config found'})
            elif path == '/api/module-blocks':
                # v2.4.1 Public v1.0: builder endpoint - full objects survive all operations
                mods = parse_config(load_config() or '').get('modules', [])
                if not isinstance(mods, list):
                    mods = []
                self.send_json({'modules': mods,
                               'disabled': load_disabled_modules()})
            elif path == '/api/preview':
                self.send_json({'output': run_fastfetch()})
            elif path == '/api/backups':
                # v2.4.1 Public v1.0: tolerate files vanishing between glob and stat
                backups = []
                for b in get_backups():
                    try:
                        st = b.stat()
                    except OSError:
                        continue
                    backups.append({'name': b.name,
                                    'mtime': int(st.st_mtime),
                                    'size': st.st_size})
                self.send_json({'backups': backups})  # filenames only
            else:
                self.send_json({'error': 'Not found'}, 404)

    def _serve_index(self):
        """Serve the freshly generated frontend file."""
        global INDEX_FILE
        if INDEX_FILE and INDEX_FILE.exists():
            try:
                body = INDEX_FILE.read_bytes()
                status = 200
            except OSError:
                body = (b'<html><body><h1>Frontend read error</h1>'
                        b'</body></html>')
                status = 500
        else:
            body = (b'<html><body><h1>Frontend not initialised - '
                    b'check the terminal for errors</h1></body></html>')
            status = 500
        self.send_response(status)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Content-Length', len(body))
        self._security_headers()
        self.end_headers()
        self.wfile.write(body)

    # ---- POST ------------------------------------------------------------------

    def do_POST(self):
        if not self.gate_common():
            return
        if not self.check_auth():
            self.send_json({'error': 'Authentication required'}, 401)
            return
        path = self.path.split('?')[0]

        length = parse_int_header(self.headers.get('Content-Length'), 0)
        if length <= 0:
            self.send_json({'error': 'Empty body'}, 400)
            return
        body = self.rfile.read(length).decode('utf-8', errors='replace')

        try:
            if path == '/api/save':
                self._p_save(body)
            elif path == '/api/build':
                # v2.4.1 Public v1.0: builder publish endpoint
                self._p_build(body)
            elif path == '/api/load-backup':
                self._p_restore(body)
            elif path == '/api/delete-backups':
                count = 0
                for b in get_backups():
                    try:
                        b.unlink()
                        count += 1
                    except OSError:
                        pass
                self.send_json({'deleted': count})
            elif path == '/api/upload-ascii':
                self._p_upload_ascii(body)
            elif path == '/api/upload-image':
                self._p_upload_image(body)
            else:
                self.send_json({'error': 'Unknown endpoint'}, 404)
        except json.JSONDecodeError:
            self.send_json({'error': 'Invalid JSON'}, 400)
        except ValueError as e:
            self.send_json({'error': str(e)}, 400)
        except Exception as e:
            print(f"[ERROR] POST {path}: {e}")
            self.send_json({'error': 'Internal server error'}, 500)

    # ---- POST sub-handlers -------------------------------------------------------

    def _p_save(self, body):
        """Raw save: backup first. v2.4.1 Public v1.0: now under config_lock too."""
        with config_lock:
            create_backup()
            ok = save_config(body)
        if ok:
            self.send_json({'success': True})
        else:
            self.send_json({'error': 'Save failed'}, 500)

    def _p_build(self, body):
        """
        v2.4.1 Public v1.0 Build endpoint: replaces modules array with complete ordered
        list from builder (full objects - key/keyColor/format survive).
        Parked blocks go to sidecar because fastfetch knows no 'disabled' attr.
        """
        data = json.loads(body)
        mods, parked = data.get('modules'), data.get('disabled')
        if not isinstance(mods, list) or not isinstance(parked, list):
            self.send_json({'error': 'Invalid payload'}, 400)
            return
        if len(mods) > MAX_MODULES or len(parked) > MAX_MODULES:
            self.send_json({'error': 'Too many modules'}, 400)
            return
        for m in mods + parked:
            if not (isinstance(m, str)
                    or (isinstance(m, dict) and isinstance(m.get('type'), str))):
                self.send_json({'error': 'Invalid module entry'}, 400)
                return

        def _mut(cfg):
            cfg['modules'] = mods

        if mutate_config(_mut):
            if not save_disabled_modules(parked):
                self.send_json({'error': 'Saved, but parking failed'}, 500)
                return
            self.send_json({'success': True})
        else:
            self.send_json({'error': 'Operation failed'}, 500)

    def _p_restore(self, body):
        data = json.loads(body)
        name = sanitize_path(data.get('name', ''))
        backup = BACKUP_DIR / name
        try:
            backup.resolve().relative_to(BACKUP_DIR.resolve())
        except ValueError:
            self.send_json({'error': 'Invalid backup'}, 400)
            return
        if not backup.exists():
            self.send_json({'error': 'Not found'}, 404)
            return
        # v2.4.1 Public v1.0: whole restore cycle under config_lock
        with config_lock:
            try:
                content = backup.read_text(encoding='utf-8')
                validate_config_size(content)
                create_backup()
                ok = save_config(content)
            except ValueError as e:
                self.send_json({'error': str(e)}, 400)
                return
        if ok:
            self.send_json({'success': True})
        else:
            self.send_json({'error': 'Restore failed'}, 500)

    def _p_upload_ascii(self, body):
        """
        ASCII uploads -> ~/.config/fastfetch/ascii/ + LogoType 'file'.
        Valid types verified against the official fastfetch Wiki
        ('Logo options'): 'file' = source is a file path whose content
        is displayed. 'ascii' and 'file-source' cause
        'JsonConfig Error (logo.type): Invalid enum string'.
        """
        ascii_text = json.loads(body).get('ascii', '')
        if not ascii_text or len(ascii_text) > MAX_ASCII_SIZE:
            self.send_json({'error': 'ASCII art empty or too large'}, 400)
            return

        def _mut(cfg):
            ASCII_DIR.mkdir(parents=True, exist_ok=True)
            logo_file = ASCII_DIR / 'custom_ascii.txt'
            atomic_write_text(ascii_text, logo_file)
            cfg['logo'] = {'type': 'file', 'source': str(logo_file)}

        if mutate_config(_mut):
            self.send_json({'success': True})
        else:
            self.send_json({'error': 'Upload failed'}, 500)

    def _p_upload_image(self, body):
        data = json.loads(body)
        filename = sanitize_path(data.get('filename', ''))
        ext = Path(filename).suffix.lower()
        if ext not in ALLOWED_IMAGE_EXTS:
            self.send_json({'error': 'Extension not allowed'}, 400)
            return
        image_data = data.get('image', '')
        if not image_data or ',' not in image_data:
            self.send_json({'error': 'Invalid image data'}, 400)
            return
        try:
            img = base64.b64decode(image_data.split(',', 1)[1], validate=False)
        except Exception:
            self.send_json({'error': 'Decode failed'}, 400)
            return
        if len(img) > MAX_UPLOAD_SIZE:
            self.send_json({'error': 'Image too large'}, 413)
            return
        if not sniff_mime(img, ALLOWED_IMAGE_MIMES):
            self.send_json({'error': 'Content is not an allowed image'}, 400)
            return
        logo_path = LOGO_DIR / f'logo_{int(time.time())}_{secrets.token_hex(4)}{ext}'

        def _mut(cfg):
            LOGO_DIR.mkdir(parents=True, exist_ok=True)
            atomic_write_bytes(img, logo_path)
            cfg['logo'] = {'type': 'auto', 'source': str(logo_path)}

        if mutate_config(_mut):
            self.send_json({'success': True})
        else:
            self.send_json({'error': 'Upload failed'}, 500)

#===============================================================================
# EMBEDDED RESOURCES
#===============================================================================

DEFAULT_ASCII = r''' █████╗ ███████╗ ██████╗██╗██╗
██╔══██╗██╔════╝██╔════╝██║██║
███████║███████╗██║     ██║██║
██╔══██║╚════██║██║     ██║██║
██║  ██║███████║╚██████╗██║██║
╚═╝  ╚═╝╚══════╝ ╚═════╝╚═╝╚═╝
'''.lstrip('\n')

INDEX_HTML = r'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>FastFetch WebUI v2.4.1 Public v1.0</title>
<style>
:root{--bg:#282828;--panel:#3c3836;--accent:#fabd2f;--text:#ebdbb2;
--green:#b8bb26;--red:#fb4934;--blue:#83a598;--bg-dark:#1d2021;
--border:#504945;--muted:#a89984}
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Segoe UI',monospace,sans-serif;background:var(--bg);
color:var(--text);padding:20px;line-height:1.6}
.container{max-width:1800px;margin:0 auto}
header{text-align:center;padding:20px 0;border-bottom:2px solid var(--accent);margin-bottom:20px}
h1{color:var(--accent);font-size:2em}
h2,h3,h4{color:var(--accent);margin-bottom:10px}
.panel{background:var(--panel);border:1px solid var(--border);border-radius:8px;padding:20px;margin-bottom:20px}
textarea{width:100%;height:250px;background:var(--bg-dark);color:var(--text);
font-family:'Consolas',monospace;font-size:13px;padding:15px;
border:1px solid var(--border);border-radius:4px;resize:vertical}
textarea:focus{outline:none;border-color:var(--green)}
.btn-group{margin:15px 0;display:flex;gap:10px;flex-wrap:wrap}
button{padding:10px 20px;background:var(--accent);color:#282828;border:none;
border-radius:4px;cursor:pointer;font-size:13px;transition:all .2s}
button:hover{opacity:.85;transform:translateY(-1px)}
button.danger{background:var(--red);color:#fff}
button.secondary{background:#504945;color:var(--text)}
button.success{background:var(--green);color:#282828}
button.small{padding:5px 10px;font-size:11px}
.status{padding:10px;margin:10px 0;border-radius:4px;display:none}
.status.show{display:block}
.status.success{background:rgba(184,187,38,.15);border-left:4px solid var(--green)}
.status.error{background:rgba(251,73,52,.15);border-left:4px solid var(--red)}
.preview{background:var(--bg-dark);padding:15px;border:1px solid var(--border);
border-radius:4px;min-height:150px;white-space:pre;overflow-x:auto;
font-family:'Consolas',monospace;font-size:13px}
.upload-section{background:var(--bg-dark);padding:20px;border:2px dashed var(--accent);
border-radius:8px;margin:15px 0}
.stats{display:flex;gap:20px;margin:15px 0;font-size:14px}
.stats span{background:var(--bg-dark);padding:5px 12px;border-radius:4px}
footer{text-align:center;margin-top:30px;color:var(--muted);font-size:12px}
input[type=file]{display:none}
.file-label{display:inline-block;padding:10px 20px;background:var(--blue);color:#282828;
border-radius:4px;cursor:pointer;margin:5px}
.row{display:flex;gap:20px}.col{flex:1}
@media(max-width:1200px){.row{flex-direction:column}}
.builder-layout{display:flex;gap:20px}
.palette-pane{width:250px;flex-shrink:0}
.workspace-pane{flex:1;min-width:0}
.p-cat{margin-bottom:12px}
.p-cat h4{font-size:11px;text-transform:uppercase;letter-spacing:1px;color:var(--muted);margin-bottom:5px}
.p-chip{display:inline-block;background:var(--bc,#665c54);color:#fff;padding:6px 10px;
margin:3px;border-radius:14px;font-size:12px;cursor:grab;border:none;font-family:inherit}
.block-stack{min-height:60px;background:var(--bg-dark);border:1px solid var(--border);
border-radius:8px;padding:8px;margin-bottom:15px}
.block-stack.parked{border-style:dashed;opacity:.8}
.ff-block{display:flex;align-items:center;gap:10px;background:#32302f;
border:1px solid var(--border);border-left:6px solid var(--bc,#665c54);
border-radius:6px;padding:8px 12px;margin:4px 0;cursor:grab;transition:box-shadow .15s}
.ff-block.dragging{opacity:.4;cursor:grabbing}
.ff-block.drop-target{box-shadow:0 -2px 0 0 var(--green)}
.b-type{font-weight:700;font-size:13px}
.b-key{font-size:11px;color:var(--muted);flex:1;white-space:nowrap;
overflow:hidden;text-overflow:ellipsis}
.b-sw{width:40px;height:22px;border-radius:11px;background:#665c54;position:relative;
cursor:pointer;flex-shrink:0;transition:background .3s}
.b-sw::after{content:'';position:absolute;width:16px;height:16px;border-radius:50%;
background:#fff;top:3px;left:3px;transition:left .3s}
.b-sw.on{background:var(--bc,#fabd2f)}
.b-sw.on::after{left:21px}
.btn-del{background:none;border:1px solid var(--border);color:var(--red);
border-radius:4px;width:26px;height:26px;cursor:pointer;font-size:12px;line-height:1;flex-shrink:0}
.btn-del:hover{background:rgba(251,73,52,.15);border-color:var(--red)}
.stack-empty{color:var(--muted);text-align:center;padding:12px;font-size:12px}
.backup-row{padding:8px;background:var(--bg-dark);margin:5px 0;border-radius:4px;
display:flex;justify-content:space-between;align-items:center}
</style>
</head>
<body>
<div class="container">
<header><h1>FastFetch Configurator</h1></header>

<div class="stats">
<span id="config-status">Loading...</span>
<span id="backup-count">Backups: 0</span>
<span id="auth-status">Checking token...</span>
</div>

<div class="panel">
<h2>Module Builder</h2>
<div class="builder-layout">
<div class="palette-pane">
<h3>Palette</h3>
<div id="palette"></div>
</div>
<div class="workspace-pane">
<h3>Active Modules (drag to reorder)</h3>
<div id="module-list" class="block-stack"></div>
<h3>Parked Blocks (inactive)</h3>
<div id="parked-list" class="block-stack parked"></div>
<div class="btn-group">
<button onclick="publishBuild()">Apply</button>
<button class="secondary" onclick="loadBlocks()">Reload</button>
</div>
</div>
</div>
</div>

<div class="panel">
<h2>Raw Config Editor</h2>
<textarea id="editor" placeholder="Loading config..."></textarea>
<div class="btn-group">
<button onclick="saveConfig()">Save &amp; Preview</button>
<button class="secondary" onclick="loadConfig()">Reload</button>
<button class="danger" onclick="showBackups()">Backups</button>
</div>
<div id="status" class="status"></div>
</div>

<div class="panel">
<h2>Logo Upload</h2>
<div class="row">
<div class="col">
<h3>ASCII Editor</h3>
<textarea id="ascii-editor" placeholder="Enter ASCII art..." style="height:150px"></textarea>
<div class="btn-group">
<button class="success" onclick="uploadAscii()">Upload ASCII</button>
<button class="secondary" onclick="loadDefaultAscii()">Default</button>
</div>
</div>
<div class="col">
<h3>Image Upload</h3>
<div class="upload-section" id="drop-zone">
<p>Drag &amp; drop or select</p>
<input type="file" id="image-input" accept="image/*">
<label for="image-input" class="file-label">Select Image</label>
<p style="font-size:11px;color:#a89984;margin-top:10px">Max 2MB - PNG, JPG, GIF, WebP</p>
</div>
</div>
</div>
</div>

<div class="panel">
<h2>Live Preview</h2>
<div class="btn-group">
<button onclick="refreshPreview()">Reload</button>
</div>
<div id="preview" class="preview"><span style="color:#a89984">Loading...</span></div>
</div>

<div id="backup-panel" class="panel" style="display:none">
<h2>Backup Management</h2>
<div class="btn-group">
<button class="danger" onclick="deleteAllBackups()">Delete All</button>
<button class="secondary" onclick="hideBackups()">Close</button>
</div>
<div id="backup-list"></div>
</div>

<footer>
FastFetch WebUI v2.4.1 Public v1.0 | Author: Beardywizz | Made with Lumo AI | MIT License<br>
<small>Local use only - never expose this server to a network.</small>
</footer>
</div>

<script>
'use strict';

// ---- token handling (sessionStorage: cleared when tab closes) -------------
function getToken() {
    let t = sessionStorage.getItem('ff_token');
    if (!t) {
        t = prompt('Enter the auth token (shown in the terminal at startup):');
        if (t) sessionStorage.setItem('ff_token', t);
    }
    return t;
}
function forgetToken() { sessionStorage.removeItem('ff_token'); }

// ---- API helper: re-prompts once on 401 instead of failing silently --------
async function apiCall(endpoint, method, body, retried) {
    method = method || 'GET';
    const resp = await fetch(endpoint, {
        method: method,
        headers: {
            'Authorization': 'Bearer ' + getToken(),
            'Content-Type': 'application/json'
        },
        body: body !== null && body !== undefined ? body : undefined
    });

    if (resp.status === 401 && !retried) {
        forgetToken();
        return apiCall(endpoint, method, body, true);
    }

    const data = await resp.json();
    if (!resp.ok) throw new Error(data.error || 'API error');
    return data;
}

const el = id => document.getElementById(id);
function showStatus(msg, type) {
    const e = el('status');
    e.textContent = msg;
    e.className = 'status show ' + type;
    setTimeout(function(){ e.classList.remove('show'); }, 5000);
}
// XSS defence: escaping for BOTH text and attribute contexts
function escapeHtml(t) {
    return String(t).replace(/[&<>]/g, function(c){
        return {'&':'&amp;','<':'&lt;','>':'&gt;'}[c]; });
}
function escapeAttr(t) {
    return String(t).replace(/[&<>"']/g, function(c){
        return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]; });
}

// ---- config editor ----------------------------------------------------------
async function loadConfig() {
    try {
        const data = await apiCall('/api/config');
        el('editor').value = data.content;
        loadBlocks();
    } catch (e) { showStatus('\u2717 ' + e.message, 'error'); }
}
async function saveConfig() {
    try {
        await apiCall('/api/save', 'POST', el('editor').value);
        showStatus('\u2713 Saved!', 'success');
        refreshPreview();
        loadBlocks();
    } catch (e) { showStatus('\u2717 ' + e.message, 'error'); }
}
async function refreshPreview() {
    try {
        el('preview').textContent = 'Loading...';
        const data = await apiCall('/api/preview');
        el('preview').textContent = data.output || '(No output)';
    } catch (e) { el('preview').textContent = 'Error: ' + e.message; }
}

// ---- module builder (Scratch-style) ---------------------------------------
let activeModules = [], parkedModules = [];

// Categories aligned with the fastfetch man page (--list-modules),
// colors inspired by the user's keyColor scheme
const PALETTE = [
  {cat: 'Hardware',  color: 'green',   items: ['host','board','cpu','gpu','memory','disk','display','monitor','audio']},
  {cat: 'System',    color: '#d9a514', items: ['os','kernel','bios','bootmgr','firmware','packages','shell','font']},
  {cat: 'Desktop',   color: 'blue',    items: ['de','lm','wm','wmtheme','icons','theme','terminal','terminalfont']},
  {cat: 'Time',      color: 'magenta', items: ['uptime','datetime','battery','poweradapter','processes']},
  {cat: 'Extras',    color: 'gray',    items: ['title','break','separator','custom','colors','player','locale','publicip','localip','wallpaper']}
];
const STRING_BLOCKS = ['break', 'title', 'colors', 'separator'];

function paletteColor(type) {
    for (const g of PALETTE)
        if (g.items.indexOf(type) >= 0) return g.color;
    return '#6d4aff';
}

async function loadBlocks() {
    try {
        const data = await apiCall('/api/module-blocks');
        activeModules = data.modules || [];
        parkedModules = data.disabled || [];
        renderPalette();
        renderStacks();
    } catch (e) { showStatus('\u2717 ' + e.message, 'error'); }
}

function renderPalette() {
    el('palette').innerHTML = PALETTE.map(function(g) {
        return '<div class="p-cat"><h4>' + escapeHtml(g.cat) + '</h4>' +
            g.items.map(function(m) {
                return '<button class="p-chip" draggable="true" style="--bc:' +
                    g.color + '" data-new="' + escapeAttr(m) + '">' +
                    escapeHtml(m) + '</button>';
            }).join('') + '</div>';
    }).join('');
    el('palette').querySelectorAll('[data-new]').forEach(function(chip) {
        chip.addEventListener('dragstart', function(e) {
            e.dataTransfer.setData('application/json',
                JSON.stringify({new: chip.dataset.new}));
            e.dataTransfer.effectAllowed = 'copy';
        });
        chip.onclick = function() { addBlock(chip.dataset.new); };
    });
}

function blockHtml(m, i, active) {
    const isObj = typeof m === 'object' && m !== null;
    const type = isObj ? (m.type || 'unknown') : m;
    const desc = isObj
        ? (m.key || Object.keys(m).filter(function(k){return k!=='type';}).join(', '))
        : '';
    const col = paletteColor(type);
    return '<div class="ff-block" draggable="true" style="--bc:' + col +
        '" data-i="' + i + '" data-active="' + (active ? 1 : 0) + '">' +
        '<span class="b-type">' + escapeHtml(type) + '</span>' +
        '<span class="b-key">' + escapeHtml(desc) + '</span>' +
        '<div class="b-sw' + (active ? ' on' : '') + '" data-sw="' + i +
        '" data-act="' + (active ? 1 : 0) + '" title="' +
        (active ? 'Park this module' : 'Activate this module') + '"></div>' +
        '<button class="btn-del" data-del="' + i + '" data-act="' +
        (active ? 1 : 0) + '" title="Remove">\u00d7</button></div>';
}

function renderStacks() {
    const ws = el('module-list'), pk = el('parked-list');
    ws.innerHTML = activeModules.length
        ? activeModules.map(function(m, i) { return blockHtml(m, i, true); }).join('')
        : '<p class="stack-empty">Drag blocks here</p>';
    pk.innerHTML = parkedModules.length
        ? parkedModules.map(function(m, i) { return blockHtml(m, i, false); }).join('')
        : '<p class="stack-empty">Parked modules appear here</p>';
    [ws, pk].forEach(function(stack) {
        stack.querySelectorAll('[data-sw]').forEach(function(sw) {
            sw.onclick = function() {
                const act = sw.dataset.act === '1';
                const arr = act ? activeModules : parkedModules;
                const dst = act ? parkedModules : activeModules;
                dst.push(arr.splice(parseInt(sw.dataset.sw, 10), 1)[0]);
                renderStacks(); schedulePublish();
            };
        });
        stack.querySelectorAll('[data-del]').forEach(function(b) {
            b.onclick = function() {
                if (!confirm('Remove this block permanently?')) return;
                const arr = b.dataset.act === '1' ? activeModules : parkedModules;
                arr.splice(parseInt(b.dataset.del, 10), 1);
                renderStacks(); schedulePublish();
            };
        });
        attachBlockDnD(stack);
    });
}

function addBlock(type) {
    const mod = STRING_BLOCKS.indexOf(type) >= 0 ? type : {type: type};
    activeModules.push(mod);
    renderStacks(); schedulePublish();
}

function attachBlockDnD(stack) {
    const isActive = stack.id === 'module-list';
    stack.querySelectorAll('.ff-block').forEach(function(row) {
        row.addEventListener('dragstart', function(e) {
            e.dataTransfer.setData('application/json', JSON.stringify({
                src: isActive ? 'active' : 'parked',
                i: parseInt(row.dataset.i, 10)
            }));
            e.dataTransfer.effectAllowed = 'move';
            row.classList.add('dragging');
        });
        row.addEventListener('dragend', function() { row.classList.remove('dragging'); });
        row.addEventListener('dragover', function(e) {
            e.preventDefault(); e.dataTransfer.dropEffect = 'move';
            row.classList.add('drop-target');
        });
        row.addEventListener('dragleave', function() { row.classList.remove('drop-target'); });
    });
    stack.addEventListener('dragover', function(e) { e.preventDefault(); });
    stack.addEventListener('drop', function(e) { e.preventDefault(); onDrop(e, stack, isActive); });
}

function onDrop(e, stack, isActive) {
    stack.querySelectorAll('.drop-target').forEach(function(r) {
        r.classList.remove('drop-target'); });
    let p = null;
    try { p = JSON.parse(e.dataTransfer.getData('application/json')); } catch (_) {}

    const target = isActive ? activeModules : parkedModules;
    let pos = target.length;
    const row = e.target.closest('.ff-block');
    if (row) {
        pos = parseInt(row.dataset.i, 10);
        const r = row.getBoundingClientRect();
        if (e.clientY > r.top + r.height / 2) pos += 1;
    }

    if (p && p.new) {
        const mod = STRING_BLOCKS.indexOf(p.new) >= 0 ? p.new : {type: p.new};
        target.splice(pos, 0, mod);
    } else if (p && p.src) {
        const fromActive = p.src === 'active';
        const src = fromActive ? activeModules : parkedModules;
        if (p.i < 0 || p.i >= src.length) return;
        const mod = src.splice(p.i, 1)[0];
        if (p.i < pos) pos -= 1;
        target.splice(pos, 0, mod);
    } else return;
    renderStacks(); schedulePublish();
}

let pubTimer = null;
function schedulePublish() {
    if (pubTimer) clearTimeout(pubTimer);
    pubTimer = setTimeout(publishBuild, 350);
}
async function publishBuild() {
    try {
        await apiCall('/api/build', 'POST',
            JSON.stringify({modules: activeModules, disabled: parkedModules}));
        refreshPreview();
    } catch (e) { showStatus('\u2717 ' + e.message, 'error'); loadBlocks(); }
}

// ---- logo upload ------------------------------------------------------------
async function uploadAscii() {
    try {
        await apiCall('/api/upload-ascii', 'POST',
            JSON.stringify({ascii: el('ascii-editor').value}));
        showStatus('\u2713 Uploaded', 'success');
        refreshPreview();
    } catch (e) { showStatus('\u2717 ' + e.message, 'error'); }
}
async function loadDefaultAscii() {
    try {
        const t = await (await fetch('/api/default-ascii')).text();
        el('ascii-editor').value = t;
    } catch (e) { console.error(e); }
}
const dropZone = el('drop-zone'), fileInput = el('image-input');
dropZone.addEventListener('dragover', function(e) {
    e.preventDefault(); dropZone.style.borderColor = '#b8bb26';
});
dropZone.addEventListener('dragleave', function() {
    dropZone.style.borderColor = 'var(--accent)';
});
dropZone.addEventListener('drop', function(e) {
    e.preventDefault();
    dropZone.style.borderColor = 'var(--accent)';
    if (e.dataTransfer.files.length) handleImage(e.dataTransfer.files[0]);
});
fileInput.addEventListener('change', function(e) {
    if (e.target.files.length) handleImage(e.target.files[0]);
});
async function handleImage(file) {
    if (file.size > 2 * 1024 * 1024) {
        showStatus('\u2717 File exceeds 2MB', 'error');
        return;
    }
    const reader = new FileReader();
    reader.onload = async function(ev) {
        try {
            await apiCall('/api/upload-image', 'POST',
                JSON.stringify({filename: file.name, image: ev.target.result}));
            showStatus('\u2713 Uploaded', 'success');
            refreshPreview();
        } catch (e) { showStatus('\u2717 ' + e.message, 'error'); }
    };
    reader.readAsDataURL(file);
}

// ---- backups ------------------------------------------------------------------
async function showBackups() {
    try {
        el('backup-panel').style.display = 'block';
        const data = await apiCall('/api/backups');
        el('backup-count').textContent = 'Backups: ' + data.backups.length;
        el('backup-list').innerHTML = data.backups.map(function(b) {
            return '<div class="backup-row"><span>' + escapeHtml(b.name) +
                ' (' + Math.round(b.size / 1024) + 'KB)</span>' +
                '<button class="small secondary" data-restore="' +
                escapeAttr(b.name) + '">Restore</button></div>';
        }).join('');
        el('backup-list').querySelectorAll('[data-restore]').forEach(function(btn) {
            btn.onclick = function(){ restoreBackup(btn.dataset.restore); };
        });
    } catch (e) { showStatus('\u2717 ' + e.message, 'error'); }
}
function hideBackups() { el('backup-panel').style.display = 'none'; }
async function restoreBackup(name) {
    try {
        await apiCall('/api/load-backup', 'POST', JSON.stringify({name: name}));
        loadConfig();
        refreshPreview();
        hideBackups();
        showStatus('\u2713 Restored', 'success');
    } catch (e) { showStatus('\u2717 ' + e.message, 'error'); }
}
async function deleteAllBackups() {
    if (!confirm('Delete ALL backups?')) return;
    try {
        const data = await apiCall('/api/delete-backups', 'POST');
        showStatus('\u2713 Deleted ' + data.deleted + ' backups', 'success');
        showBackups();
    } catch (e) { showStatus('\u2717 ' + e.message, 'error'); }
}

// ---- init ----------------------------------------------------------------------
getToken();
loadConfig();
refreshPreview();
loadDefaultAscii();

// Health poll: updates status badges (public endpoint, no token needed)
setInterval(async function() {
    try {
        const r = await fetch('/api/health');
        const h = await r.json();
        el('config-status').textContent = h.config_exists ?
            '\u2713 Config OK' : 'No config';
        el('auth-status').textContent = h.auth_required ?
            'Auth active' : 'Auth inactive';
    } catch (e) { /* server unreachable: ignore */ }
}, 3000);
</script>
</body>
</html>'''

#===============================================================================
# SERVER STARTUP
#===============================================================================

def print_banner():
    """Startup info. The token itself is NEVER printed here."""
    print("\n" + "=" * 60)
    print("  FastFetch WebUI v2.4.1 Public v1.0 - Scratch-style Block Builder Edition")
    print("=" * 60)
    print("\n  Config  : " + str(CONFIG_FILE))
    print("  State   : " + str(STATE_FILE))
    print("  Backups : " + str(BACKUP_DIR))
    print("  ASCII   : " + str(ASCII_DIR))
    print("  Logos   : " + str(LOGO_DIR))
    print("  Mode    : " + ("HTTPS" if SSL_ENABLED else "HTTP") +
          " | auth: bearer token | host-lock: loopback only")
    print("  Token   : set via WEBAUTH_TOKEN, CLI prompt, or one-time random")
    print("=" * 60 + "\n")

def main():
    setup_directories()

    # Token resolution FIRST (fail-closed before anything is served)
    if not setup_auth():
        raise SystemExit(1)

    print_banner()
    create_index_file()

    # Graceful termination: SIGINT/SIGTERM -> SystemExit -> atexit cleanup
    signal.signal(signal.SIGTERM, terminate_handler)
    signal.signal(signal.SIGINT, terminate_handler)

    server = ThreadingHTTPServer((HOST, PORT), Handler)
    server.daemon_threads = True

    if SSL_ENABLED:
        ctx = generate_ssl_context()
        if ctx:
            server.socket = ctx.wrap_socket(server.socket, server_side=True)
            print("[INFO] HTTPS enabled")
        else:
            print("[WARN] SSL unavailable - continuing with plain HTTP")

    url = f"{'https' if SSL_ENABLED else 'http'}://{HOST}:{PORT}"
    print(f"[INFO] Serving at {url}")
    print("[INFO] Press Ctrl+C to stop\n")

    def open_browser():
        time.sleep(1.5)
        try:
            webbrowser.open(url)
        except Exception:
            pass

    threading.Thread(target=open_browser, daemon=True).start()

    try:
        server.serve_forever()
    except (KeyboardInterrupt, SystemExit):
        print("\n[INFO] Shutting down...")
    finally:
        server.server_close()
        cleanup_index_file()
        print("[INFO] Server stopped - temporary files removed.")

if __name__ == '__main__':
    main()
