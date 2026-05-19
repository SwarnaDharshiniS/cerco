"""
Capability Analysis Engine — data model.

Defines all static data (capability registries) and the dataclasses
used to represent findings and reports.

Capability classes
------------------
  FS    – filesystem access (read, write, delete, list, …)
  NET   – network access (sockets, HTTP clients, DNS, …)
  PROC  – process / subprocess spawning
  DYN   – dynamic execution (eval, exec, importlib, …)

Each registry entry maps a *dotted qualified name* to a `CapabilityDef`
which records the class, severity and a short human-readable reason.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


# ---------------------------------------------------------------------------
# Capability class enum
# ---------------------------------------------------------------------------

class CapClass(str, Enum):
    FS   = "FS"    # filesystem
    NET  = "NET"   # network
    PROC = "PROC"  # process / subprocess
    DYN  = "DYN"   # dynamic execution


class Severity(str, Enum):
    HIGH   = "HIGH"
    MEDIUM = "MEDIUM"
    LOW    = "LOW"


# ---------------------------------------------------------------------------
# Registry entry
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class CapabilityDef:
    """Static definition of one capability signal."""
    cap_class: CapClass
    severity:  Severity
    reason:    str          # one-line description shown in reports


# ---------------------------------------------------------------------------
# Registry helpers
# ---------------------------------------------------------------------------

def _fs(sev: Severity, reason: str) -> CapabilityDef:
    return CapabilityDef(CapClass.FS,   sev, reason)

def _net(sev: Severity, reason: str) -> CapabilityDef:
    return CapabilityDef(CapClass.NET,  sev, reason)

def _proc(sev: Severity, reason: str) -> CapabilityDef:
    return CapabilityDef(CapClass.PROC, sev, reason)

def _dyn(sev: Severity, reason: str) -> CapabilityDef:
    return CapabilityDef(CapClass.DYN,  sev, reason)

H, M, L = Severity.HIGH, Severity.MEDIUM, Severity.LOW


# ---------------------------------------------------------------------------
# Call-based signals  (dotted qualified name → CapabilityDef)
# ---------------------------------------------------------------------------

CALL_SIGNALS: dict[str, CapabilityDef] = {
    # ── FS ──────────────────────────────────────────────────────────────────
    "open":                     _fs(H,  "built-in open() reads/writes files"),
    "io.open":                  _fs(H,  "io.open() reads/writes files"),
    "os.open":                  _fs(H,  "os.open() low-level file descriptor"),
    "os.read":                  _fs(M,  "os.read() reads from file descriptor"),
    "os.write":                 _fs(M,  "os.write() writes to file descriptor"),
    "os.close":                 _fs(L,  "os.close() closes file descriptor"),
    "os.remove":                _fs(H,  "os.remove() deletes a file"),
    "os.unlink":                _fs(H,  "os.unlink() deletes a file"),
    "os.rename":                _fs(M,  "os.rename() renames/moves a file"),
    "os.replace":               _fs(M,  "os.replace() atomically replaces a file"),
    "os.makedirs":              _fs(M,  "os.makedirs() creates directory tree"),
    "os.mkdir":                 _fs(M,  "os.mkdir() creates a directory"),
    "os.rmdir":                 _fs(M,  "os.rmdir() removes a directory"),
    "os.listdir":               _fs(L,  "os.listdir() lists directory contents"),
    "os.scandir":               _fs(L,  "os.scandir() iterates directory entries"),
    "os.walk":                  _fs(L,  "os.walk() walks directory tree"),
    "os.stat":                  _fs(L,  "os.stat() reads file metadata"),
    "os.chmod":                 _fs(M,  "os.chmod() changes file permissions"),
    "os.chown":                 _fs(M,  "os.chown() changes file ownership"),
    "os.truncate":              _fs(H,  "os.truncate() truncates a file"),
    "os.link":                  _fs(M,  "os.link() creates a hard link"),
    "os.symlink":               _fs(M,  "os.symlink() creates a symbolic link"),
    "os.readlink":              _fs(L,  "os.readlink() reads a symlink target"),
    "os.getcwd":                _fs(L,  "os.getcwd() reads current directory"),
    "os.chdir":                 _fs(M,  "os.chdir() changes current directory"),
    "os.access":                _fs(L,  "os.access() checks file permissions"),
    "shutil.copy":              _fs(M,  "shutil.copy() copies a file"),
    "shutil.copy2":             _fs(M,  "shutil.copy2() copies a file with metadata"),
    "shutil.copyfile":          _fs(M,  "shutil.copyfile() copies file contents"),
    "shutil.copytree":          _fs(M,  "shutil.copytree() copies a directory tree"),
    "shutil.rmtree":            _fs(H,  "shutil.rmtree() deletes a directory tree"),
    "shutil.move":              _fs(M,  "shutil.move() moves a file or directory"),
    "shutil.disk_usage":        _fs(L,  "shutil.disk_usage() reads disk statistics"),
    "pathlib.Path.read_text":   _fs(H,  "Path.read_text() reads file contents"),
    "pathlib.Path.write_text":  _fs(H,  "Path.write_text() writes file contents"),
    "pathlib.Path.read_bytes":  _fs(H,  "Path.read_bytes() reads file bytes"),
    "pathlib.Path.write_bytes": _fs(H,  "Path.write_bytes() writes file bytes"),
    "pathlib.Path.unlink":      _fs(H,  "Path.unlink() deletes a file"),
    "pathlib.Path.mkdir":       _fs(M,  "Path.mkdir() creates a directory"),
    "pathlib.Path.rmdir":       _fs(M,  "Path.rmdir() removes a directory"),
    "pathlib.Path.rename":      _fs(M,  "Path.rename() renames a path"),
    "pathlib.Path.glob":        _fs(L,  "Path.glob() lists matching paths"),
    "pathlib.Path.iterdir":     _fs(L,  "Path.iterdir() iterates directory"),
    "tempfile.mkstemp":         _fs(M,  "tempfile.mkstemp() creates temp file"),
    "tempfile.mkdtemp":         _fs(M,  "tempfile.mkdtemp() creates temp dir"),
    "tempfile.NamedTemporaryFile": _fs(M, "NamedTemporaryFile() creates temp file"),
    "fileinput.input":          _fs(M,  "fileinput.input() reads multiple files"),
    "glob.glob":                _fs(L,  "glob.glob() lists matching files"),
    "glob.iglob":               _fs(L,  "glob.iglob() yields matching files"),
    "fnmatch.fnmatch":          _fs(L,  "fnmatch.fnmatch() matches filenames"),
    "zipfile.ZipFile":          _fs(M,  "ZipFile() reads/writes ZIP archives"),
    "tarfile.open":             _fs(M,  "tarfile.open() reads/writes tar archives"),
    "gzip.open":                _fs(M,  "gzip.open() reads/writes gzip files"),
    "bz2.open":                 _fs(M,  "bz2.open() reads/writes bz2 files"),
    "lzma.open":                _fs(M,  "lzma.open() reads/writes xz/lzma files"),
    "csv.reader":               _fs(L,  "csv.reader() parses CSV input"),
    "csv.writer":               _fs(L,  "csv.writer() writes CSV output"),
    "json.load":                _fs(L,  "json.load() deserialises from file"),
    "json.dump":                _fs(L,  "json.dump() serialises to file"),
    "pickle.load":              _fs(H,  "pickle.load() deserialises (unsafe)"),
    "pickle.dump":              _fs(M,  "pickle.dump() serialises to file"),
    "shelve.open":              _fs(M,  "shelve.open() opens a persistent shelf"),
    "dbm.open":                 _fs(M,  "dbm.open() opens a DBM database"),
    "sqlite3.connect":          _fs(M,  "sqlite3.connect() opens SQLite database"),
    "configparser.ConfigParser.read": _fs(L, "ConfigParser.read() reads config file"),

    # ── NET ─────────────────────────────────────────────────────────────────
    "socket.socket":            _net(H,  "socket.socket() creates a raw socket"),
    "socket.create_connection": _net(H,  "creates a TCP connection"),
    "socket.getaddrinfo":       _net(M,  "resolves a hostname (DNS)"),
    "socket.gethostbyname":     _net(M,  "resolves a hostname (DNS)"),
    "socket.gethostname":       _net(L,  "reads the local hostname"),
    "ssl.wrap_socket":          _net(M,  "wraps socket in TLS"),
    "ssl.create_default_context": _net(M, "creates TLS context"),
    "ssl.SSLContext":           _net(M,  "creates TLS context"),
    "requests.get":             _net(H,  "HTTP GET via requests"),
    "requests.post":            _net(H,  "HTTP POST via requests"),
    "requests.put":             _net(H,  "HTTP PUT via requests"),
    "requests.delete":          _net(H,  "HTTP DELETE via requests"),
    "requests.patch":           _net(H,  "HTTP PATCH via requests"),
    "requests.head":            _net(M,  "HTTP HEAD via requests"),
    "requests.request":         _net(H,  "generic HTTP via requests"),
    "requests.Session":         _net(H,  "HTTP session via requests"),
    "urllib.request.urlopen":   _net(H,  "urllib opens a URL"),
    "urllib.request.urlretrieve": _net(H, "urllib downloads a URL"),
    "urllib.request.Request":   _net(M,  "urllib builds an HTTP request"),
    "http.client.HTTPConnection":  _net(H, "low-level HTTP connection"),
    "http.client.HTTPSConnection": _net(H, "low-level HTTPS connection"),
    "httplib.HTTPConnection":   _net(H,  "httplib HTTP connection"),
    "ftplib.FTP":               _net(H,  "FTP connection"),
    "smtplib.SMTP":             _net(H,  "SMTP connection (email)"),
    "smtplib.SMTP_SSL":         _net(H,  "SMTP/SSL connection (email)"),
    "imaplib.IMAP4":            _net(H,  "IMAP4 connection (email)"),
    "poplib.POP3":              _net(H,  "POP3 connection (email)"),
    "xmlrpc.client.ServerProxy": _net(H, "XML-RPC client"),
    "paramiko.SSHClient":       _net(H,  "SSH client via paramiko"),
    "paramiko.Transport":       _net(H,  "SSH transport via paramiko"),
    "asyncio.open_connection":  _net(H,  "async TCP connection"),
    "asyncio.start_server":     _net(H,  "async TCP server"),
    "aiohttp.ClientSession":    _net(H,  "async HTTP via aiohttp"),
    "httpx.get":                _net(H,  "HTTP GET via httpx"),
    "httpx.post":               _net(H,  "HTTP POST via httpx"),
    "httpx.Client":             _net(H,  "HTTP client via httpx"),
    "httpx.AsyncClient":        _net(H,  "async HTTP client via httpx"),
    "pycurl.Curl":              _net(H,  "HTTP via pycurl"),
    "grpc.insecure_channel":    _net(H,  "gRPC insecure channel"),
    "grpc.secure_channel":      _net(H,  "gRPC secure channel"),
    "websockets.connect":       _net(H,  "WebSocket connection"),
    "websocket.WebSocketApp":   _net(H,  "WebSocket via websocket-client"),
    "dns.resolver.resolve":     _net(M,  "DNS resolution via dnspython"),
    "dns.resolver.query":       _net(M,  "DNS query via dnspython"),

    # ── PROC ────────────────────────────────────────────────────────────────
    "os.system":                _proc(H, "os.system() spawns a shell command"),
    "os.popen":                 _proc(H, "os.popen() opens a pipe to a command"),
    "os.execv":                 _proc(H, "os.execv() replaces process image"),
    "os.execve":                _proc(H, "os.execve() replaces process image"),
    "os.execvp":                _proc(H, "os.execvp() replaces process image"),
    "os.execvpe":               _proc(H, "os.execvpe() replaces process image"),
    "os.execl":                 _proc(H, "os.execl() replaces process image"),
    "os.execle":                _proc(H, "os.execle() replaces process image"),
    "os.execlp":                _proc(H, "os.execlp() replaces process image"),
    "os.execlpe":               _proc(H, "os.execlpe() replaces process image"),
    "os.spawnl":                _proc(H, "os.spawnl() spawns a subprocess"),
    "os.spawnle":               _proc(H, "os.spawnle() spawns a subprocess"),
    "os.spawnv":                _proc(H, "os.spawnv() spawns a subprocess"),
    "os.spawnve":               _proc(H, "os.spawnve() spawns a subprocess"),
    "os.spawnvp":               _proc(H, "os.spawnvp() spawns a subprocess"),
    "os.fork":                  _proc(H, "os.fork() forks the process"),
    "os.forkpty":               _proc(H, "os.forkpty() forks with a pty"),
    "os.waitpid":               _proc(M, "os.waitpid() waits for child process"),
    "os.kill":                  _proc(H, "os.kill() sends a signal"),
    "os.killpg":                _proc(H, "os.killpg() sends signal to group"),
    "subprocess.run":           _proc(H, "subprocess.run() spawns a process"),
    "subprocess.Popen":         _proc(H, "subprocess.Popen() spawns a process"),
    "subprocess.call":          _proc(H, "subprocess.call() spawns a process"),
    "subprocess.check_call":    _proc(H, "subprocess.check_call() spawns a process"),
    "subprocess.check_output":  _proc(H, "subprocess.check_output() captures output"),
    "subprocess.getoutput":     _proc(M, "subprocess.getoutput() captures shell output"),
    "subprocess.getstatusoutput": _proc(M, "subprocess.getstatusoutput() captures output"),
    "multiprocessing.Process":  _proc(M, "multiprocessing.Process() spawns a process"),
    "multiprocessing.Pool":     _proc(M, "multiprocessing.Pool() spawns worker pool"),
    "concurrent.futures.ProcessPoolExecutor": _proc(M, "ProcessPoolExecutor spawns processes"),
    "pty.spawn":                _proc(H, "pty.spawn() spawns under a pseudoterminal"),
    "pexpect.spawn":            _proc(H, "pexpect.spawn() spawns and interacts with process"),
    "fabric.Connection.run":    _proc(H, "fabric runs remote command over SSH"),

    # ── DYN ─────────────────────────────────────────────────────────────────
    "eval":                     _dyn(H, "eval() executes a Python expression"),
    "exec":                     _dyn(H, "exec() executes Python statements"),
    "compile":                  _dyn(H, "compile() compiles source to bytecode"),
    "__import__":               _dyn(H, "__import__() dynamic module import"),
    "importlib.import_module":  _dyn(H, "importlib.import_module() dynamic import"),
    "importlib.reload":         _dyn(M, "importlib.reload() reloads a module"),
    "importlib.util.spec_from_file_location": _dyn(H, "loads module from file path"),
    "importlib.util.module_from_spec": _dyn(H, "creates module from spec"),
    "types.FunctionType":       _dyn(M, "constructs a function object dynamically"),
    "ctypes.CDLL":              _dyn(H, "ctypes.CDLL() loads a native shared library"),
    "ctypes.cdll.LoadLibrary":  _dyn(H, "loads a native shared library"),
    "ctypes.WinDLL":            _dyn(H, "loads a Windows DLL"),
    "cffi.FFI":                 _dyn(H, "cffi.FFI() interfaces with native code"),
    "pickle.loads":             _dyn(H, "pickle.loads() executes arbitrary objects"),
    "marshal.loads":            _dyn(H, "marshal.loads() loads bytecode objects"),
    "ast.literal_eval":         _dyn(L, "ast.literal_eval() evaluates a literal"),
    "code.InteractiveConsole":  _dyn(H, "spawns an interactive Python console"),
    "code.InteractiveInterpreter": _dyn(H, "runs arbitrary Python interactively"),
}


# ── Import-based signals (module name → CapabilityDef)  ──────────────────────
# Merely importing these modules signals the capability, even with no call sites.

IMPORT_SIGNALS: dict[str, CapabilityDef] = {
    # FS
    "os":           _fs(L,   "os module provides filesystem access"),
    "os.path":      _fs(L,   "os.path provides filesystem path utilities"),
    "pathlib":      _fs(L,   "pathlib provides object-oriented path handling"),
    "shutil":       _fs(L,   "shutil provides high-level file operations"),
    "tempfile":     _fs(L,   "tempfile provides temporary file creation"),
    "glob":         _fs(L,   "glob provides filename pattern matching"),
    "fnmatch":      _fs(L,   "fnmatch provides filename pattern matching"),
    "fileinput":    _fs(L,   "fileinput reads from multiple input files"),
    "io":           _fs(L,   "io provides core I/O utilities"),
    "zipfile":      _fs(L,   "zipfile reads/writes ZIP archives"),
    "tarfile":      _fs(L,   "tarfile reads/writes tar archives"),
    "gzip":         _fs(L,   "gzip reads/writes gzip files"),
    "bz2":          _fs(L,   "bz2 reads/writes bz2 files"),
    "lzma":         _fs(L,   "lzma reads/writes xz/lzma files"),
    "sqlite3":      _fs(L,   "sqlite3 embeds an SQL database"),
    "shelve":       _fs(L,   "shelve provides a persistent dictionary"),
    "dbm":          _fs(L,   "dbm provides a DBM-style database"),
    "pickle":       _fs(M,   "pickle (de)serialises Python objects"),
    "marshal":      _fs(M,   "marshal loads/dumps Python code objects"),
    # NET
    "socket":       _net(M,  "socket provides raw network access"),
    "ssl":          _net(M,  "ssl provides TLS/SSL support"),
    "requests":     _net(M,  "requests is an HTTP library"),
    "urllib":       _net(M,  "urllib provides URL handling"),
    "urllib.request": _net(M, "urllib.request opens URLs"),
    "http":         _net(M,  "http provides HTTP client/server"),
    "http.client":  _net(M,  "http.client provides HTTP connections"),
    "ftplib":       _net(M,  "ftplib provides FTP connections"),
    "smtplib":      _net(M,  "smtplib provides SMTP connections"),
    "imaplib":      _net(M,  "imaplib provides IMAP connections"),
    "poplib":       _net(M,  "poplib provides POP3 connections"),
    "xmlrpc":       _net(M,  "xmlrpc provides XML-RPC client/server"),
    "paramiko":     _net(M,  "paramiko provides SSH connections"),
    "asyncio":      _net(L,  "asyncio may be used for network I/O"),
    "aiohttp":      _net(M,  "aiohttp provides async HTTP"),
    "httpx":        _net(M,  "httpx provides sync/async HTTP"),
    "pycurl":       _net(M,  "pycurl provides libcurl bindings"),
    "grpc":         _net(M,  "grpc provides gRPC communication"),
    "websockets":   _net(M,  "websockets provides WebSocket support"),
    "websocket":    _net(M,  "websocket-client provides WebSocket support"),
    "dns":          _net(M,  "dnspython provides DNS lookups"),
    # PROC
    "os":           _proc(L, "os module provides process control"),
    "subprocess":   _proc(M, "subprocess spawns child processes"),
    "multiprocessing": _proc(M, "multiprocessing spawns worker processes"),
    "concurrent.futures": _proc(L, "concurrent.futures may spawn processes"),
    "pty":          _proc(M, "pty provides pseudoterminal support"),
    "pexpect":      _proc(M, "pexpect spawns and controls processes"),
    "signal":       _proc(L, "signal sends UNIX signals"),
    # DYN
    "importlib":    _dyn(M,  "importlib provides dynamic import machinery"),
    "types":        _dyn(L,  "types module includes dynamic type construction"),
    "ctypes":       _dyn(H,  "ctypes provides C foreign function interface"),
    "cffi":         _dyn(H,  "cffi provides C foreign function interface"),
    "ast":          _dyn(L,  "ast module may be used for dynamic code manipulation"),
    "code":         _dyn(H,  "code module provides interactive interpreters"),
}

# ---------------------------------------------------------------------------
# Finding dataclasses
# ---------------------------------------------------------------------------

@dataclass
class CapabilityUse:
    """One detected use of a capability in the source code."""
    cap_class:  CapClass
    severity:   Severity
    kind:       str            # "call" | "import"
    symbol:     str            # e.g. "os.system", "subprocess"
    alias:      str | None     # local alias if different from symbol, else None
    line:       int | None
    col:        int | None
    reason:     str

    def to_dict(self) -> dict[str, Any]:
        return {
            "cap_class":  self.cap_class.value,
            "severity":   self.severity.value,
            "kind":       self.kind,
            "symbol":     self.symbol,
            "alias":      self.alias,
            "line":       self.line,
            "col":        self.col,
            "reason":     self.reason,
        }


@dataclass
class CapabilityReport:
    """Aggregated capability report for one file / source string."""
    source_name: str
    uses: list[CapabilityUse] = field(default_factory=list)

    # ------------------------------------------------------------------ helpers

    def by_class(self, cap: CapClass) -> list[CapabilityUse]:
        return [u for u in self.uses if u.cap_class == cap]

    def has(self, cap: CapClass) -> bool:
        return any(u.cap_class == cap for u in self.uses)

    def capabilities_present(self) -> list[CapClass]:
        return sorted({u.cap_class for u in self.uses}, key=lambda c: c.value)

    def highest_severity(self) -> Severity | None:
        order = [Severity.HIGH, Severity.MEDIUM, Severity.LOW]
        for s in order:
            if any(u.severity == s for u in self.uses):
                return s
        return None

    # ------------------------------------------------------------------ serialisation

    def to_dict(self) -> dict[str, Any]:
        by_cap: dict[str, list[dict]] = {}
        for u in self.uses:
            by_cap.setdefault(u.cap_class.value, []).append(u.to_dict())

        return {
            "source": self.source_name,
            "summary": {
                "capabilities": [c.value for c in self.capabilities_present()],
                "highest_severity": self.highest_severity().value if self.highest_severity() else None,
                "total_uses": len(self.uses),
                "FS":   len(self.by_class(CapClass.FS)),
                "NET":  len(self.by_class(CapClass.NET)),
                "PROC": len(self.by_class(CapClass.PROC)),
                "DYN":  len(self.by_class(CapClass.DYN)),
            },
            "by_capability": by_cap,
        }

    def to_json(self, *, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)

    def __repr__(self) -> str:
        caps = ", ".join(c.value for c in self.capabilities_present()) or "none"
        return (
            f"<CapabilityReport '{self.source_name}' "
            f"caps=[{caps}] uses={len(self.uses)}>"
        )
