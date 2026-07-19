"""
Taint Analysis Engine — data model.

Defines the immutable data types used throughout the engine:

  ChainStep    – one propagation hop (source → variable → variable → sink)
  TaintTag     – a piece of taint anchored to a specific source, carrying
                 its full propagation chain
  TaintFinding – a confirmed source→sink flow with full path information
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any


# ---------------------------------------------------------------------------
# Propagation chain
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ChainStep:
    """One step in the propagation chain from a taint source."""
    variable: str           # variable that received the taint
    line: int | None        # line number of the assignment
    col: int | None         # column offset
    how: str                # "assign" | "aug_assign" | "binop" | "fstring" |
                            # "subscript" | "call_arg" | "unpack" | "attr" |
                            # "return" | "loop_target" | "container"


# ---------------------------------------------------------------------------
# Taint tag
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class TaintTag:
    """
    Immutable token representing a unit of taint originating from one source.

    Tags are propagated through assignments and expressions; each hop appends
    a ChainStep so the full path from source to any sink can be reconstructed.
    """
    source_kind: str        # "input" | "sys_argv" | "env_var" | "stdin" | "argv_import"
    source_line: int | None
    source_col: int | None
    source_expr: str        # human-readable, e.g. "input()", "sys.argv[1]"
    chain: tuple[ChainStep, ...] = ()

    def extend(self, variable: str, line: int | None, col: int | None, how: str) -> "TaintTag":
        """Return a new tag with *one* extra propagation step appended."""
        step = ChainStep(variable=variable, line=line, col=col, how=how)
        return TaintTag(
            source_kind=self.source_kind,
            source_line=self.source_line,
            source_col=self.source_col,
            source_expr=self.source_expr,
            chain=(*self.chain, step),
        )

    def path_summary(self) -> list[dict]:
        steps = [
            {
                "kind": "source",
                "expr": self.source_expr,
                "line": self.source_line,
                "col": self.source_col,
            }
        ]
        for s in self.chain:
            steps.append({
                "kind": s.how,
                "variable": s.variable,
                "line": s.line,
                "col": s.col,
            })
        return steps


# ---------------------------------------------------------------------------
# Source / sink registries
# ---------------------------------------------------------------------------

# Dotted call name → (kind, human label)
SOURCES: dict[str, tuple[str, str]] = {
    "input":                    ("input",      "input()"),
    "sys.stdin.read":           ("stdin",      "sys.stdin.read()"),
    "sys.stdin.readline":       ("stdin",      "sys.stdin.readline()"),
    "os.environ.get":           ("env_var",    "os.environ.get()"),
    "os.getenv":                ("env_var",    "os.getenv()"),
}

# Attribute/name that IS a source when merely accessed (not called)
SOURCE_ATTRS: dict[str, tuple[str, str]] = {
    "sys.argv":     ("sys_argv", "sys.argv"),
    "os.environ":   ("env_var",  "os.environ"),
    "sys.stdin":    ("stdin",    "sys.stdin"),
}

# Dotted call name → (sink_kind, severity, description)
SINKS: dict[str, tuple[str, str, str]] = {
    # Command injection
    "os.system":                    ("command_injection", "CRITICAL", "os.system"),
    "os.popen":                     ("command_injection", "CRITICAL", "os.popen"),
    "os.execv":                     ("command_injection", "CRITICAL", "os.execv"),
    "os.execve":                    ("command_injection", "CRITICAL", "os.execve"),
    "os.execvp":                    ("command_injection", "CRITICAL", "os.execvp"),
    "os.execvpe":                   ("command_injection", "CRITICAL", "os.execvpe"),
    "os.spawnl":                    ("command_injection", "CRITICAL", "os.spawnl"),
    "os.spawnle":                   ("command_injection", "CRITICAL", "os.spawnle"),
    "os.spawnv":                    ("command_injection", "CRITICAL", "os.spawnv"),
    "subprocess.run":               ("command_injection", "CRITICAL", "subprocess.run"),
    "subprocess.Popen":             ("command_injection", "CRITICAL", "subprocess.Popen"),
    "subprocess.call":              ("command_injection", "CRITICAL", "subprocess.call"),
    "subprocess.check_call":        ("command_injection", "CRITICAL", "subprocess.check_call"),
    "subprocess.check_output":      ("command_injection", "CRITICAL", "subprocess.check_output"),
    "subprocess.getoutput":         ("command_injection", "HIGH",     "subprocess.getoutput"),
    "subprocess.getstatusoutput":   ("command_injection", "HIGH",     "subprocess.getstatusoutput"),
    # Code injection
    "eval":                         ("code_injection",    "CRITICAL", "eval"),
    "exec":                         ("code_injection",    "CRITICAL", "exec"),
    "compile":                      ("code_injection",    "HIGH",     "compile"),
    "__import__":                   ("code_injection",    "HIGH",     "__import__"),
    "importlib.import_module":      ("code_injection",    "HIGH",     "importlib.import_module"),
    # Path traversal (lower severity)
    "open":                         ("path_traversal",    "MEDIUM",   "open"),
    "os.remove":                    ("path_traversal",    "MEDIUM",   "os.remove"),
    "os.unlink":                    ("path_traversal",    "MEDIUM",   "os.unlink"),
    "os.rename":                    ("path_traversal",    "MEDIUM",   "os.rename"),
    "os.makedirs":                  ("path_traversal",    "MEDIUM",   "os.makedirs"),
    "os.mkdir":                     ("path_traversal",    "MEDIUM",   "os.mkdir"),
    "shutil.rmtree":                ("path_traversal",    "HIGH",     "shutil.rmtree"),
    "shutil.copy":                  ("path_traversal",    "MEDIUM",   "shutil.copy"),
    # SSRF / URL
    "urllib.request.urlopen":       ("ssrf",              "HIGH",     "urllib.request.urlopen"),
    "urllib.request.urlretrieve":   ("ssrf",              "HIGH",     "urllib.request.urlretrieve"),
    "requests.get":                 ("ssrf",              "HIGH",     "requests.get"),
    "requests.post":                ("ssrf",              "HIGH",     "requests.post"),
    "requests.put":                 ("ssrf",              "HIGH",     "requests.put"),
    "requests.request":             ("ssrf",              "HIGH",     "requests.request"),
}

# Dotted call name → True if it sanitizes taint completely
SANITIZERS: set[str] = {
    "int", "float", "bool",
    "shlex.quote",
    "re.escape",
    "html.escape",
    "xml.sax.saxutils.escape",
    "urllib.parse.quote",
    "urllib.parse.quote_plus",
}

# String methods that do NOT sanitize (taint passes through)
TAINT_PASSING_STR_METHODS = {
    "strip", "lstrip", "rstrip", "upper", "lower", "title", "capitalize",
    "replace", "split", "rsplit", "join", "format", "format_map",
    "encode", "decode", "expandtabs", "center", "ljust", "rjust",
    "removeprefix", "removesuffix", "partition", "rpartition",
    "zfill", "translate",
}


# ---------------------------------------------------------------------------
# Finding
# ---------------------------------------------------------------------------

@dataclass
class TaintFinding:
    """A confirmed taint flow from a source to a dangerous sink."""

    sink_name: str          # e.g. "os.system"
    sink_kind: str          # "command_injection" | "code_injection" | ...
    sink_line: int | None
    sink_col: int | None
    severity: str           # "CRITICAL" | "HIGH" | "MEDIUM"
    tags: list[TaintTag]    # all taint sources that reach this sink
    message: str = ""

    def __post_init__(self) -> None:
        if not self.message:
            sources = ", ".join(sorted({t.source_expr for t in self.tags}))
            self.message = (
                f"[{self.severity}] {self.sink_name} called with tainted data "
                f"from {sources} at line {self.sink_line}"
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "severity": self.severity,
            "sink": self.sink_name,
            "sink_kind": self.sink_kind,
            "location": {"line": self.sink_line, "col": self.sink_col},
            "sources": [
                {
                    "kind": t.source_kind,
                    "expr": t.source_expr,
                    "line": t.source_line,
                    "col": t.source_col,
                }
                for t in self.tags
            ],
            "taint_paths": [t.path_summary() for t in self.tags],
            "message": self.message,
        }

    def __str__(self) -> str:
        return self.message
