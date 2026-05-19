"""
Capability Analysis Engine — AST traversal core.

Walks the Python AST in two coordinated passes:

Pass 1 — Import collection
    Records every `import X`, `import X as Y`, `from M import N`,
    `from M import N as A` statement.  Builds two alias tables:

        module_aliases : local_name → canonical_module
            e.g.  "import os as o"          → {"o": "os"}
            e.g.  "import subprocess as sp" → {"sp": "subprocess"}

        name_aliases   : local_name → canonical_dotted_name
            e.g.  "from subprocess import Popen"    → {"Popen": "subprocess.Popen"}
            e.g.  "from os import system as run_it" → {"run_it": "os.system"}

Pass 2 — Call / use detection
    Visits every Call node and resolves its qualified name through
    the alias tables, then looks it up in CALL_SIGNALS.

    Also emits CapabilityUse entries for every matched import
    (from IMPORT_SIGNALS).

De-duplication
    Import-level findings are de-duplicated per (symbol, kind) pair so
    that `import os` appearing multiple times creates one entry.
"""

from __future__ import annotations

import ast
import json
from pathlib import Path
from typing import Any

from ._model import (
    CapabilityDef,
    CapabilityReport,
    CapabilityUse,
    CapClass,
    Severity,
    CALL_SIGNALS,
    IMPORT_SIGNALS,
)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def analyze_source(source: str, name: str = "<string>") -> CapabilityReport:
    """Analyse Python *source* string and return a `CapabilityReport`."""
    tree = ast.parse(source, filename=name)
    return CapabilityAnalyzer(name).analyze(tree)


def analyze_file(path: str | Path) -> CapabilityReport:
    """Analyse a Python source file and return a `CapabilityReport`."""
    path = Path(path)
    source = path.read_text(encoding="utf-8")
    return analyze_source(source, name=str(path))


def analyze_to_dict(source: str, name: str = "<string>") -> dict[str, Any]:
    """Analyse *source* and return a JSON-serialisable report dict."""
    return analyze_source(source, name).to_dict()


# ---------------------------------------------------------------------------
# Analyzer
# ---------------------------------------------------------------------------

class CapabilityAnalyzer(ast.NodeVisitor):
    """
    Single-pass (with two sub-phases) AST analyzer.

    Usage::

        report = CapabilityAnalyzer("<module>").analyze(ast.parse(source))
    """

    def __init__(self, source_name: str = "<string>") -> None:
        self._name = source_name
        self._report = CapabilityReport(source_name=source_name)

        # alias tables built during import pass
        # local_name → canonical module  (e.g. "o" → "os")
        self._module_aliases:  dict[str, str] = {}
        # local_name → canonical dotted symbol (e.g. "Popen" → "subprocess.Popen")
        self._name_aliases:    dict[str, str] = {}
        # track (symbol, kind) to avoid duplicate import-level entries
        self._seen_imports: set[tuple[str, str]] = set()

    # ------------------------------------------------------------------ entry

    def analyze(self, tree: ast.AST) -> CapabilityReport:
        # Pass 1: collect imports
        _ImportCollector(self).visit(tree)
        # Pass 2: detect call sites + emit import findings
        self.visit(tree)
        return self._report

    # ------------------------------------------------------------------ import visitors

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            canonical = alias.name
            local = alias.asname or alias.name.split(".")[0]
            if alias.asname:
                self._module_aliases[alias.asname] = canonical
            else:
                # "import os.path" → "os" in scope, but canonical is "os.path"
                self._module_aliases[local] = canonical

            # Emit import finding
            self._maybe_emit_import(canonical, local if alias.asname else None,
                                    node.lineno, node.col_offset)

        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        module = node.module or ""
        for alias in node.names:
            if alias.name == "*":
                # wildcard: can't resolve; emit module-level signal only
                self._maybe_emit_import(module, None, node.lineno, node.col_offset)
                continue

            canonical_symbol = f"{module}.{alias.name}" if module else alias.name
            local = alias.asname or alias.name
            self._name_aliases[local] = canonical_symbol
            # Also allow the local name to resolve as a module alias
            self._module_aliases[local] = canonical_symbol

            self._maybe_emit_import(canonical_symbol, local if alias.asname else None,
                                    node.lineno, node.col_offset)

        self.generic_visit(node)

    # ------------------------------------------------------------------ call visitor

    def visit_Call(self, node: ast.Call) -> None:
        qname = self._resolve_call(node)
        if qname:
            cap_def = CALL_SIGNALS.get(qname)
            # Also try the canonical module + function for aliased imports
            if cap_def is None:
                for suffix in self._suffix_lookups(qname):
                    cap_def = CALL_SIGNALS.get(suffix)
                    if cap_def:
                        qname = suffix
                        break

            if cap_def:
                alias = self._call_alias(node)
                self._report.uses.append(CapabilityUse(
                    cap_class=cap_def.cap_class,
                    severity=cap_def.severity,
                    kind="call",
                    symbol=qname,
                    alias=alias,
                    line=node.lineno,
                    col=node.col_offset,
                    reason=cap_def.reason,
                ))

        self.generic_visit(node)

    # ------------------------------------------------------------------ resolution

    def _resolve_call(self, node: ast.Call) -> str | None:
        """Return the best canonical dotted name for a Call node."""
        func = node.func

        if isinstance(func, ast.Name):
            name = func.id
            # Direct alias: from subprocess import Popen → Popen(...)
            if name in self._name_aliases:
                return self._name_aliases[name]
            # Built-in call like eval(...)
            return name

        if isinstance(func, ast.Attribute):
            obj = func.value
            attr = func.attr

            if isinstance(obj, ast.Name):
                obj_name = obj.id
                # Resolve through module alias: import os as o → o.system → os.system
                canonical_mod = self._module_aliases.get(obj_name, obj_name)
                return f"{canonical_mod}.{attr}"

            if isinstance(obj, ast.Attribute):
                # Three-level: e.g. urllib.request.urlopen
                if isinstance(obj.value, ast.Name):
                    top = obj.value.id
                    raw = f"{top}.{obj.attr}.{attr}"
                    # Prefer raw name (handles `import urllib.request` where
                    # module_aliases["urllib"] = "urllib.request" but the
                    # three-level call is already fully qualified)
                    if raw in CALL_SIGNALS:
                        return raw
                    canonical_top = self._module_aliases.get(top, top)
                    if canonical_top != top:
                        return f"{canonical_top}.{obj.attr}.{attr}"
                    return raw

        return None

    def _call_alias(self, node: ast.Call) -> str | None:
        """Return the local alias used at this call site, if any."""
        func = node.func
        if isinstance(func, ast.Name):
            if func.id in self._name_aliases:
                return func.id
            if func.id in self._module_aliases:
                return func.id
        if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
            local = func.value.id
            if local in self._module_aliases and self._module_aliases[local] != local:
                return f"{local}.{func.attr}"
        return None

    @staticmethod
    def _suffix_lookups(qname: str) -> list[str]:
        """
        Generate shorter canonical names for lookup when an alias added a prefix.
        e.g. "sp.run" → also try "subprocess.run" via module_aliases elsewhere.
        This handles deeply aliased cases that the main resolver already fixed;
        kept as fallback.
        """
        parts = qname.split(".")
        return [".".join(parts[i:]) for i in range(1, len(parts))]

    # ------------------------------------------------------------------ import emission

    def _maybe_emit_import(
        self,
        canonical: str,
        alias: str | None,
        line: int,
        col: int,
    ) -> None:
        key = (canonical, "import")
        if key in self._seen_imports:
            return

        # Check full name first, then progressively shorter prefixes
        cap_def = self._best_import_match(canonical)
        if cap_def is None:
            return

        self._seen_imports.add(key)
        self._report.uses.append(CapabilityUse(
            cap_class=cap_def.cap_class,
            severity=cap_def.severity,
            kind="import",
            symbol=canonical,
            alias=alias,
            line=line,
            col=col,
            reason=cap_def.reason,
        ))

    @staticmethod
    def _best_import_match(canonical: str) -> CapabilityDef | None:
        """
        Find the most-specific IMPORT_SIGNALS entry that matches *canonical*.
        e.g. "subprocess.Popen" → try "subprocess.Popen", then "subprocess".
        """
        parts = canonical.split(".")
        for length in range(len(parts), 0, -1):
            key = ".".join(parts[:length])
            if key in IMPORT_SIGNALS:
                return IMPORT_SIGNALS[key]
        return None


# ---------------------------------------------------------------------------
# Pass-1 import collector (pre-populates alias tables before main visit)
# ---------------------------------------------------------------------------

class _ImportCollector(ast.NodeVisitor):
    """Fills alias tables on the analyzer before the main walk."""

    def __init__(self, analyzer: CapabilityAnalyzer) -> None:
        self._a = analyzer

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            local = alias.asname or alias.name.split(".")[0]
            if alias.asname:
                self._a._module_aliases[alias.asname] = alias.name
            else:
                self._a._module_aliases[local] = alias.name
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        module = node.module or ""
        for alias in node.names:
            if alias.name == "*":
                continue
            local = alias.asname or alias.name
            canonical = f"{module}.{alias.name}" if module else alias.name
            self._a._name_aliases[local] = canonical
            self._a._module_aliases[local] = canonical
        self.generic_visit(node)
