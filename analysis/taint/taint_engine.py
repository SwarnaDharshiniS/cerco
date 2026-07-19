"""
Taint Analysis Engine — core analyzer.

Algorithm
---------
The analyzer performs a flow-sensitive, intra-procedural taint analysis with
one level of inter-procedural expansion (user-defined functions called with
tainted arguments are analysed inline up to a configurable call depth).

Key concepts
~~~~~~~~~~~~
TaintEnv   : dict[str, frozenset[TaintTag]]
             Maps variable names (and pseudo-names like "sys.argv",
             "__return__") to the set of taint tags that may flow into them.

Expression evaluation  (_eval_expr)
    Returns the frozenset[TaintTag] that may flow out of an expression.
    Pure constants → empty set.  Sources → singleton tag.
    Compound expressions → union of child taints.
    Sanitizer calls → empty set (taint is removed).

Statement execution (_exec_stmt / _exec_stmts)
    Mutates the TaintEnv in place.  Branch points (if/try/with) fork the
    env, process each branch, and merge the results.  Loops iterate the
    body to a fixed point (at most MAX_LOOP_ITERS passes).

Sink checking (_check_call)
    When a Call node is visited during expression evaluation the dotted
    qualified name is looked up in the SINKS registry.  If a tainted
    argument reaches a sink a TaintFinding is emitted.

Import tracking
    `from sys import argv` → registers "argv" as an alias for sys.argv.
    `import sys as s`      → registers "s.argv" as an alias.
    `from os import environ` → registers "environ" as env_var source.
"""

from __future__ import annotations

import ast
import json
from copy import deepcopy
from pathlib import Path
from typing import Any

from ._model import (
    ChainStep,
    TaintTag,
    TaintFinding,
    SOURCES,
    SOURCE_ATTRS,
    SINKS,
    SANITIZERS,
    TAINT_PASSING_STR_METHODS,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

MAX_LOOP_ITERS = 3   # fixed-point iterations for loops
MAX_CALL_DEPTH = 2   # max inline expansion of user-defined functions

TaintEnv = dict[str, frozenset[TaintTag]]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _call_qname(node: ast.Call) -> str | None:
    """Return the dotted qualified name of a call, e.g. 'os.system'."""
    func = node.func
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        val = func.value
        if isinstance(val, ast.Name):
            return f"{val.id}.{func.attr}"
        if isinstance(val, ast.Attribute) and isinstance(val.value, ast.Name):
            return f"{val.value.id}.{val.attr}.{func.attr}"
    return None


def _attr_qname(node: ast.Attribute) -> str | None:
    """Return 'obj.attr' for a two-level attribute access."""
    if isinstance(node.value, ast.Name):
        return f"{node.value.id}.{node.attr}"
    return None


def _merge_envs(*envs: TaintEnv) -> TaintEnv:
    """Join multiple environments at a control-flow merge point."""
    merged: TaintEnv = {}
    for env in envs:
        for name, tags in env.items():
            merged[name] = merged.get(name, frozenset()) | tags
    return merged


def _env_eq(a: TaintEnv, b: TaintEnv) -> bool:
    return a.keys() == b.keys() and all(a[k] == b[k] for k in a)


def _unparse(node: ast.AST) -> str:
    try:
        return ast.unparse(node)
    except Exception:
        return type(node).__name__


# ---------------------------------------------------------------------------
# Core analyzer
# ---------------------------------------------------------------------------

class TaintAnalyzer:
    """
    Analyses Python source for taint flows from sources to sinks.

    Usage::

        analyzer = TaintAnalyzer()
        findings = analyzer.analyze_source(source_code)
        for f in findings:
            print(f)
    """

    def __init__(self, call_depth: int = 0) -> None:
        self._call_depth = call_depth
        self._findings: list[TaintFinding] = []
        # name → FunctionDef/AsyncFunctionDef collected during analysis
        self._functions: dict[str, ast.FunctionDef | ast.AsyncFunctionDef] = {}
        # import aliases: local_name → (source_kind, source_expr)
        self._source_aliases: dict[str, tuple[str, str]] = {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def analyze_source(self, source: str) -> list[TaintFinding]:
        """Parse *source* and return all taint findings."""
        tree = ast.parse(source)
        self._findings = []
        self._functions = {}
        self._source_aliases = {}
        env: TaintEnv = {}
        self._collect_functions(tree.body)
        self._exec_stmts(tree.body, env)
        return list(self._findings)

    def analyze_file(self, path: str | Path) -> list[TaintFinding]:
        source = Path(path).read_text(encoding="utf-8")
        return self.analyze_source(source)

    # ------------------------------------------------------------------
    # Function collection (first pass)
    # ------------------------------------------------------------------

    def _collect_functions(
        self, stmts: list[ast.stmt]
    ) -> None:
        for stmt in stmts:
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self._functions[stmt.name] = stmt
            elif isinstance(stmt, ast.ClassDef):
                self._collect_functions(stmt.body)

    # ------------------------------------------------------------------
    # Statement execution
    # ------------------------------------------------------------------

    def _exec_stmts(self, stmts: list[ast.stmt], env: TaintEnv) -> None:
        for stmt in stmts:
            self._exec_stmt(stmt, env)

    def _exec_stmt(self, stmt: ast.stmt, env: TaintEnv) -> None:  # noqa: C901
        # ---- imports --------------------------------------------------
        if isinstance(stmt, ast.Import):
            self._handle_import(stmt, env)

        elif isinstance(stmt, ast.ImportFrom):
            self._handle_import_from(stmt, env)

        # ---- assignments ----------------------------------------------
        elif isinstance(stmt, ast.Assign):
            tags = self._eval_expr(stmt.value, env)
            for target in stmt.targets:
                self._assign(target, tags, env,
                             stmt.lineno, stmt.col_offset, "assign")

        elif isinstance(stmt, ast.AugAssign):
            rhs = self._eval_expr(stmt.value, env)
            lhs = self._eval_expr(stmt.target, env)
            tags = lhs | rhs
            self._assign(stmt.target, tags, env,
                         stmt.lineno, stmt.col_offset, "aug_assign")

        elif isinstance(stmt, ast.AnnAssign):
            if stmt.value is not None:
                tags = self._eval_expr(stmt.value, env)
                self._assign(stmt.target, tags, env,
                             stmt.lineno, stmt.col_offset, "assign")

        # ---- expression statement (bare call etc.) -------------------
        elif isinstance(stmt, ast.Expr):
            self._eval_expr(stmt.value, env)

        # ---- control flow: if ----------------------------------------
        elif isinstance(stmt, ast.If):
            self._eval_expr(stmt.test, env)   # may contain source/sink calls
            env_true = dict(env)
            env_false = dict(env)
            self._exec_stmts(stmt.body, env_true)
            if stmt.orelse:
                self._exec_stmts(stmt.orelse, env_false)
            merged = _merge_envs(env_true, env_false)
            env.clear()
            env.update(merged)

        # ---- control flow: for ---------------------------------------
        elif isinstance(stmt, (ast.For, ast.AsyncFor)):
            iter_tags = self._eval_expr(stmt.iter, env)
            # target gets taint from iterable
            self._assign(stmt.target, iter_tags, env,
                         stmt.lineno, stmt.col_offset, "loop_target")
            self._loop_fixed_point(stmt.body, env)
            if stmt.orelse:
                self._exec_stmts(stmt.orelse, env)

        # ---- control flow: while ------------------------------------
        elif isinstance(stmt, ast.While):
            self._eval_expr(stmt.test, env)
            self._loop_fixed_point(stmt.body, env)
            if stmt.orelse:
                self._exec_stmts(stmt.orelse, env)

        # ---- try / except -------------------------------------------
        elif isinstance(stmt, ast.Try):
            env_try = dict(env)
            self._exec_stmts(stmt.body, env_try)
            branch_envs = [env_try]
            for handler in stmt.handlers:
                env_h = dict(env)
                if handler.name:
                    # exception variable: mark as potentially tainted if
                    # the exception was caused by tainted input
                    env_h[handler.name] = frozenset()
                self._exec_stmts(handler.body, env_h)
                branch_envs.append(env_h)
            merged = _merge_envs(*branch_envs)
            if stmt.orelse:
                self._exec_stmts(stmt.orelse, merged)
            if stmt.finalbody:
                self._exec_stmts(stmt.finalbody, merged)
            env.clear()
            env.update(merged)

        # ---- with ----------------------------------------------------
        elif isinstance(stmt, (ast.With, ast.AsyncWith)):
            for item in stmt.items:
                ctx_tags = self._eval_expr(item.context_expr, env)
                if item.optional_vars is not None:
                    self._assign(item.optional_vars, ctx_tags, env,
                                 stmt.lineno, stmt.col_offset, "assign")
            self._exec_stmts(stmt.body, env)

        # ---- function / class defs -----------------------------------
        elif isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
            # Analyse the function body treating all parameters as CLEAN
            # (they become tainted only when called with tainted args).
            # A separate analysis with tainted params is triggered at call sites.
            pass  # collected in _collect_functions; expanded at call sites

        elif isinstance(stmt, ast.ClassDef):
            self._collect_functions(stmt.body)
            inner_env: TaintEnv = {}
            self._exec_stmts(stmt.body, inner_env)

        # ---- return / raise ------------------------------------------
        elif isinstance(stmt, ast.Return):
            if stmt.value is not None:
                ret_tags = self._eval_expr(stmt.value, env)
                env["__return__"] = (
                    env.get("__return__", frozenset()) | ret_tags
                )

        elif isinstance(stmt, ast.Raise):
            if stmt.exc is not None:
                self._eval_expr(stmt.exc, env)

        elif isinstance(stmt, ast.Assert):
            self._eval_expr(stmt.test, env)

        elif isinstance(stmt, ast.Delete):
            for t in stmt.targets:
                if isinstance(t, ast.Name):
                    env.pop(t.id, None)

        elif isinstance(stmt, ast.Global):
            pass  # conservative: ignore global declarations

        elif isinstance(stmt, ast.Nonlocal):
            pass

    def _loop_fixed_point(self, body: list[ast.stmt], env: TaintEnv) -> None:
        for _ in range(MAX_LOOP_ITERS):
            snapshot = {k: v for k, v in env.items()}
            self._exec_stmts(body, env)
            if _env_eq(snapshot, env):
                break

    # ------------------------------------------------------------------
    # Import alias tracking
    # ------------------------------------------------------------------

    def _handle_import(self, stmt: ast.Import, env: TaintEnv) -> None:
        for alias in stmt.names:
            local = alias.asname or alias.name
            # e.g. import sys as s  → s.argv is a source
            if alias.name == "sys":
                self._source_aliases[f"{local}.argv"] = ("sys_argv", f"{local}.argv")
                self._source_aliases[f"{local}.stdin"] = ("stdin", f"{local}.stdin")
            elif alias.name == "os":
                self._source_aliases[f"{local}.environ"] = ("env_var", f"{local}.environ")

    def _handle_import_from(self, stmt: ast.ImportFrom, env: TaintEnv) -> None:
        module = stmt.module or ""
        for alias in stmt.names:
            local = alias.asname or alias.name
            # from sys import argv  → argv is tainted list
            if module == "sys" and alias.name == "argv":
                tag = TaintTag(
                    source_kind="sys_argv",
                    source_line=stmt.lineno,
                    source_col=stmt.col_offset,
                    source_expr="sys.argv",
                )
                env[local] = frozenset({tag})
            elif module == "sys" and alias.name == "stdin":
                self._source_aliases[local] = ("stdin", "sys.stdin")
            elif module == "os" and alias.name == "environ":
                self._source_aliases[local] = ("env_var", "os.environ")
                # Seed env so `environ['KEY']` (Name subscript) is tainted too
                env[local] = frozenset({TaintTag(
                    source_kind="env_var",
                    source_line=stmt.lineno,
                    source_col=stmt.col_offset,
                    source_expr="os.environ",
                )})
            elif module in {"os", "os.path"} and alias.name == "getenv":
                self._source_aliases[f"{local}()"] = ("env_var", "os.getenv()")

    # ------------------------------------------------------------------
    # Expression evaluation → frozenset[TaintTag]
    # ------------------------------------------------------------------

    def _eval_expr(self, node: ast.expr, env: TaintEnv) -> frozenset[TaintTag]:  # noqa: C901
        if node is None:
            return frozenset()

        # ---- constants ------------------------------------------------
        if isinstance(node, ast.Constant):
            return frozenset()

        # ---- names ----------------------------------------------------
        if isinstance(node, ast.Name):
            return env.get(node.id, frozenset())

        # ---- attribute access ----------------------------------------
        if isinstance(node, ast.Attribute):
            qname = _attr_qname(node)
            # sys.argv, os.environ, etc.
            if qname in SOURCE_ATTRS:
                kind, expr = SOURCE_ATTRS[qname]
                return frozenset({TaintTag(
                    source_kind=kind,
                    source_line=node.lineno,
                    source_col=node.col_offset,
                    source_expr=expr,
                )})
            if qname in self._source_aliases:
                kind, expr = self._source_aliases[qname]
                return frozenset({TaintTag(
                    source_kind=kind,
                    source_line=node.lineno,
                    source_col=node.col_offset,
                    source_expr=expr,
                )})
            # taint from the object propagates through attribute access
            obj_tags = self._eval_expr(node.value, env)
            if obj_tags and node.attr not in {"__class__", "__dict__"}:
                return obj_tags
            return frozenset()

        # ---- subscript -----------------------------------------------
        if isinstance(node, ast.Subscript):
            container = self._eval_expr(node.value, env)
            # sys.argv[n] is already covered by the attribute case above
            # but the container taint flows to the element
            return container

        # ---- calls ---------------------------------------------------
        if isinstance(node, ast.Call):
            return self._eval_call(node, env)

        # ---- binary operations ---------------------------------------
        if isinstance(node, ast.BinOp):
            return self._eval_expr(node.left, env) | self._eval_expr(node.right, env)

        # ---- unary operations ----------------------------------------
        if isinstance(node, ast.UnaryOp):
            return self._eval_expr(node.operand, env)

        # ---- boolean operations --------------------------------------
        if isinstance(node, ast.BoolOp):
            result: frozenset[TaintTag] = frozenset()
            for val in node.values:
                result = result | self._eval_expr(val, env)
            return result

        # ---- comparisons (produce bool, not injectable) --------------
        if isinstance(node, ast.Compare):
            # still evaluate sub-expressions to catch sink calls within them
            self._eval_expr(node.left, env)
            for c in node.comparators:
                self._eval_expr(c, env)
            return frozenset()

        # ---- ternary -------------------------------------------------
        if isinstance(node, ast.IfExp):
            self._eval_expr(node.test, env)
            return (
                self._eval_expr(node.body, env) |
                self._eval_expr(node.orelse, env)
            )

        # ---- f-strings -----------------------------------------------
        if isinstance(node, ast.JoinedStr):
            result = frozenset()
            for part in node.values:
                if isinstance(part, ast.FormattedValue):
                    result = result | self._eval_expr(part.value, env)
            return result

        # ---- containers: list / tuple / set --------------------------
        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            result = frozenset()
            for elt in node.elts:
                result = result | self._eval_expr(elt, env)
            return result

        # ---- dict ----------------------------------------------------
        if isinstance(node, ast.Dict):
            result = frozenset()
            for k, v in zip(node.keys, node.values):
                if k is not None:
                    result = result | self._eval_expr(k, env)
                result = result | self._eval_expr(v, env)
            return result

        # ---- starred -------------------------------------------------
        if isinstance(node, ast.Starred):
            return self._eval_expr(node.value, env)

        # ---- comprehensions ------------------------------------------
        if isinstance(node, (ast.ListComp, ast.SetComp, ast.GeneratorExp)):
            comp_env = dict(env)
            for gen in node.generators:
                iter_t = self._eval_expr(gen.iter, comp_env)
                self._assign(gen.target, iter_t, comp_env,
                             None, None, "loop_target")
            return self._eval_expr(node.elt, comp_env)

        if isinstance(node, ast.DictComp):
            comp_env = dict(env)
            for gen in node.generators:
                iter_t = self._eval_expr(gen.iter, comp_env)
                self._assign(gen.target, iter_t, comp_env,
                             None, None, "loop_target")
            return (
                self._eval_expr(node.key, comp_env) |
                self._eval_expr(node.value, comp_env)
            )

        # ---- lambda --------------------------------------------------
        if isinstance(node, ast.Lambda):
            return frozenset()

        # ---- await ---------------------------------------------------
        if isinstance(node, ast.Await):
            return self._eval_expr(node.value, env)

        # ---- yield ---------------------------------------------------
        if isinstance(node, (ast.Yield, ast.YieldFrom)):
            if isinstance(node, ast.Yield) and node.value:
                return self._eval_expr(node.value, env)
            if isinstance(node, ast.YieldFrom):
                return self._eval_expr(node.value, env)
            return frozenset()

        return frozenset()

    # ------------------------------------------------------------------
    # Call evaluation
    # ------------------------------------------------------------------

    def _eval_call(self, node: ast.Call, env: TaintEnv) -> frozenset[TaintTag]:
        qname = _call_qname(node)

        # ---- sanitizers: return clean --------------------------------
        if qname in SANITIZERS:
            # still evaluate args (they might contain other sink calls)
            for arg in node.args:
                self._eval_expr(arg, env)
            return frozenset()

        # ---- sources: return a fresh taint tag -----------------------
        if qname in SOURCES:
            kind, expr = SOURCES[qname]
            return frozenset({TaintTag(
                source_kind=kind,
                source_line=node.lineno,
                source_col=node.col_offset,
                source_expr=expr,
            )})

        # ---- taint-passing string methods (e.g. x.strip()) ----------
        if (
            isinstance(node.func, ast.Attribute)
            and node.func.attr in TAINT_PASSING_STR_METHODS
        ):
            obj_tags = self._eval_expr(node.func.value, env)
            arg_tags: frozenset[TaintTag] = frozenset()
            for arg in node.args:
                arg_tags = arg_tags | self._eval_expr(arg, env)
            # "join" passes taint from its iterable argument
            if node.func.attr == "join" and node.args:
                return obj_tags | arg_tags
            return obj_tags | arg_tags

        # ---- collect taint from all arguments first ------------------
        all_arg_tags: frozenset[TaintTag] = frozenset()
        for arg in node.args:
            all_arg_tags = all_arg_tags | self._eval_expr(arg, env)
        for kw in node.keywords:
            all_arg_tags = all_arg_tags | self._eval_expr(kw.value, env)

        # ---- sinks: report findings ----------------------------------
        if qname in SINKS:
            self._check_sink(node, qname, all_arg_tags)

        # ---- user-defined function calls with tainted args -----------
        if qname and qname in self._functions and self._call_depth < MAX_CALL_DEPTH:
            ret_tags = self._expand_user_call(
                self._functions[qname], node, all_arg_tags, env
            )
            return ret_tags

        # Conservative: taint from args propagates to return value
        return all_arg_tags

    def _expand_user_call(
        self,
        func: ast.FunctionDef | ast.AsyncFunctionDef,
        call: ast.Call,
        arg_tags: frozenset[TaintTag],
        caller_env: TaintEnv,
    ) -> frozenset[TaintTag]:
        """Inline-analyse a user function with the given argument taint."""
        callee_env: TaintEnv = {}

        # Map positional args to parameters
        params = [a.arg for a in func.args.args]
        for i, actual_arg in enumerate(call.args):
            if i < len(params):
                actual_tags = self._eval_expr(actual_arg, caller_env)
                if actual_tags:
                    callee_env[params[i]] = actual_tags

        # Map keyword args to parameters
        for kw in call.keywords:
            if kw.arg and kw.arg in params:
                kw_tags = self._eval_expr(kw.value, caller_env)
                if kw_tags:
                    callee_env[kw.arg] = kw_tags

        # Run the callee analysis at incremented depth
        sub = TaintAnalyzer(call_depth=self._call_depth + 1)
        sub._functions = self._functions
        sub._source_aliases = self._source_aliases
        sub._exec_stmts(func.body, callee_env)
        self._findings.extend(sub._findings)

        return callee_env.get("__return__", frozenset())

    # ------------------------------------------------------------------
    # Sink checking
    # ------------------------------------------------------------------

    def _check_sink(
        self,
        node: ast.Call,
        qname: str,
        tainted_args: frozenset[TaintTag],
    ) -> None:
        if not tainted_args:
            return
        sink_kind, severity, sink_label = SINKS[qname]
        # Propagate chain: add one last step "→ sink argument"
        propagated = frozenset(
            t.extend(
                variable=f"<arg of {sink_label}>",
                line=node.lineno,
                col=node.col_offset,
                how="call_arg",
            )
            for t in tainted_args
        )
        finding = TaintFinding(
            sink_name=sink_label,
            sink_kind=sink_kind,
            sink_line=node.lineno,
            sink_col=node.col_offset,
            severity=severity,
            tags=list(propagated),
        )
        self._findings.append(finding)

    # ------------------------------------------------------------------
    # Assignment helper
    # ------------------------------------------------------------------

    def _assign(
        self,
        target: ast.expr,
        tags: frozenset[TaintTag],
        env: TaintEnv,
        line: int | None,
        col: int | None,
        how: str,
    ) -> None:
        if isinstance(target, ast.Name):
            if tags:
                propagated = frozenset(
                    t.extend(target.id, line, col, how) for t in tags
                )
                env[target.id] = propagated
            else:
                env.pop(target.id, None)

        elif isinstance(target, (ast.Tuple, ast.List)):
            # Unpacking: each element gets all the taint conservatively
            for elt in target.elts:
                self._assign(elt, tags, env, line, col, "unpack")

        elif isinstance(target, ast.Starred):
            self._assign(target.value, tags, env, line, col, how)

        elif isinstance(target, ast.Subscript):
            # d[key] = val → d becomes tainted if val is tainted
            if isinstance(target.value, ast.Name) and tags:
                existing = env.get(target.value.id, frozenset())
                propagated = frozenset(
                    t.extend(target.value.id, line, col, "subscript_assign")
                    for t in tags
                )
                env[target.value.id] = existing | propagated

        elif isinstance(target, ast.Attribute):
            # obj.attr = val → track as "obj.attr"
            key = _attr_qname(target)
            if key and tags:
                propagated = frozenset(
                    t.extend(key, line, col, "attr_assign") for t in tags
                )
                env[key] = propagated


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def analyze_source(source: str) -> list[TaintFinding]:
    """Analyse a Python source string and return taint findings."""
    return TaintAnalyzer().analyze_source(source)


def analyze_file(path: str | Path) -> list[TaintFinding]:
    """Analyse a Python source file and return taint findings."""
    return TaintAnalyzer().analyze_file(path)


def analyze_to_dict(source: str) -> dict[str, Any]:
    """Analyse *source* and return a JSON-serialisable report dict."""
    findings = analyze_source(source)
    return {
        "total": len(findings),
        "critical": sum(1 for f in findings if f.severity == "CRITICAL"),
        "high":     sum(1 for f in findings if f.severity == "HIGH"),
        "medium":   sum(1 for f in findings if f.severity == "MEDIUM"),
        "findings": [f.to_dict() for f in findings],
    }
