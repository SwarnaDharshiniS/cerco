"""
Python AST → JSON serializer.

Walks the Python AST produced by the built-in `ast` module and converts it
into a plain-dict / JSON-serializable node tree that preserves:

  • node_type  – the AST class name (e.g. "Module", "FunctionDef", "For")
  • line / col  – source location where available
  • Function definitions  – name, args, decorators, return annotation, body
  • Loops                 – for / while / async-for, with target, iter, body
  • Imports               – import / from-import with module + aliases
  • Everything else       – recursively serialized child nodes / fields
"""

from __future__ import annotations

import ast
import json
from pathlib import Path
from typing import Any


# ---------------------------------------------------------------------------
# Public helpers
# ---------------------------------------------------------------------------

def parse_source(source: str, filename: str = "<string>") -> dict:
    """Parse Python *source* string and return a JSON-serialisable node tree."""
    tree = ast.parse(source, filename=filename, type_comments=False)
    return ASTParser(source=source).serialize(tree)


def parse_file(path: str | Path) -> dict:
    """Parse a Python file at *path* and return a JSON-serialisable node tree."""
    path = Path(path)
    source = path.read_text(encoding="utf-8")
    return parse_source(source, filename=str(path))


# ---------------------------------------------------------------------------
# Core serialiser
# ---------------------------------------------------------------------------

class ASTParser:
    """Converts a Python AST tree into a JSON-serialisable dictionary tree."""

    def __init__(self, source: str = "") -> None:
        self._source = source
        self._lines: list[str] = source.splitlines()

    # ------------------------------------------------------------------
    # Entry point
    # ------------------------------------------------------------------

    def serialize(self, node: ast.AST) -> dict:
        """Recursively serialise *node* into a plain dict."""
        return self._visit(node)

    def to_json(self, node: ast.AST, *, indent: int = 2) -> str:
        """Return a JSON string for *node*."""
        return json.dumps(self.serialize(node), indent=indent, ensure_ascii=False)

    # ------------------------------------------------------------------
    # Generic visitor dispatcher
    # ------------------------------------------------------------------

    def _visit(self, node: Any) -> Any:
        if isinstance(node, ast.AST):
            method = f"_visit_{type(node).__name__}"
            visitor = getattr(self, method, self._visit_generic)
            return visitor(node)
        if isinstance(node, list):
            return [self._visit(child) for child in node]
        # Primitives (int, str, float, bool, None) are already serialisable.
        return node

    # ------------------------------------------------------------------
    # Shared utility
    # ------------------------------------------------------------------

    def _base(self, node: ast.AST) -> dict:
        """Build the base dict with node_type and source location."""
        d: dict[str, Any] = {"node_type": type(node).__name__}
        if hasattr(node, "lineno"):
            d["line"] = node.lineno  # type: ignore[attr-defined]
            d["col"] = node.col_offset  # type: ignore[attr-defined]
        if hasattr(node, "end_lineno") and node.end_lineno is not None:
            d["end_line"] = node.end_lineno  # type: ignore[attr-defined]
            d["end_col"] = node.end_col_offset  # type: ignore[attr-defined]
        return d

    def _visit_generic(self, node: ast.AST) -> dict:
        """Fallback: serialise all AST fields generically."""
        d = self._base(node)
        for field, value in ast.iter_fields(node):
            serialised = self._visit(value)
            if serialised is not None and serialised != []:
                d[field] = serialised
        return d

    # ------------------------------------------------------------------
    # Module-level nodes
    # ------------------------------------------------------------------

    def _visit_Module(self, node: ast.Module) -> dict:
        d = self._base(node)
        d["body"] = [self._visit(stmt) for stmt in node.body]
        return d

    # ------------------------------------------------------------------
    # Imports
    # ------------------------------------------------------------------

    def _visit_Import(self, node: ast.Import) -> dict:
        d = self._base(node)
        d["names"] = [
            {"name": alias.name, "asname": alias.asname}
            for alias in node.names
        ]
        return d

    def _visit_ImportFrom(self, node: ast.ImportFrom) -> dict:
        d = self._base(node)
        d["module"] = node.module or ""
        d["level"] = node.level  # relative import dots
        d["names"] = [
            {"name": alias.name, "asname": alias.asname}
            for alias in node.names
        ]
        return d

    # ------------------------------------------------------------------
    # Function / class definitions
    # ------------------------------------------------------------------

    def _visit_FunctionDef(self, node: ast.FunctionDef) -> dict:
        return self._serialize_function(node, is_async=False)

    def _visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> dict:
        return self._serialize_function(node, is_async=True)

    def _serialize_function(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
        *,
        is_async: bool,
    ) -> dict:
        d = self._base(node)
        d["is_async"] = is_async
        d["name"] = node.name
        d["args"] = self._serialize_arguments(node.args)
        if node.returns is not None:
            d["returns"] = self._visit(node.returns)
        d["decorators"] = [self._visit(dec) for dec in node.decorator_list]
        d["body"] = [self._visit(stmt) for stmt in node.body]
        return d

    def _serialize_arguments(self, args: ast.arguments) -> dict:
        def _arg(a: ast.arg) -> dict:
            entry: dict[str, Any] = {"name": a.arg}
            if a.annotation is not None:
                entry["annotation"] = self._visit(a.annotation)
            return entry

        result: dict[str, Any] = {
            "args": [_arg(a) for a in args.args],
            "vararg": _arg(args.vararg) if args.vararg else None,
            "kwonlyargs": [_arg(a) for a in args.kwonlyargs],
            "kwarg": _arg(args.kwarg) if args.kwarg else None,
            "posonlyargs": [_arg(a) for a in args.posonlyargs],
            "defaults": [self._visit(d) for d in args.defaults],
            "kw_defaults": [self._visit(d) for d in args.kw_defaults if d is not None],
        }
        return result

    def _visit_ClassDef(self, node: ast.ClassDef) -> dict:
        d = self._base(node)
        d["name"] = node.name
        d["bases"] = [self._visit(b) for b in node.bases]
        d["decorators"] = [self._visit(dec) for dec in node.decorator_list]
        d["body"] = [self._visit(stmt) for stmt in node.body]
        return d

    # ------------------------------------------------------------------
    # Loops
    # ------------------------------------------------------------------

    def _visit_For(self, node: ast.For) -> dict:
        return self._serialize_for(node, is_async=False)

    def _visit_AsyncFor(self, node: ast.AsyncFor) -> dict:
        return self._serialize_for(node, is_async=True)

    def _serialize_for(
        self, node: ast.For | ast.AsyncFor, *, is_async: bool
    ) -> dict:
        d = self._base(node)
        d["is_async"] = is_async
        d["target"] = self._visit(node.target)
        d["iter"] = self._visit(node.iter)
        d["body"] = [self._visit(stmt) for stmt in node.body]
        if node.orelse:
            d["orelse"] = [self._visit(stmt) for stmt in node.orelse]
        return d

    def _visit_While(self, node: ast.While) -> dict:
        d = self._base(node)
        d["test"] = self._visit(node.test)
        d["body"] = [self._visit(stmt) for stmt in node.body]
        if node.orelse:
            d["orelse"] = [self._visit(stmt) for stmt in node.orelse]
        return d

    # ------------------------------------------------------------------
    # Conditionals
    # ------------------------------------------------------------------

    def _visit_If(self, node: ast.If) -> dict:
        d = self._base(node)
        d["test"] = self._visit(node.test)
        d["body"] = [self._visit(stmt) for stmt in node.body]
        if node.orelse:
            d["orelse"] = [self._visit(stmt) for stmt in node.orelse]
        return d

    # ------------------------------------------------------------------
    # Exception handling
    # ------------------------------------------------------------------

    def _visit_Try(self, node: ast.Try) -> dict:
        d = self._base(node)
        d["body"] = [self._visit(stmt) for stmt in node.body]
        d["handlers"] = [self._visit(h) for h in node.handlers]
        if node.orelse:
            d["orelse"] = [self._visit(stmt) for stmt in node.orelse]
        if node.finalbody:
            d["finalbody"] = [self._visit(stmt) for stmt in node.finalbody]
        return d

    def _visit_ExceptHandler(self, node: ast.ExceptHandler) -> dict:
        d = self._base(node)
        if node.type is not None:
            d["exc_type"] = self._visit(node.type)
        d["name"] = node.name
        d["body"] = [self._visit(stmt) for stmt in node.body]
        return d

    # ------------------------------------------------------------------
    # With statements
    # ------------------------------------------------------------------

    def _visit_With(self, node: ast.With) -> dict:
        return self._serialize_with(node, is_async=False)

    def _visit_AsyncWith(self, node: ast.AsyncWith) -> dict:
        return self._serialize_with(node, is_async=True)

    def _serialize_with(
        self, node: ast.With | ast.AsyncWith, *, is_async: bool
    ) -> dict:
        d = self._base(node)
        d["is_async"] = is_async
        d["items"] = [
            {
                "context_expr": self._visit(item.context_expr),
                "optional_vars": self._visit(item.optional_vars) if item.optional_vars else None,
            }
            for item in node.items
        ]
        d["body"] = [self._visit(stmt) for stmt in node.body]
        return d

    # ------------------------------------------------------------------
    # Assignments and expressions
    # ------------------------------------------------------------------

    def _visit_Assign(self, node: ast.Assign) -> dict:
        d = self._base(node)
        d["targets"] = [self._visit(t) for t in node.targets]
        d["value"] = self._visit(node.value)
        return d

    def _visit_AugAssign(self, node: ast.AugAssign) -> dict:
        d = self._base(node)
        d["target"] = self._visit(node.target)
        d["op"] = type(node.op).__name__
        d["value"] = self._visit(node.value)
        return d

    def _visit_AnnAssign(self, node: ast.AnnAssign) -> dict:
        d = self._base(node)
        d["target"] = self._visit(node.target)
        d["annotation"] = self._visit(node.annotation)
        if node.value is not None:
            d["value"] = self._visit(node.value)
        d["simple"] = bool(node.simple)
        return d

    def _visit_Return(self, node: ast.Return) -> dict:
        d = self._base(node)
        if node.value is not None:
            d["value"] = self._visit(node.value)
        return d

    def _visit_Yield(self, node: ast.Yield) -> dict:
        d = self._base(node)
        if node.value is not None:
            d["value"] = self._visit(node.value)
        return d

    def _visit_YieldFrom(self, node: ast.YieldFrom) -> dict:
        d = self._base(node)
        d["value"] = self._visit(node.value)
        return d

    def _visit_Expr(self, node: ast.Expr) -> dict:
        d = self._base(node)
        d["value"] = self._visit(node.value)
        return d

    # ------------------------------------------------------------------
    # Calls
    # ------------------------------------------------------------------

    def _visit_Call(self, node: ast.Call) -> dict:
        d = self._base(node)
        d["func"] = self._visit(node.func)
        d["args"] = [self._visit(a) for a in node.args]
        d["keywords"] = [
            {"arg": kw.arg, "value": self._visit(kw.value)}
            for kw in node.keywords
        ]
        return d

    # ------------------------------------------------------------------
    # Names, attributes, subscripts
    # ------------------------------------------------------------------

    def _visit_Name(self, node: ast.Name) -> dict:
        d = self._base(node)
        d["id"] = node.id
        d["ctx"] = type(node.ctx).__name__
        return d

    def _visit_Attribute(self, node: ast.Attribute) -> dict:
        d = self._base(node)
        d["value"] = self._visit(node.value)
        d["attr"] = node.attr
        d["ctx"] = type(node.ctx).__name__
        return d

    def _visit_Subscript(self, node: ast.Subscript) -> dict:
        d = self._base(node)
        d["value"] = self._visit(node.value)
        d["slice"] = self._visit(node.slice)
        d["ctx"] = type(node.ctx).__name__
        return d

    # ------------------------------------------------------------------
    # Literals
    # ------------------------------------------------------------------

    def _visit_Constant(self, node: ast.Constant) -> dict:
        d = self._base(node)
        d["value"] = node.value
        d["kind"] = type(node.value).__name__
        return d

    def _visit_JoinedStr(self, node: ast.JoinedStr) -> dict:
        """f-string"""
        d = self._base(node)
        d["values"] = [self._visit(v) for v in node.values]
        return d

    def _visit_List(self, node: ast.List) -> dict:
        d = self._base(node)
        d["elts"] = [self._visit(e) for e in node.elts]
        d["ctx"] = type(node.ctx).__name__
        return d

    def _visit_Tuple(self, node: ast.Tuple) -> dict:
        d = self._base(node)
        d["elts"] = [self._visit(e) for e in node.elts]
        d["ctx"] = type(node.ctx).__name__
        return d

    def _visit_Dict(self, node: ast.Dict) -> dict:
        d = self._base(node)
        d["keys"] = [self._visit(k) if k is not None else None for k in node.keys]
        d["values"] = [self._visit(v) for v in node.values]
        return d

    def _visit_Set(self, node: ast.Set) -> dict:
        d = self._base(node)
        d["elts"] = [self._visit(e) for e in node.elts]
        return d

    # ------------------------------------------------------------------
    # Comprehensions
    # ------------------------------------------------------------------

    def _visit_ListComp(self, node: ast.ListComp) -> dict:
        d = self._base(node)
        d["elt"] = self._visit(node.elt)
        d["generators"] = [self._visit(g) for g in node.generators]
        return d

    def _visit_SetComp(self, node: ast.SetComp) -> dict:
        d = self._base(node)
        d["elt"] = self._visit(node.elt)
        d["generators"] = [self._visit(g) for g in node.generators]
        return d

    def _visit_DictComp(self, node: ast.DictComp) -> dict:
        d = self._base(node)
        d["key"] = self._visit(node.key)
        d["value"] = self._visit(node.value)
        d["generators"] = [self._visit(g) for g in node.generators]
        return d

    def _visit_GeneratorExp(self, node: ast.GeneratorExp) -> dict:
        d = self._base(node)
        d["elt"] = self._visit(node.elt)
        d["generators"] = [self._visit(g) for g in node.generators]
        return d

    def _visit_comprehension(self, node: ast.comprehension) -> dict:
        d = {"node_type": "comprehension"}
        d["target"] = self._visit(node.target)
        d["iter"] = self._visit(node.iter)
        d["ifs"] = [self._visit(i) for i in node.ifs]
        d["is_async"] = bool(node.is_async)
        return d

    # ------------------------------------------------------------------
    # Operators / boolean ops / comparisons
    # ------------------------------------------------------------------

    def _visit_BinOp(self, node: ast.BinOp) -> dict:
        d = self._base(node)
        d["left"] = self._visit(node.left)
        d["op"] = type(node.op).__name__
        d["right"] = self._visit(node.right)
        return d

    def _visit_UnaryOp(self, node: ast.UnaryOp) -> dict:
        d = self._base(node)
        d["op"] = type(node.op).__name__
        d["operand"] = self._visit(node.operand)
        return d

    def _visit_BoolOp(self, node: ast.BoolOp) -> dict:
        d = self._base(node)
        d["op"] = type(node.op).__name__
        d["values"] = [self._visit(v) for v in node.values]
        return d

    def _visit_Compare(self, node: ast.Compare) -> dict:
        d = self._base(node)
        d["left"] = self._visit(node.left)
        d["ops"] = [type(op).__name__ for op in node.ops]
        d["comparators"] = [self._visit(c) for c in node.comparators]
        return d

    def _visit_IfExp(self, node: ast.IfExp) -> dict:
        d = self._base(node)
        d["test"] = self._visit(node.test)
        d["body"] = self._visit(node.body)
        d["orelse"] = self._visit(node.orelse)
        return d

    # ------------------------------------------------------------------
    # Lambda
    # ------------------------------------------------------------------

    def _visit_Lambda(self, node: ast.Lambda) -> dict:
        d = self._base(node)
        d["args"] = self._serialize_arguments(node.args)
        d["body"] = self._visit(node.body)
        return d

    # ------------------------------------------------------------------
    # Control flow
    # ------------------------------------------------------------------

    def _visit_Break(self, node: ast.Break) -> dict:
        return self._base(node)

    def _visit_Continue(self, node: ast.Continue) -> dict:
        return self._base(node)

    def _visit_Pass(self, node: ast.Pass) -> dict:
        return self._base(node)

    def _visit_Raise(self, node: ast.Raise) -> dict:
        d = self._base(node)
        if node.exc is not None:
            d["exc"] = self._visit(node.exc)
        if node.cause is not None:
            d["cause"] = self._visit(node.cause)
        return d

    def _visit_Assert(self, node: ast.Assert) -> dict:
        d = self._base(node)
        d["test"] = self._visit(node.test)
        if node.msg is not None:
            d["msg"] = self._visit(node.msg)
        return d

    def _visit_Delete(self, node: ast.Delete) -> dict:
        d = self._base(node)
        d["targets"] = [self._visit(t) for t in node.targets]
        return d

    def _visit_Global(self, node: ast.Global) -> dict:
        d = self._base(node)
        d["names"] = list(node.names)
        return d

    def _visit_Nonlocal(self, node: ast.Nonlocal) -> dict:
        d = self._base(node)
        d["names"] = list(node.names)
        return d

    # ------------------------------------------------------------------
    # Await / starred
    # ------------------------------------------------------------------

    def _visit_Await(self, node: ast.Await) -> dict:
        d = self._base(node)
        d["value"] = self._visit(node.value)
        return d

    def _visit_Starred(self, node: ast.Starred) -> dict:
        d = self._base(node)
        d["value"] = self._visit(node.value)
        d["ctx"] = type(node.ctx).__name__
        return d
