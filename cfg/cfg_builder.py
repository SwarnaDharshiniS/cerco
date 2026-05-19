"""
Control Flow Graph (CFG) generator for Python source code.

Architecture
------------
1. `BasicBlock`   – a maximal straight-line sequence of statements with a
                    single entry and single exit.  Carries metadata about
                    whether it is a loop header, branch condition, or
                    plain sequence block.

2. `CFGBuilder`   – walks a Python function (or module) body and emits a
                    `networkx.DiGraph` whose nodes are `BasicBlock` ids and
                    whose edges carry a `label` ("true"/"false"/"loop-back"/
                    "unconditional"/"fallthrough").

3. `CFG`          – thin wrapper around the DiGraph that exposes helpers:
                    `loops()`, `branches()`, `basic_blocks()`, and
                    serialisation to JSON-compatible dicts.

Supported constructs
--------------------
  • Sequences of statements → merged into basic blocks
  • if / elif / else        → branch node + true/false edges
  • for / while             → loop-header block, back-edge, break exits
  • try / except / finally  → handler edges
  • function / class defs   → treated as opaque statements (nested CFGs
                              can be built by calling `build_cfg` on them)
  • return / raise / break /
    continue                → terminate the current block
"""

from __future__ import annotations

import ast
import itertools
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator

import networkx as nx


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

_id_counter = itertools.count(1)


def _new_id() -> int:
    return next(_id_counter)


@dataclass
class BasicBlock:
    """A maximal straight-line sequence of AST statements."""

    id: int = field(default_factory=_new_id)
    stmts: list[ast.stmt] = field(default_factory=list)
    # Semantic tags
    kind: str = "sequence"       # "sequence" | "branch" | "loop_header" | "loop_exit" | "entry" | "exit"
    label: str = ""              # human-readable (e.g. function name, loop target)

    # ------------------------------------------------------------------ repr
    def summary(self) -> str:
        parts = [f"[BB{self.id}:{self.kind}]"]
        if self.label:
            parts.append(self.label)
        for stmt in self.stmts:
            parts.append(_stmt_summary(stmt))
        return "\n".join(parts)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "kind": self.kind,
            "label": self.label,
            "stmts": [_stmt_summary(s) for s in self.stmts],
            "lines": _stmt_lines(self.stmts),
        }


def _stmt_summary(stmt: ast.stmt) -> str:
    try:
        return ast.unparse(stmt)
    except Exception:
        return type(stmt).__name__


def _stmt_lines(stmts: list[ast.stmt]) -> dict[str, int | None]:
    if not stmts:
        return {"start": None, "end": None}
    return {
        "start": getattr(stmts[0], "lineno", None),
        "end": getattr(stmts[-1], "end_lineno", None),
    }


# ---------------------------------------------------------------------------
# CFG wrapper
# ---------------------------------------------------------------------------

class CFG:
    """
    A control-flow graph for a Python function or module body.

    Attributes
    ----------
    graph   : networkx.DiGraph  (node = block id, edge attr = {"label": str})
    blocks  : dict[int, BasicBlock]
    name    : str  (function name or "<module>")
    """

    def __init__(self, graph: nx.DiGraph, blocks: dict[int, BasicBlock], name: str = "<module>") -> None:
        self.graph = graph
        self.blocks = blocks
        self.name = name

    # ------------------------------------------------------------------ queries

    def basic_blocks(self) -> list[BasicBlock]:
        """All basic blocks in topological order (as far as cycles allow)."""
        try:
            order = list(nx.topological_sort(self.graph))
        except nx.NetworkXUnfeasible:
            order = list(self.graph.nodes)
        return [self.blocks[n] for n in order if n in self.blocks]

    def branches(self) -> list[BasicBlock]:
        """Blocks that represent conditional branch points (if/elif)."""
        return [b for b in self.blocks.values() if b.kind == "branch"]

    def loops(self) -> list[BasicBlock]:
        """Blocks that are loop headers (for/while)."""
        return [b for b in self.blocks.values() if b.kind == "loop_header"]

    def loop_back_edges(self) -> list[tuple[int, int]]:
        """Edges that form back-edges (loop-back label)."""
        return [
            (u, v)
            for u, v, data in self.graph.edges(data=True)
            if data.get("label") == "loop-back"
        ]

    def entry_block(self) -> BasicBlock | None:
        for b in self.blocks.values():
            if b.kind == "entry":
                return b
        return None

    def exit_block(self) -> BasicBlock | None:
        for b in self.blocks.values():
            if b.kind == "exit":
                return b
        return None

    # ------------------------------------------------------------------ serialisation

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "blocks": [b.to_dict() for b in self.basic_blocks()],
            "edges": [
                {"from": u, "to": v, "label": data.get("label", "")}
                for u, v, data in self.graph.edges(data=True)
            ],
            "summary": {
                "total_blocks": len(self.blocks),
                "total_edges": self.graph.number_of_edges(),
                "branches": len(self.branches()),
                "loops": len(self.loops()),
                "loop_back_edges": len(self.loop_back_edges()),
            },
        }

    def to_json(self, *, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)

    def __repr__(self) -> str:
        return (
            f"<CFG '{self.name}' "
            f"blocks={len(self.blocks)} "
            f"edges={self.graph.number_of_edges()} "
            f"loops={len(self.loops())} "
            f"branches={len(self.branches())}>"
        )


# ---------------------------------------------------------------------------
# Builder
# ---------------------------------------------------------------------------

class CFGBuilder:
    """
    Builds a CFG from a list of AST statements (a function body or module body).

    Usage::

        builder = CFGBuilder()
        cfg = builder.build(func_node, name="my_func")
        # or for a whole module:
        cfg = builder.build_module(module_node)
    """

    def build(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
        name: str | None = None,
    ) -> CFG:
        func_name = name or getattr(node, "name", "<anonymous>")
        graph, blocks = self._build_body(node.body, func_name)
        return CFG(graph, blocks, name=func_name)

    def build_module(self, node: ast.Module, name: str = "<module>") -> CFG:
        graph, blocks = self._build_body(node.body, name)
        return CFG(graph, blocks, name=name)

    def build_source(self, source: str, name: str = "<module>") -> CFG:
        tree = ast.parse(source)
        return self.build_module(tree, name=name)

    def build_file(self, path: str | Path) -> CFG:
        path = Path(path)
        source = path.read_text(encoding="utf-8")
        return self.build_source(source, name=str(path))

    # ------------------------------------------------------------------ core

    def _build_body(
        self, stmts: list[ast.stmt], scope_name: str
    ) -> tuple[nx.DiGraph, dict[int, BasicBlock]]:
        graph: nx.DiGraph = nx.DiGraph()
        blocks: dict[int, BasicBlock] = {}

        entry = BasicBlock(kind="entry", label=scope_name)
        exit_ = BasicBlock(kind="exit", label=scope_name + ":exit")
        blocks[entry.id] = entry
        blocks[exit_.id] = exit_
        graph.add_node(entry.id)
        graph.add_node(exit_.id)

        # Walk body; _process returns the set of "live" block ids that need
        # to be connected to whatever comes next.
        live = self._process_stmts(
            stmts, graph, blocks, predecessors={entry.id}, exit_id=exit_.id
        )

        # Connect remaining live blocks to the exit node.
        for pred in live:
            if pred != exit_.id:
                self._add_edge(graph, pred, exit_.id, "fallthrough")

        return graph, blocks

    def _process_stmts(
        self,
        stmts: list[ast.stmt],
        graph: nx.DiGraph,
        blocks: dict[int, BasicBlock],
        predecessors: set[int],
        exit_id: int,
    ) -> set[int]:
        """
        Emit basic blocks for *stmts* into *graph*/*blocks*.

        Returns the set of block ids that are "live" after processing
        (i.e., they have no outgoing edge yet and need to be connected
        to the next thing).
        """
        current_block: BasicBlock | None = None
        live: set[int] = set(predecessors)

        def flush() -> None:
            nonlocal current_block
            if current_block is not None and current_block.stmts:
                blocks[current_block.id] = current_block
                graph.add_node(current_block.id)
                current_block = None

        def get_or_create_current() -> BasicBlock:
            nonlocal current_block
            if current_block is None:
                current_block = BasicBlock(kind="sequence")
                blocks[current_block.id] = current_block
                graph.add_node(current_block.id)
                for pred in live:
                    self._add_edge(graph, pred, current_block.id, "unconditional")
                live.clear()
                live.add(current_block.id)
            return current_block

        for stmt in stmts:
            # ---- branch: if / elif / else ----------------------------
            if isinstance(stmt, ast.If):
                flush()
                live = self._process_if(stmt, graph, blocks, live, exit_id)

            # ---- loops: for / while / async-for ----------------------
            elif isinstance(stmt, (ast.For, ast.AsyncFor, ast.While)):
                flush()
                live = self._process_loop(stmt, graph, blocks, live, exit_id)

            # ---- try / except / finally ------------------------------
            elif isinstance(stmt, ast.Try):
                flush()
                live = self._process_try(stmt, graph, blocks, live, exit_id)

            # ---- with ------------------------------------------------
            elif isinstance(stmt, (ast.With, ast.AsyncWith)):
                flush()
                live = self._process_with(stmt, graph, blocks, live, exit_id)

            # ---- function / class defs (treated as opaque stmts) -----
            elif isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                blk = get_or_create_current()
                blk.stmts.append(stmt)
                flush()

            # ---- hard terminators ------------------------------------
            elif isinstance(stmt, (ast.Return, ast.Raise)):
                blk = get_or_create_current()
                blk.stmts.append(stmt)
                flush()
                for pred in live:
                    self._add_edge(graph, pred, exit_id, "return" if isinstance(stmt, ast.Return) else "raise")
                live = set()

            elif isinstance(stmt, ast.Break):
                blk = get_or_create_current()
                blk.stmts.append(stmt)
                flush()
                # Break target is resolved by the loop handler; mark as sentinel
                live = {"__break__"}  # type: ignore[assignment]

            elif isinstance(stmt, ast.Continue):
                blk = get_or_create_current()
                blk.stmts.append(stmt)
                flush()
                live = {"__continue__"}  # type: ignore[assignment]

            # ---- plain statements ------------------------------------
            else:
                blk = get_or_create_current()
                blk.stmts.append(stmt)

        flush()
        return live

    # ------------------------------------------------------------------ if

    def _process_if(
        self,
        node: ast.If,
        graph: nx.DiGraph,
        blocks: dict[int, BasicBlock],
        predecessors: set[int],
        exit_id: int,
    ) -> set[int]:
        # Condition block
        cond_block = BasicBlock(
            kind="branch",
            label=f"if {_stmt_summary(node)}",
            stmts=[node],
        )
        blocks[cond_block.id] = cond_block
        graph.add_node(cond_block.id)
        for pred in predecessors:
            self._add_edge(graph, pred, cond_block.id, "unconditional")

        # True branch
        true_live = self._process_stmts(
            node.body, graph, blocks, predecessors={cond_block.id}, exit_id=exit_id
        )
        for pred in true_live:
            self._add_edge(graph, cond_block.id, pred, "true")
        # Overwrite edge: the cond_block already connects via _process_stmts;
        # we need true edge from cond_block to the first block of the body.
        # Re-label the unconditional edges that left cond_block going into body.
        self._relabel_edges_from(graph, cond_block.id, node.body, "true")

        # False / else branch
        if node.orelse:
            false_live = self._process_stmts(
                node.orelse, graph, blocks, predecessors={cond_block.id}, exit_id=exit_id
            )
            self._relabel_edges_from(graph, cond_block.id, node.orelse, "false")
        else:
            false_live = {cond_block.id}

        return true_live | false_live

    # ------------------------------------------------------------------ loops

    def _process_loop(
        self,
        node: ast.For | ast.AsyncFor | ast.While,
        graph: nx.DiGraph,
        blocks: dict[int, BasicBlock],
        predecessors: set[int],
        exit_id: int,
    ) -> set[int]:
        # Loop header
        if isinstance(node, ast.While):
            lbl = f"while {ast.unparse(node.test)}"
        else:
            lbl = f"for {ast.unparse(node.target)} in {ast.unparse(node.iter)}"

        header = BasicBlock(kind="loop_header", label=lbl, stmts=[node])
        blocks[header.id] = header
        graph.add_node(header.id)
        for pred in predecessors:
            self._add_edge(graph, pred, header.id, "unconditional")

        # Body
        body_live = self._process_stmts(
            node.body, graph, blocks, predecessors={header.id}, exit_id=exit_id
        )
        self._relabel_edges_from(graph, header.id, node.body, "loop-body")

        # Back edges from live body exits → header (continue targets)
        actual_live: set[int] = set()
        break_ids: set[int] = set()
        for pred in body_live:
            if pred == "__break__":  # type: ignore[comparison-overlap]
                break_ids.add(pred)
            elif pred == "__continue__":  # type: ignore[comparison-overlap]
                pass  # continue → header; handled below via all body_live
            else:
                self._add_edge(graph, pred, header.id, "loop-back")

        # Loop exit block
        loop_exit = BasicBlock(kind="loop_exit", label=lbl + ":exit")
        blocks[loop_exit.id] = loop_exit
        graph.add_node(loop_exit.id)
        self._add_edge(graph, header.id, loop_exit.id, "loop-exit")

        # orelse (for-else / while-else) feeds into exit block
        if node.orelse:
            else_live = self._process_stmts(
                node.orelse, graph, blocks, predecessors={loop_exit.id}, exit_id=exit_id
            )
            actual_live |= else_live
        else:
            actual_live.add(loop_exit.id)

        # break statements exit directly to loop_exit
        # (we can't retroactively fix the __break__ sentinel here without
        # a second pass; instead, the last block that issued break connects)
        # We handle it by scanning for Break-terminating blocks in body.
        for bid in list(graph.nodes):
            if bid not in blocks:
                continue
            blk = blocks[bid]
            if blk.stmts and isinstance(blk.stmts[-1], ast.Break):
                # Already has a "raise"/"return" to exit_id; re-route to loop_exit
                for u, v, data in list(graph.out_edges(bid, data=True)):
                    graph.remove_edge(u, v)
                self._add_edge(graph, bid, loop_exit.id, "break")

        return actual_live

    # ------------------------------------------------------------------ try

    def _process_try(
        self,
        node: ast.Try,
        graph: nx.DiGraph,
        blocks: dict[int, BasicBlock],
        predecessors: set[int],
        exit_id: int,
    ) -> set[int]:
        try_block = BasicBlock(kind="sequence", label="try")
        blocks[try_block.id] = try_block
        graph.add_node(try_block.id)
        for pred in predecessors:
            self._add_edge(graph, pred, try_block.id, "unconditional")

        body_live = self._process_stmts(
            node.body, graph, blocks, predecessors={try_block.id}, exit_id=exit_id
        )

        all_live: set[int] = set(body_live)

        for handler in node.handlers:
            exc_label = f"except {ast.unparse(handler.type) if handler.type else '*'}"
            h_block = BasicBlock(kind="branch", label=exc_label)
            blocks[h_block.id] = h_block
            graph.add_node(h_block.id)
            self._add_edge(graph, try_block.id, h_block.id, "exception")
            h_live = self._process_stmts(
                handler.body, graph, blocks, predecessors={h_block.id}, exit_id=exit_id
            )
            all_live |= h_live

        if node.orelse:
            else_live = self._process_stmts(
                node.orelse, graph, blocks, predecessors=body_live, exit_id=exit_id
            )
            all_live = else_live

        if node.finalbody:
            fin_live = self._process_stmts(
                node.finalbody, graph, blocks, predecessors=all_live, exit_id=exit_id
            )
            all_live = fin_live

        return all_live

    # ------------------------------------------------------------------ with

    def _process_with(
        self,
        node: ast.With | ast.AsyncWith,
        graph: nx.DiGraph,
        blocks: dict[int, BasicBlock],
        predecessors: set[int],
        exit_id: int,
    ) -> set[int]:
        with_block = BasicBlock(kind="sequence", label="with", stmts=[node])
        blocks[with_block.id] = with_block
        graph.add_node(with_block.id)
        for pred in predecessors:
            self._add_edge(graph, pred, with_block.id, "unconditional")

        return self._process_stmts(
            node.body, graph, blocks, predecessors={with_block.id}, exit_id=exit_id
        )

    # ------------------------------------------------------------------ helpers

    @staticmethod
    def _add_edge(graph: nx.DiGraph, u: int, v: int, label: str) -> None:
        if isinstance(u, str) or isinstance(v, str):
            return
        if not graph.has_edge(u, v):
            graph.add_edge(u, v, label=label)

    @staticmethod
    def _relabel_edges_from(
        graph: nx.DiGraph,
        source: int,
        stmts: list[ast.stmt],
        new_label: str,
    ) -> None:
        """
        Re-label the first edge leaving *source* whose destination block
        was created for *stmts*.  Because _process_stmts links preds →
        first new block with "unconditional", we upgrade that label.
        """
        for u, v, data in graph.out_edges(source, data=True):
            if data.get("label") == "unconditional":
                data["label"] = new_label
                return  # only upgrade the first one


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def build_cfg(
    source: str | None = None,
    *,
    file: str | Path | None = None,
    name: str | None = None,
    function: str | None = None,
) -> CFG | dict[str, CFG]:
    """
    Build one or more CFGs from Python source.

    Parameters
    ----------
    source   : Python source string (mutually exclusive with *file*)
    file     : Path to a Python source file
    name     : Name for the module-level CFG
    function : If given, return only the CFG for this function name.
               Pass ``"*"`` to get a dict of all top-level functions.

    Returns
    -------
    A single `CFG` (for a module or a named function) or
    ``dict[str, CFG]`` when ``function="*"``.
    """
    if file is not None:
        path = Path(file)
        source = path.read_text(encoding="utf-8")
        name = name or str(path)
    elif source is None:
        raise ValueError("Provide either 'source' or 'file'.")

    tree = ast.parse(source)
    builder = CFGBuilder()

    if function is None:
        return builder.build_module(tree, name=name or "<module>")

    # Collect all top-level function defs
    funcs: dict[str, ast.FunctionDef | ast.AsyncFunctionDef] = {
        node.name: node
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }

    if function == "*":
        return {fname: builder.build(fnode) for fname, fnode in funcs.items()}

    if function not in funcs:
        raise KeyError(f"Function '{function}' not found in source.")

    return builder.build(funcs[function])
