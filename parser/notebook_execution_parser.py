"""Jupyter notebook execution parser for untrusted Python analysis."""

from __future__ import annotations

import ast
import json
from pathlib import Path
from typing import Any

CELL_CODE = "CODE"
CELL_MARKDOWN = "MARKDOWN"
CELL_MAGIC = "MAGIC"
CELL_SHELL = "SHELL"


class NotebookExecutionParser:
    """Parses .ipynb documents into execution-ready analysis structures."""

    def parse_file(self, path: str | Path) -> dict[str, Any]:
        p = Path(path)
        raw = p.read_text(encoding="utf-8")
        return self.parse_source(raw, source_name=str(p))

    def parse_source(self, raw_json: str, *, source_name: str = "<string>") -> dict[str, Any]:
        data = json.loads(raw_json)
        if not isinstance(data, dict):
            raise ValueError("notebook JSON root must be an object")
        return self.parse_data(data, source_name=source_name)

    def parse_data(self, data: dict[str, Any], *, source_name: str = "<string>") -> dict[str, Any]:
        raw_cells = data.get("cells", [])
        if not isinstance(raw_cells, list):
            raise ValueError("notebook cells must be a list")

        cells: list[dict[str, Any]] = []
        execution_units: list[dict[str, Any]] = []
        dependency_graph: dict[str, list[str]] = {}
        code_cell_ids: list[str] = []

        name_to_cell: dict[str, str] = {}
        defined_names_by_cell: dict[str, set[str]] = {}
        used_names_by_cell: dict[str, set[str]] = {}

        for idx, raw_cell in enumerate(raw_cells, start=1):
            if not isinstance(raw_cell, dict):
                continue

            cell_id = self._cell_id(raw_cell, idx)
            cell_type = str(raw_cell.get("cell_type", ""))
            source = self._source_text(raw_cell.get("source", []))
            execution_count = raw_cell.get("execution_count")
            classification = self._classify_cell(cell_type=cell_type, source=source)

            parsed_cell = {
                "cell_id": cell_id,
                "notebook_index": idx,
                "execution_count": execution_count,
                "cell_type": cell_type,
                "classification": classification,
                "source": source,
                "dependency_ids": [],
            }

            cells.append(parsed_cell)
            dependency_graph[cell_id] = []

            if classification != CELL_CODE:
                continue

            code_cell_ids.append(cell_id)

            defined_names, used_names, imports, static_signals = self._analyze_code_cell(source)
            defined_names_by_cell[cell_id] = defined_names
            used_names_by_cell[cell_id] = used_names

            dep_ids = sorted({name_to_cell[name] for name in used_names if name in name_to_cell})
            parsed_cell["dependency_ids"] = dep_ids
            dependency_graph[cell_id] = dep_ids

            for name in sorted(defined_names):
                name_to_cell[name] = cell_id

            execution_units.append(
                {
                    "unit_id": f"unit_{len(execution_units) + 1}",
                    "cell_id": cell_id,
                    "execution_order": len(execution_units) + 1,
                    "dependency_ids": dep_ids,
                    "code": source,
                    "static_analysis": {
                        "imports": imports,
                        "defined_symbols": sorted(defined_names),
                        "referenced_symbols": sorted(used_names),
                        **static_signals,
                    },
                }
            )

        for c in cells:
            if c["classification"] != CELL_CODE:
                continue
            c["defined_symbols"] = sorted(defined_names_by_cell.get(c["cell_id"], set()))
            c["referenced_symbols"] = sorted(used_names_by_cell.get(c["cell_id"], set()))

        dag = self._build_dag(code_cell_ids=code_cell_ids, dependency_graph=dependency_graph)
        independent = sorted(
            [
                cid
                for cid in code_cell_ids
                if len(dependency_graph.get(cid, [])) == 0
            ]
        )

        return {
            "source_name": source_name,
            "format": "ipynb",
            "total_cells": len(cells),
            "cells": cells,
            "execution_units": execution_units,
            "dependency_graph": dependency_graph,
            "code_dependency_dag": dag,
            "independent_cells": independent,
            "distributed_execution": {
                "ready": True,
                "unit_count": len(execution_units),
                "dependency_type": "symbol_reference",
                "independent_cell_count": len(independent),
            },
            "pre_runtime_safety_analysis": {
                "ready": True,
                "signal_source": "static_ast",
                "unit_count": len(execution_units),
            },
        }

    @staticmethod
    def _build_dag(*, code_cell_ids: list[str], dependency_graph: dict[str, list[str]]) -> dict[str, Any]:
        nodes = list(code_cell_ids)
        incoming: dict[str, set[str]] = {n: set(dependency_graph.get(n, [])) for n in nodes}
        outgoing: dict[str, set[str]] = {n: set() for n in nodes}

        for node in nodes:
            for dep in incoming[node]:
                if dep in outgoing:
                    outgoing[dep].add(node)

        edges = sorted(
            [
                {"from": dep, "to": node}
                for node in nodes
                for dep in sorted(incoming[node])
                if dep in incoming
            ],
            key=lambda e: (e["from"], e["to"]),
        )

        in_degree = {n: len(incoming[n]) for n in nodes}
        queue = sorted([n for n in nodes if in_degree[n] == 0])
        topo_order: list[str] = []
        levels: list[list[str]] = []

        while queue:
            current_level = list(queue)
            levels.append(current_level)
            next_queue: set[str] = set()

            for node in current_level:
                topo_order.append(node)
                for out in sorted(outgoing[node]):
                    in_degree[out] -= 1
                    if in_degree[out] == 0:
                        next_queue.add(out)

            queue = sorted(next_queue)

        is_dag = len(topo_order) == len(nodes)
        return {
            "nodes": nodes,
            "edges": edges,
            "topological_order": topo_order if is_dag else [],
            "levels": levels if is_dag else [],
            "is_dag": is_dag,
        }

    @staticmethod
    def _cell_id(raw_cell: dict[str, Any], index: int) -> str:
        metadata = raw_cell.get("metadata", {})
        if isinstance(metadata, dict):
            maybe_id = metadata.get("id")
            if isinstance(maybe_id, str) and maybe_id.strip():
                return maybe_id
        return f"cell_{index}"

    @staticmethod
    def _source_text(src: Any) -> str:
        if isinstance(src, str):
            return src
        if isinstance(src, list):
            return "".join(str(x) for x in src)
        return ""

    def _classify_cell(self, *, cell_type: str, source: str) -> str:
        if cell_type == "markdown":
            return CELL_MARKDOWN

        if cell_type != "code":
            return CELL_MARKDOWN

        first = self._first_content_line(source)
        if first is None:
            return CELL_CODE

        shell_magics = ("%%bash", "%%sh", "%%script", "!", "%%cmd", "%%shell")
        if first.startswith(shell_magics):
            return CELL_SHELL
        if first.startswith("%%") or first.startswith("%"):
            return CELL_MAGIC
        return CELL_CODE

    @staticmethod
    def _first_content_line(source: str) -> str | None:
        for line in source.splitlines():
            stripped = line.strip()
            if stripped:
                return stripped
        return None

    def _analyze_code_cell(self, source: str) -> tuple[set[str], set[str], list[str], dict[str, Any]]:
        try:
            tree = ast.parse(source)
        except SyntaxError:
            return set(), set(), [], {
                "syntax_valid": False,
                "dynamic_execution_primitives": [],
                "subprocess_calls": [],
                "filesystem_calls": [],
            }

        collector = _SymbolCollector()
        collector.visit(tree)

        dynamic_prims = sorted(set(x for x in collector.call_names if x in {"eval", "exec", "compile", "__import__"}))
        subprocess_calls = sorted(set(x for x in collector.call_names if x.startswith("subprocess.") or x in {"os.system", "os.popen"}))
        filesystem_calls = sorted(
            set(
                x
                for x in collector.call_names
                if x in {"open", "os.open", "os.remove", "os.unlink", "os.rename", "pathlib.Path.read_text", "pathlib.Path.write_text"}
            )
        )

        return collector.defined, collector.used, sorted(collector.imports), {
            "syntax_valid": True,
            "dynamic_execution_primitives": dynamic_prims,
            "subprocess_calls": subprocess_calls,
            "filesystem_calls": filesystem_calls,
        }


class _SymbolCollector(ast.NodeVisitor):
    def __init__(self) -> None:
        self.defined: set[str] = set()
        self.used: set[str] = set()
        self.imports: set[str] = set()
        self.call_names: list[str] = []

    def visit_Name(self, node: ast.Name) -> None:
        if isinstance(node.ctx, ast.Store):
            self.defined.add(node.id)
        elif isinstance(node.ctx, ast.Load):
            self.used.add(node.id)
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self.defined.add(node.name)
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self.defined.add(node.name)
        self.generic_visit(node)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self.defined.add(node.name)
        self.generic_visit(node)

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            name = alias.asname or alias.name.split(".")[0]
            self.defined.add(name)
            self.imports.add(alias.name)
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        module = node.module or ""
        if module:
            self.imports.add(module)
        for alias in node.names:
            if alias.name == "*":
                continue
            local_name = alias.asname or alias.name
            self.defined.add(local_name)
            if module:
                self.imports.add(f"{module}.{alias.name}")
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        qname = self._call_qname(node)
        if qname:
            self.call_names.append(qname)
        self.generic_visit(node)

    @staticmethod
    def _call_qname(node: ast.Call) -> str | None:
        func = node.func
        if isinstance(func, ast.Name):
            return func.id
        if isinstance(func, ast.Attribute):
            if isinstance(func.value, ast.Name):
                return f"{func.value.id}.{func.attr}"
            if isinstance(func.value, ast.Attribute) and isinstance(func.value.value, ast.Name):
                return f"{func.value.value.id}.{func.value.attr}.{func.attr}"
        return None


def parse_notebook_source(raw_json: str, *, source_name: str = "<string>") -> dict[str, Any]:
    return NotebookExecutionParser().parse_source(raw_json, source_name=source_name)


def parse_notebook_file(path: str | Path) -> dict[str, Any]:
    return NotebookExecutionParser().parse_file(path)
