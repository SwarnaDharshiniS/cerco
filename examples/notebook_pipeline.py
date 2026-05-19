"""Notebook parsing and orchestrator execution example.

Run from repository root:
    python3 examples/notebook_pipeline.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from parser import parse_notebook_source
from sandbox.execution_orchestrator import SandboxedExecutionOrchestrator


def main() -> None:
    notebook_data = {
        "cells": [
            {
                "cell_type": "markdown",
                "metadata": {"id": "m1"},
                "source": ["# Demo notebook\n"],
            },
            {
                "cell_type": "code",
                "metadata": {"id": "c1"},
                "execution_count": 1,
                "source": ["x = 10\n"],
            },
            {
                "cell_type": "code",
                "metadata": {"id": "c2"},
                "execution_count": 2,
                "source": ["y = 15\nprint(y)\n"],
            },
            {
                "cell_type": "code",
                "metadata": {"id": "c3"},
                "execution_count": 3,
                "source": ["%time y\n"],
            },
        ],
        "metadata": {},
        "nbformat": 4,
        "nbformat_minor": 5,
    }

    parsed = parse_notebook_source(json.dumps(notebook_data), source_name="in_memory.ipynb")

    print("=== Notebook Parse Summary ===")
    print(f"total_cells: {parsed['total_cells']}")
    print(f"execution_units: {len(parsed['execution_units'])}")
    print(f"independent_cells: {parsed['independent_cells']}")
    print(f"dag_is_dag: {parsed['code_dependency_dag']['is_dag']}")

    orchestrator = SandboxedExecutionOrchestrator()
    cell_to_unit_id = {u["cell_id"]: u["unit_id"] for u in parsed["execution_units"]}
    units = []
    for unit in parsed["execution_units"]:
        mapped_deps = [cell_to_unit_id[d] for d in unit["dependency_ids"] if d in cell_to_unit_id]
        units.append(
            {
                "unit_id": unit["unit_id"],
                "code": unit["code"],
                "dependency_ids": mapped_deps,
                "static_validation": {"passed": True},
            }
        )

    result = orchestrator.execute_units(units)
    print("\n=== Orchestrator Results ===")
    print(f"total: {result['summary']['total']}")
    print(f"success: {result['summary']['success']}")
    print(f"failed: {result['summary']['failed']}")
    for item in result["results"]:
        print(f"- {item['unit_id']}: {item['status']}")


if __name__ == "__main__":
    main()
