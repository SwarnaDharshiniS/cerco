"""Tests for parser.notebook_execution_parser."""

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from parser.notebook_execution_parser import parse_notebook_file, parse_notebook_source


def notebook_json(cells: list[dict]) -> str:
    return json.dumps({"cells": cells, "metadata": {}, "nbformat": 4, "nbformat_minor": 5})


class TestNotebookExtraction(unittest.TestCase):

    def test_extract_cells_preserves_order(self):
        raw = notebook_json(
            [
                {"cell_type": "markdown", "metadata": {"id": "m1"}, "source": ["# Title\n"]},
                {"cell_type": "code", "metadata": {"id": "c1"}, "execution_count": 1, "source": ["x = 1\n"]},
            ]
        )
        out = parse_notebook_source(raw, source_name="<test>")
        self.assertEqual(out["cells"][0]["cell_id"], "m1")
        self.assertEqual(out["cells"][1]["cell_id"], "c1")
        self.assertEqual(out["cells"][0]["notebook_index"], 1)
        self.assertEqual(out["cells"][1]["notebook_index"], 2)

    def test_parse_from_file(self):
        raw = notebook_json(
            [{"cell_type": "code", "metadata": {}, "execution_count": 1, "source": ["x = 1\n"]}]
        )
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "nb.ipynb"
            p.write_text(raw, encoding="utf-8")
            out = parse_notebook_file(p)
            self.assertEqual(out["total_cells"], 1)
            self.assertEqual(out["format"], "ipynb")


class TestClassification(unittest.TestCase):

    def test_classifies_markdown_magic_shell_code(self):
        raw = notebook_json(
            [
                {"cell_type": "markdown", "metadata": {}, "source": ["hello\n"]},
                {"cell_type": "code", "metadata": {}, "execution_count": 1, "source": ["%time x = 1\n"]},
                {"cell_type": "code", "metadata": {}, "execution_count": 2, "source": ["!ls\n"]},
                {"cell_type": "code", "metadata": {}, "execution_count": 3, "source": ["x = 1\n"]},
            ]
        )
        out = parse_notebook_source(raw)
        classes = [c["classification"] for c in out["cells"]]
        self.assertEqual(classes, ["MARKDOWN", "MAGIC", "SHELL", "CODE"])


class TestDependenciesAndUnits(unittest.TestCase):

    def test_assigns_dependency_ids_between_code_cells(self):
        raw = notebook_json(
            [
                {"cell_type": "code", "metadata": {"id": "c1"}, "execution_count": 1, "source": ["x = 1\n"]},
                {"cell_type": "code", "metadata": {"id": "c2"}, "execution_count": 2, "source": ["print(x)\n"]},
            ]
        )
        out = parse_notebook_source(raw)
        cells = out["cells"]
        self.assertEqual(cells[0]["dependency_ids"], [])
        self.assertEqual(cells[1]["dependency_ids"], ["c1"])

    def test_generates_isolated_execution_units_for_code_only(self):
        raw = notebook_json(
            [
                {"cell_type": "markdown", "metadata": {"id": "m1"}, "source": ["doc\n"]},
                {"cell_type": "code", "metadata": {"id": "c1"}, "execution_count": 1, "source": ["x = 1\n"]},
                {"cell_type": "code", "metadata": {"id": "s1"}, "execution_count": 2, "source": ["!echo hi\n"]},
                {"cell_type": "code", "metadata": {"id": "c2"}, "execution_count": 3, "source": ["y = x + 2\n"]},
            ]
        )
        out = parse_notebook_source(raw)
        units = out["execution_units"]
        self.assertEqual(len(units), 2)
        self.assertEqual(units[0]["cell_id"], "c1")
        self.assertEqual(units[1]["cell_id"], "c2")
        self.assertEqual(units[1]["dependency_ids"], ["c1"])

    def test_output_contains_distributed_and_safety_metadata(self):
        raw = notebook_json(
            [{"cell_type": "code", "metadata": {"id": "c1"}, "execution_count": 1, "source": ["import os\nos.system('ls')\n"]}]
        )
        out = parse_notebook_source(raw)
        self.assertTrue(out["distributed_execution"]["ready"])
        self.assertTrue(out["pre_runtime_safety_analysis"]["ready"])
        unit = out["execution_units"][0]
        self.assertIn("static_analysis", unit)
        self.assertIn("subprocess_calls", unit["static_analysis"])

    def test_builds_code_dependency_dag(self):
        raw = notebook_json(
            [
                {"cell_type": "code", "metadata": {"id": "c1"}, "execution_count": 1, "source": ["x = 1\n"]},
                {"cell_type": "code", "metadata": {"id": "c2"}, "execution_count": 2, "source": ["y = x + 1\n"]},
                {"cell_type": "code", "metadata": {"id": "c3"}, "execution_count": 3, "source": ["z = y + 1\n"]},
            ]
        )
        out = parse_notebook_source(raw)
        dag = out["code_dependency_dag"]

        self.assertTrue(dag["is_dag"])
        self.assertEqual(dag["topological_order"], ["c1", "c2", "c3"])
        self.assertIn({"from": "c1", "to": "c2"}, dag["edges"])
        self.assertIn({"from": "c2", "to": "c3"}, dag["edges"])

    def test_identifies_independent_cells(self):
        raw = notebook_json(
            [
                {"cell_type": "code", "metadata": {"id": "c1"}, "execution_count": 1, "source": ["x = 1\n"]},
                {"cell_type": "code", "metadata": {"id": "c2"}, "execution_count": 2, "source": ["a = 7\n"]},
                {"cell_type": "code", "metadata": {"id": "c3"}, "execution_count": 3, "source": ["print(x)\n"]},
            ]
        )
        out = parse_notebook_source(raw)
        self.assertEqual(out["independent_cells"], ["c1", "c2"])
        self.assertEqual(out["distributed_execution"]["independent_cell_count"], 2)


if __name__ == "__main__":
    unittest.main()
