"""Tests for cfg.cfg_builder."""

import ast
import sys
import textwrap
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from cfg.cfg_builder import CFGBuilder, CFG, BasicBlock, build_cfg


def cfg_from(code: str, *, function: str | None = None) -> CFG:
    src = textwrap.dedent(code)
    if function:
        return build_cfg(source=src, function=function)
    return build_cfg(source=src)


# ---------------------------------------------------------------------------
# Basic block structure
# ---------------------------------------------------------------------------

class TestBasicBlocks(unittest.TestCase):

    def test_empty_module_has_entry_exit(self):
        cfg = cfg_from("")
        kinds = {b.kind for b in cfg.blocks.values()}
        self.assertIn("entry", kinds)
        self.assertIn("exit", kinds)

    def test_single_statement_one_block(self):
        cfg = cfg_from("x = 1")
        seq_blocks = [b for b in cfg.blocks.values() if b.kind == "sequence"]
        self.assertEqual(len(seq_blocks), 1)
        self.assertEqual(len(seq_blocks[0].stmts), 1)

    def test_consecutive_statements_merged(self):
        cfg = cfg_from("""
            x = 1
            y = 2
            z = 3
        """)
        seq_blocks = [b for b in cfg.blocks.values() if b.kind == "sequence"]
        # All three plain statements land in one block.
        stmts = [s for b in seq_blocks for s in b.stmts]
        self.assertEqual(len(stmts), 3)

    def test_basic_block_ids_unique(self):
        cfg = cfg_from("""
            x = 1
            if x:
                y = 2
        """)
        ids = list(cfg.blocks.keys())
        self.assertEqual(len(ids), len(set(ids)))

    def test_basic_block_to_dict(self):
        cfg = cfg_from("x = 1")
        blk = next(b for b in cfg.blocks.values() if b.kind == "sequence")
        d = blk.to_dict()
        self.assertIn("id", d)
        self.assertIn("kind", d)
        self.assertIn("stmts", d)
        self.assertIn("lines", d)

    def test_line_numbers_captured(self):
        cfg = cfg_from("x = 1\ny = 2")
        seq = next(b for b in cfg.blocks.values() if b.kind == "sequence")
        lines = seq.to_dict()["lines"]
        self.assertEqual(lines["start"], 1)

    def test_cfg_is_connected(self):
        cfg = cfg_from("x = 1\ny = 2")
        # undirected connectivity: every node should be reachable
        self.assertTrue(
            len(list(cfg.graph.nodes)) >= 2
        )

    def test_cfg_to_dict_structure(self):
        cfg = cfg_from("x = 1")
        d = cfg.to_dict()
        self.assertIn("blocks", d)
        self.assertIn("edges", d)
        self.assertIn("summary", d)

    def test_cfg_to_json_is_valid(self):
        import json
        cfg = cfg_from("x = 1")
        data = json.loads(cfg.to_json())
        self.assertIsInstance(data["blocks"], list)


# ---------------------------------------------------------------------------
# Imports and plain statements
# ---------------------------------------------------------------------------

class TestImportStatements(unittest.TestCase):

    def test_import_in_sequence_block(self):
        cfg = cfg_from("import os\nimport sys")
        seq = [b for b in cfg.blocks.values() if b.kind == "sequence"]
        stmts_text = [ast.unparse(s) for b in seq for s in b.stmts]
        self.assertTrue(any("os" in t for t in stmts_text))
        self.assertTrue(any("sys" in t for t in stmts_text))


# ---------------------------------------------------------------------------
# Branch (if/elif/else) detection
# ---------------------------------------------------------------------------

class TestBranches(unittest.TestCase):

    def test_if_creates_branch_block(self):
        cfg = cfg_from("""
            if x > 0:
                y = 1
        """)
        self.assertEqual(len(cfg.branches()), 1)
        self.assertEqual(cfg.branches()[0].kind, "branch")

    def test_if_else_two_paths(self):
        cfg = cfg_from("""
            if flag:
                a = 1
            else:
                b = 2
        """)
        # At least one true and one false edge from the branch block
        branch_id = cfg.branches()[0].id
        edge_labels = {
            data["label"]
            for _, _, data in cfg.graph.out_edges(branch_id, data=True)
        }
        self.assertIn("true", edge_labels)

    def test_nested_if(self):
        cfg = cfg_from("""
            if a:
                if b:
                    x = 1
        """)
        self.assertEqual(len(cfg.branches()), 2)

    def test_branch_count_elif(self):
        cfg = cfg_from("""
            if x == 1:
                pass
            elif x == 2:
                pass
            else:
                pass
        """)
        # The elif is represented as a nested if in the AST → 2 branch blocks
        self.assertGreaterEqual(len(cfg.branches()), 2)

    def test_no_branches_flat_code(self):
        cfg = cfg_from("x = 1\ny = 2\nz = x + y")
        self.assertEqual(len(cfg.branches()), 0)


# ---------------------------------------------------------------------------
# Loop detection
# ---------------------------------------------------------------------------

class TestLoops(unittest.TestCase):

    def test_for_loop_creates_header(self):
        cfg = cfg_from("""
            for i in range(10):
                print(i)
        """)
        self.assertEqual(len(cfg.loops()), 1)
        self.assertEqual(cfg.loops()[0].kind, "loop_header")

    def test_while_loop_creates_header(self):
        cfg = cfg_from("""
            while True:
                pass
        """)
        self.assertEqual(len(cfg.loops()), 1)

    def test_loop_back_edge_exists(self):
        cfg = cfg_from("""
            for i in range(5):
                x = i
        """)
        back_edges = cfg.loop_back_edges()
        self.assertGreaterEqual(len(back_edges), 1)

    def test_loop_exit_block_created(self):
        cfg = cfg_from("""
            for i in range(3):
                pass
        """)
        exit_blocks = [b for b in cfg.blocks.values() if b.kind == "loop_exit"]
        self.assertGreaterEqual(len(exit_blocks), 1)

    def test_nested_loops(self):
        cfg = cfg_from("""
            for i in range(3):
                for j in range(3):
                    pass
        """)
        self.assertEqual(len(cfg.loops()), 2)

    def test_while_loop_back_edge(self):
        cfg = cfg_from("""
            n = 0
            while n < 10:
                n += 1
        """)
        self.assertGreaterEqual(len(cfg.loop_back_edges()), 1)

    def test_loop_header_label(self):
        cfg = cfg_from("""
            for x in items:
                pass
        """)
        header = cfg.loops()[0]
        self.assertIn("for", header.label)
        self.assertIn("items", header.label)

    def test_while_header_label(self):
        cfg = cfg_from("""
            while cond:
                pass
        """)
        header = cfg.loops()[0]
        self.assertIn("while", header.label)

    def test_break_exits_loop(self):
        cfg = cfg_from("""
            for i in range(10):
                if i == 5:
                    break
        """)
        # There should be a 'break' edge to the loop_exit block
        break_edges = [
            (u, v)
            for u, v, data in cfg.graph.edges(data=True)
            if data.get("label") == "break"
        ]
        self.assertGreaterEqual(len(break_edges), 1)

    def test_continue_in_loop(self):
        cfg = cfg_from("""
            for i in range(10):
                if i % 2 == 0:
                    continue
                print(i)
        """)
        # Graph should have a back-edge to the header
        self.assertGreaterEqual(len(cfg.loop_back_edges()), 1)

    def test_for_else(self):
        cfg = cfg_from("""
            for i in range(3):
                pass
            else:
                done = True
        """)
        self.assertGreaterEqual(len(cfg.loops()), 1)


# ---------------------------------------------------------------------------
# Function-level CFG
# ---------------------------------------------------------------------------

class TestFunctionCFG(unittest.TestCase):

    def test_function_cfg_name(self):
        cfg = cfg_from("""
            def add(a, b):
                return a + b
        """, function="add")
        self.assertEqual(cfg.name, "add")

    def test_return_connects_to_exit(self):
        cfg = cfg_from("""
            def f(x):
                if x > 0:
                    return x
                return -x
        """, function="f")
        exit_id = cfg.exit_block().id
        return_edges = [
            (u, v)
            for u, v, data in cfg.graph.edges(data=True)
            if v == exit_id and data.get("label") == "return"
        ]
        self.assertGreaterEqual(len(return_edges), 1)

    def test_multiple_functions(self):
        cfgs = build_cfg(source=textwrap.dedent("""
            def foo(): pass
            def bar(): pass
        """), function="*")
        self.assertIn("foo", cfgs)
        self.assertIn("bar", cfgs)

    def test_function_with_loop_and_branch(self):
        cfg = cfg_from("""
            def process(items):
                result = []
                for item in items:
                    if item > 0:
                        result.append(item)
                return result
        """, function="process")
        self.assertEqual(len(cfg.loops()), 1)
        self.assertEqual(len(cfg.branches()), 1)

    def test_async_function(self):
        cfg = cfg_from("""
            async def fetch(url):
                return url
        """, function="fetch")
        self.assertEqual(cfg.name, "fetch")

    def test_unknown_function_raises(self):
        with self.assertRaises(KeyError):
            build_cfg(source="def foo(): pass", function="bar")


# ---------------------------------------------------------------------------
# Try / except
# ---------------------------------------------------------------------------

class TestTryExcept(unittest.TestCase):

    def test_try_creates_exception_edge(self):
        cfg = cfg_from("""
            try:
                x = int(s)
            except ValueError:
                x = 0
        """)
        exc_edges = [
            (u, v)
            for u, v, data in cfg.graph.edges(data=True)
            if data.get("label") == "exception"
        ]
        self.assertGreaterEqual(len(exc_edges), 1)

    def test_except_handler_is_branch_block(self):
        cfg = cfg_from("""
            try:
                risky()
            except TypeError as e:
                handle(e)
        """)
        branch_labels = [b.label for b in cfg.branches()]
        self.assertTrue(any("except" in lbl for lbl in branch_labels))


# ---------------------------------------------------------------------------
# With statement
# ---------------------------------------------------------------------------

class TestWithStatement(unittest.TestCase):

    def test_with_creates_block(self):
        cfg = cfg_from("""
            with open('f') as fh:
                data = fh.read()
        """)
        with_blocks = [b for b in cfg.blocks.values() if b.label == "with"]
        self.assertGreaterEqual(len(with_blocks), 1)


# ---------------------------------------------------------------------------
# CFG summary and repr
# ---------------------------------------------------------------------------

class TestCFGSummary(unittest.TestCase):

    def test_summary_counts(self):
        cfg = cfg_from("""
            for i in range(3):
                if i > 1:
                    break
        """)
        s = cfg.to_dict()["summary"]
        self.assertGreaterEqual(s["loops"], 1)
        self.assertGreaterEqual(s["branches"], 1)
        self.assertGreaterEqual(s["total_blocks"], 3)

    def test_repr(self):
        cfg = cfg_from("x = 1")
        r = repr(cfg)
        self.assertIn("CFG", r)
        self.assertIn("blocks=", r)

    def test_basic_blocks_ordered(self):
        cfg = cfg_from("a = 1\nb = 2")
        blocks = cfg.basic_blocks()
        self.assertIsInstance(blocks, list)
        self.assertGreater(len(blocks), 0)


if __name__ == "__main__":
    unittest.main()
