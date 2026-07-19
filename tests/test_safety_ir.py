"""Tests for analysis.safety_ir.safety_ir_builder."""

import json
import sys
import textwrap
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from analysis.safety_ir import build_safety_ir_from_source, safety_ir_to_json


def ir_from(code: str):
    return build_safety_ir_from_source(
        textwrap.dedent(code),
        source_name="<test>",
        timestamp="2026-05-18T00:00:00Z",
        analysis_version="2026.05",
    )


class TestRequiredNodeTypes(unittest.TestCase):

    def test_required_node_types_present(self):
        ir = ir_from("""
            import os
            def run(x):
                while True:
                    os.system(x)
            run(input())
        """)
        d = ir.to_dict()

        self.assertEqual(d["node_type"], "ManifestRoot")
        self.assertTrue(any(n["node_type"] == "FunctionNode" for n in d["nodes"]["functions"]))
        self.assertTrue(any(n["node_type"] == "LoopNode" for n in d["nodes"]["loops"]))
        self.assertTrue(any(n["node_type"] == "CapabilityNode" for n in d["nodes"]["capabilities"]))
        self.assertTrue(any(n["node_type"] == "CFGBlockNode" for n in d["nodes"]["cfg_blocks"]))
        self.assertTrue(any(e["node_type"] == "TaintFlowEdge" for e in d["edges"]["taint_flows"]))


class TestSourceReferences(unittest.TestCase):

    def test_function_and_loop_line_refs(self):
        ir = ir_from("""
            def f(n):
                while n > 0:
                    n -= 1
                return n
        """)
        d = ir.to_dict()

        fn = d["nodes"]["functions"][0]
        lp = d["nodes"]["loops"][0]
        self.assertEqual(fn["source"]["line"], 2)
        self.assertEqual(lp["source"]["line"], 3)

    def test_capability_line_refs(self):
        ir = ir_from("""
            import os
            os.system('ls')
        """)
        d = ir.to_dict()
        caps = d["nodes"]["capabilities"]
        self.assertTrue(any(c["source"]["line"] == 3 for c in caps))


class TestGraphRelationships(unittest.TestCase):

    def test_graph_edges_present(self):
        ir = ir_from("""
            import os
            def g(x):
                os.system(x)
            g(input())
        """)
        d = ir.to_dict()
        graph = d["edges"]["graph"]
        self.assertTrue(len(graph) > 0)
        self.assertTrue(any(e["edge_type"] in {"contains", "observes", "cfg_next"} for e in graph))

    def test_taint_flow_edge_links_to_nodes(self):
        ir = ir_from("""
            import os
            def g():
                cmd = input()
                os.system(cmd)
            g()
        """)
        d = ir.to_dict()
        flow = d["edges"]["taint_flows"]
        self.assertTrue(len(flow) >= 1)
        self.assertIn("from", flow[0])
        self.assertIn("to", flow[0])


class TestDeterministicSerialization(unittest.TestCase):

    def test_same_input_same_json(self):
        code = """
            def f(x):
                for i in range(3):
                    x += i
                return x
        """
        ir1 = ir_from(code)
        ir2 = ir_from(code)

        j1 = safety_ir_to_json(ir1, indent=2)
        j2 = safety_ir_to_json(ir2, indent=2)
        self.assertEqual(j1, j2)

    def test_json_is_machine_readable(self):
        ir = ir_from("x = 1")
        raw = safety_ir_to_json(ir)
        obj = json.loads(raw)
        self.assertEqual(obj["node_type"], "ManifestRoot")
        self.assertIn("nodes", obj)
        self.assertIn("edges", obj)


class TestScopeModeling(unittest.TestCase):

    def test_ir_declares_non_semantic_scope(self):
        ir = ir_from("x = 1")
        d = ir.to_dict()
        self.assertFalse(d["metadata"]["full_python_semantics"])
        self.assertEqual(d["metadata"]["modeling_scope"], "safety_relevant_only")


if __name__ == "__main__":
    unittest.main()
