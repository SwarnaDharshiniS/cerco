"""Tests for parser.ast_parser."""

import json
import sys
import textwrap
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from parser.ast_parser import parse_source


def src(code: str) -> dict:
    return parse_source(textwrap.dedent(code))


class TestNodeTypes(unittest.TestCase):
    def test_module_root(self):
        tree = src("x = 1")
        self.assertEqual(tree["node_type"], "Module")
        self.assertIn("body", tree)

    def test_location_fields(self):
        tree = src("x = 1")
        assign = tree["body"][0]
        self.assertIn("line", assign)
        self.assertIn("col", assign)

    def test_expression_node(self):
        tree = src("1 + 2")
        expr = tree["body"][0]
        self.assertEqual(expr["node_type"], "Expr")
        binop = expr["value"]
        self.assertEqual(binop["node_type"], "BinOp")
        self.assertEqual(binop["op"], "Add")

    def test_constant(self):
        tree = src("42")
        const = tree["body"][0]["value"]
        self.assertEqual(const["node_type"], "Constant")
        self.assertEqual(const["value"], 42)
        self.assertEqual(const["kind"], "int")

    def test_name(self):
        tree = src("foo")
        name = tree["body"][0]["value"]
        self.assertEqual(name["node_type"], "Name")
        self.assertEqual(name["id"], "foo")

    def test_json_serialisable(self):
        tree = src("x = [1, 2, 3]")
        # should not raise
        json.dumps(tree)


class TestImports(unittest.TestCase):
    def test_import(self):
        tree = src("import os")
        node = tree["body"][0]
        self.assertEqual(node["node_type"], "Import")
        self.assertEqual(node["names"], [{"name": "os", "asname": None}])

    def test_import_alias(self):
        tree = src("import numpy as np")
        node = tree["body"][0]
        self.assertEqual(node["names"][0], {"name": "numpy", "asname": "np"})

    def test_import_multiple(self):
        tree = src("import os, sys")
        node = tree["body"][0]
        self.assertEqual(len(node["names"]), 2)
        self.assertEqual(node["names"][0]["name"], "os")
        self.assertEqual(node["names"][1]["name"], "sys")

    def test_from_import(self):
        tree = src("from os.path import join")
        node = tree["body"][0]
        self.assertEqual(node["node_type"], "ImportFrom")
        self.assertEqual(node["module"], "os.path")
        self.assertEqual(node["level"], 0)
        self.assertEqual(node["names"], [{"name": "join", "asname": None}])

    def test_from_import_alias(self):
        tree = src("from pathlib import Path as P")
        node = tree["body"][0]
        self.assertEqual(node["names"][0], {"name": "Path", "asname": "P"})

    def test_relative_import(self):
        tree = src("from . import utils")
        node = tree["body"][0]
        self.assertEqual(node["node_type"], "ImportFrom")
        self.assertEqual(node["level"], 1)
        self.assertEqual(node["module"], "")

    def test_star_import(self):
        tree = src("from os import *")
        node = tree["body"][0]
        self.assertEqual(node["names"][0]["name"], "*")


class TestFunctionDefinitions(unittest.TestCase):
    def test_simple_function(self):
        tree = src("""
            def greet(name):
                return name
        """)
        func = tree["body"][0]
        self.assertEqual(func["node_type"], "FunctionDef")
        self.assertEqual(func["name"], "greet")
        self.assertFalse(func["is_async"])

    def test_function_args(self):
        tree = src("""
            def add(a, b):
                return a + b
        """)
        args = tree["body"][0]["args"]
        self.assertEqual([a["name"] for a in args["args"]], ["a", "b"])

    def test_function_defaults(self):
        tree = src("""
            def greet(name="world"):
                pass
        """)
        args = tree["body"][0]["args"]
        self.assertEqual(args["defaults"][0]["value"], "world")

    def test_function_annotations(self):
        tree = src("""
            def add(a: int, b: int) -> int:
                return a + b
        """)
        func = tree["body"][0]
        args = func["args"]["args"]
        self.assertEqual(args[0]["annotation"]["id"], "int")
        self.assertEqual(func["returns"]["id"], "int")

    def test_function_vararg_kwarg(self):
        tree = src("""
            def f(*args, **kwargs):
                pass
        """)
        fargs = tree["body"][0]["args"]
        self.assertEqual(fargs["vararg"]["name"], "args")
        self.assertEqual(fargs["kwarg"]["name"], "kwargs")

    def test_function_kwonlyargs(self):
        tree = src("""
            def f(*, key=None):
                pass
        """)
        fargs = tree["body"][0]["args"]
        self.assertEqual(fargs["kwonlyargs"][0]["name"], "key")

    def test_function_body(self):
        tree = src("""
            def f():
                x = 1
                return x
        """)
        body = tree["body"][0]["body"]
        self.assertEqual(body[0]["node_type"], "Assign")
        self.assertEqual(body[1]["node_type"], "Return")

    def test_function_decorator(self):
        tree = src("""
            @staticmethod
            def f():
                pass
        """)
        func = tree["body"][0]
        self.assertEqual(func["decorators"][0]["id"], "staticmethod")

    def test_async_function(self):
        tree = src("""
            async def fetch():
                pass
        """)
        func = tree["body"][0]
        self.assertEqual(func["node_type"], "AsyncFunctionDef")
        self.assertTrue(func["is_async"])

    def test_nested_function(self):
        tree = src("""
            def outer():
                def inner():
                    pass
        """)
        outer = tree["body"][0]
        inner = outer["body"][0]
        self.assertEqual(inner["node_type"], "FunctionDef")
        self.assertEqual(inner["name"], "inner")


class TestLoops(unittest.TestCase):
    def test_for_loop(self):
        tree = src("""
            for i in range(10):
                print(i)
        """)
        node = tree["body"][0]
        self.assertEqual(node["node_type"], "For")
        self.assertFalse(node["is_async"])
        self.assertEqual(node["target"]["id"], "i")
        self.assertEqual(node["iter"]["node_type"], "Call")

    def test_for_loop_body(self):
        tree = src("""
            for x in items:
                pass
        """)
        node = tree["body"][0]
        self.assertEqual(node["body"][0]["node_type"], "Pass")

    def test_for_loop_orelse(self):
        tree = src("""
            for x in items:
                pass
            else:
                break
        """)
        node = tree["body"][0]
        self.assertIn("orelse", node)

    def test_for_tuple_unpack(self):
        tree = src("""
            for k, v in d.items():
                pass
        """)
        node = tree["body"][0]
        self.assertEqual(node["target"]["node_type"], "Tuple")

    def test_while_loop(self):
        tree = src("""
            while True:
                break
        """)
        node = tree["body"][0]
        self.assertEqual(node["node_type"], "While")
        self.assertEqual(node["test"]["value"], True)
        self.assertEqual(node["body"][0]["node_type"], "Break")

    def test_while_orelse(self):
        tree = src("""
            while cond:
                pass
            else:
                pass
        """)
        node = tree["body"][0]
        self.assertIn("orelse", node)

    def test_async_for(self):
        tree = src("""
            async def f():
                async for item in gen():
                    pass
        """)
        body = tree["body"][0]["body"]
        node = body[0]
        self.assertEqual(node["node_type"], "AsyncFor")
        self.assertTrue(node["is_async"])

    def test_nested_loops(self):
        tree = src("""
            for i in range(3):
                for j in range(3):
                    pass
        """)
        outer = tree["body"][0]
        inner = outer["body"][0]
        self.assertEqual(inner["node_type"], "For")

    def test_break_continue(self):
        tree = src("""
            for x in items:
                if x:
                    continue
                break
        """)
        body = tree["body"][0]["body"]
        # if-stmt body has continue; then break
        self.assertEqual(body[0]["body"][0]["node_type"], "Continue")
        self.assertEqual(body[1]["node_type"], "Break")


class TestClassDef(unittest.TestCase):
    def test_class(self):
        tree = src("""
            class Foo(Bar):
                pass
        """)
        node = tree["body"][0]
        self.assertEqual(node["node_type"], "ClassDef")
        self.assertEqual(node["name"], "Foo")
        self.assertEqual(node["bases"][0]["id"], "Bar")

    def test_class_method(self):
        tree = src("""
            class Foo:
                def method(self):
                    return self
        """)
        node = tree["body"][0]
        method = node["body"][0]
        self.assertEqual(method["node_type"], "FunctionDef")
        self.assertEqual(method["name"], "method")


class TestMiscNodes(unittest.TestCase):
    def test_assign(self):
        tree = src("x = 10")
        node = tree["body"][0]
        self.assertEqual(node["node_type"], "Assign")
        self.assertEqual(node["targets"][0]["id"], "x")
        self.assertEqual(node["value"]["value"], 10)

    def test_augmented_assign(self):
        tree = src("x += 1")
        node = tree["body"][0]
        self.assertEqual(node["node_type"], "AugAssign")
        self.assertEqual(node["op"], "Add")

    def test_annotated_assign(self):
        tree = src("x: int = 5")
        node = tree["body"][0]
        self.assertEqual(node["node_type"], "AnnAssign")
        self.assertEqual(node["annotation"]["id"], "int")

    def test_if_statement(self):
        tree = src("""
            if x > 0:
                pass
            else:
                pass
        """)
        node = tree["body"][0]
        self.assertEqual(node["node_type"], "If")
        self.assertIn("orelse", node)

    def test_compare(self):
        tree = src("x > 0")
        node = tree["body"][0]["value"]
        self.assertEqual(node["node_type"], "Compare")
        self.assertEqual(node["ops"], ["Gt"])

    def test_bool_op(self):
        tree = src("a and b")
        node = tree["body"][0]["value"]
        self.assertEqual(node["node_type"], "BoolOp")
        self.assertEqual(node["op"], "And")

    def test_list_literal(self):
        tree = src("[1, 2, 3]")
        node = tree["body"][0]["value"]
        self.assertEqual(node["node_type"], "List")
        self.assertEqual(len(node["elts"]), 3)

    def test_dict_literal(self):
        tree = src('{"a": 1}')
        node = tree["body"][0]["value"]
        self.assertEqual(node["node_type"], "Dict")

    def test_lambda(self):
        tree = src("f = lambda x: x + 1")
        lam = tree["body"][0]["value"]
        self.assertEqual(lam["node_type"], "Lambda")

    def test_list_comprehension(self):
        tree = src("[x for x in items]")
        node = tree["body"][0]["value"]
        self.assertEqual(node["node_type"], "ListComp")
        self.assertEqual(len(node["generators"]), 1)

    def test_try_except(self):
        tree = src("""
            try:
                pass
            except ValueError as e:
                pass
        """)
        node = tree["body"][0]
        self.assertEqual(node["node_type"], "Try")
        handler = node["handlers"][0]
        self.assertEqual(handler["node_type"], "ExceptHandler")
        self.assertEqual(handler["exc_type"]["id"], "ValueError")
        self.assertEqual(handler["name"], "e")

    def test_with_statement(self):
        tree = src("""
            with open("f") as fh:
                pass
        """)
        node = tree["body"][0]
        self.assertEqual(node["node_type"], "With")
        self.assertFalse(node["is_async"])
        item = node["items"][0]
        self.assertEqual(item["optional_vars"]["id"], "fh")

    def test_raise(self):
        tree = src("raise ValueError('oops')")
        node = tree["body"][0]
        self.assertEqual(node["node_type"], "Raise")
        self.assertEqual(node["exc"]["node_type"], "Call")

    def test_assert(self):
        tree = src("assert x > 0, 'must be positive'")
        node = tree["body"][0]
        self.assertEqual(node["node_type"], "Assert")
        self.assertIn("msg", node)

    def test_global(self):
        tree = src("""
            def f():
                global x
        """)
        node = tree["body"][0]["body"][0]
        self.assertEqual(node["node_type"], "Global")
        self.assertEqual(node["names"], ["x"])

    def test_delete(self):
        tree = src("del x")
        node = tree["body"][0]
        self.assertEqual(node["node_type"], "Delete")


if __name__ == "__main__":
    unittest.main()
